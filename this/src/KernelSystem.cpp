#include "KernelSystem.h"
#include "OMAllocator.h"
#include "DiscAllocator.h"
#include "Process.h"
#include "KernelProcess.h"

//#define THRASHING_PROTECTION

unsigned int KernelSystem::IdGen = 0;

OMAllocator* KernelSystem::allocPMTSpace = 0;
OMAllocator* KernelSystem::allocProcSpace = 0;
DiscAllocator* KernelSystem::dscAlloc = 0;
Partition* KernelSystem::partition = 0;

std::vector<KernelSystem::FirstLvlPgDesc*> KernelSystem::pmtFirstLvl(KernelSystem::PROCESS_CREATING_STEP);
std::vector<KernelProcess*> KernelSystem::allExistsProc(KernelSystem::PROCESS_CREATING_STEP);

const unsigned short KernelSystem::pg1w = 8, KernelSystem::pg2w = 6, KernelSystem::offsetW = 10;
const unsigned KernelSystem::pmt1size = 1 << KernelSystem::pg1w, KernelSystem::pmt2size = 1 << KernelSystem::pg2w;
const unsigned long KernelSystem::MAX_VIRTUAL_ADDRESS = 0x3FFF; // 0x3FFF je page deo najvece virtualne adrese.
const unsigned short KernelSystem::PROCESS_CREATING_STEP = 10;

KernelSystem::KernelSystem(PhysicalAddress processVMSpace, PageNum processVMSpaceSize, 
	                       PhysicalAddress pmtSpace, PageNum pmtSpaceSize, Partition* partition) {

	KernelSystem::allocProcSpace = new OMAllocator(processVMSpace, processVMSpaceSize);
	KernelSystem::allocPMTSpace = new OMAllocator(pmtSpace, pmtSpaceSize);
	KernelSystem::dscAlloc = new DiscAllocator(partition);
	KernelSystem::partition = partition;
}

KernelSystem::~KernelSystem() {

	unsigned long size = allExistsProc.size();
	for (unsigned long i = 0; i < size; i++) {
		if (allExistsProc[i] != 0) 
		    delete allExistsProc[i];
	}

	if (dscAlloc != 0) {
		delete dscAlloc;
		dscAlloc = 0;
	}

	// Uklanjamo listu deskr. deljenih segm. kada se uklanja i sam sistem. Lista je prazna, jer se je to vec sve uklonjeno
	// kod poziva ~KernelProcess() za sve do tada aktivne procese.
	if (KernelProcess::shSegmentDescs != 0) { 
		delete KernelProcess::shSegmentDescs; 
		KernelProcess::shSegmentDescs = 0;
	}

	// Uklanjamo listu za klonirane proces. Znamo da su sve liste prazne.
	for (unsigned i = 0; i < KernelProcess::hashForClones.size(); i++) {
		if (KernelProcess::hashForClones[i] != 0)
			delete KernelProcess::hashForClones[i];
	}

	if (KernelProcess::blockedProc != 0) {
		delete KernelProcess::blockedProc;
		KernelProcess::blockedProc = 0;
	}
}

Process* KernelSystem::createProcess() {
	if (!allocPMTSpace->haveSpace())
		return 0;

	if (IdGen != 0 && IdGen % PROCESS_CREATING_STEP == 0) { // Trenutna velicina vektora + 10 koji predstavlja korak povecanja vektora.
		pmtFirstLvl.resize(pmtFirstLvl.size() + PROCESS_CREATING_STEP, 0);
		allExistsProc.resize(allExistsProc.size() + PROCESS_CREATING_STEP, 0);
		KernelProcess::hashForClones.resize(KernelProcess::hashForClones.size() + PROCESS_CREATING_STEP, 0);
	}

	ProcessId procId = IdGen++;
	FirstLvlPgDesc* firstLvlPgPoint = createFirstLvlPmt();
	pmtFirstLvl[procId] = firstLvlPgPoint;

	return new Process(procId);
}

Time KernelSystem::periodicJob() {
	
	unsigned maxSize = 0;
	ProcessId procWithHighestWS = -1;
	unsigned long sumOfWS = 0;
	unsigned short curWSSize = 0;
	ProcessId pidCount = 0;
	FirstLvlPgDesc* pmt1Lvl = 0;
	unsigned size = pmtFirstLvl.size();

	for (unsigned i = 0; i < size; i++) {
		FirstLvlPgDesc* pmt1Lvl = pmtFirstLvl[i];
		if (pmt1Lvl == 0) {
			pidCount++;
			continue;
		}

		for (unsigned pgn1 = 0; pgn1 < pmt1size; pgn1++) {
			SecondLvlPgDesc* pmt2Lvl = (pmt1Lvl + pgn1)->frame;

			if (pmt2Lvl == 0)
				continue;

			SecondLvlPgDesc* cur;
			for (unsigned pgn2 = 0; pgn2 < pmt2size; pgn2++) {
				cur = pmt2Lvl + pgn2;
				if (cur->valid == 1) {
					if (cur->reference == 1) 
						curWSSize++;
					cur->refBits >>= 1;
					cur->refBits |= (unsigned long)cur->reference << (sizeof(unsigned long) * 8 - 1);
				}
				cur->reference = 0;
			}
		}
		if (curWSSize >= maxSize) {
			maxSize = curWSSize;
			procWithHighestWS = pidCount;
		}
		sumOfWS += curWSSize;
		curWSSize = 0;
		pidCount++;
	}

#ifdef THRASHING_PROTECTION
	if (procWithHighestWS != -1) {
		if (!allocProcSpace->canFit(sumOfWS)) {
         	KernelProcess* kp = allExistsProc[procWithHighestWS];
			if (!kp->mustDiscardOwnership && !kp->isBlocked) {
				if (kp->trashingMutex->try_lock()) {
					kp->isBlocked = true;
					KernelProcess::blockedProc->push(new TrashingDesc(procWithHighestWS, maxSize));
				}
				else {
					kp->mustDiscardOwnership = true;
					return 2'000;
				}
			}
		}
		else {
			if (!KernelProcess::blockedProc->empty()) {
				TrashingDesc* tdes = 0;
				while (!KernelProcess::blockedProc->empty()) {
					tdes = KernelProcess::blockedProc->front();
					if (!allExistsProc[tdes->pid]) 
						KernelProcess::blockedProc->pop();
					else
						break;
					tdes = 0;
				}
				if (tdes != 0 && allocProcSpace->canFit(tdes->sizeOfWS)) {
					KernelProcess* kp = allExistsProc[tdes->pid];
					kp->isBlocked = false;
					kp->trashingMutex->unlock();
					KernelProcess::blockedProc->pop();
				}
			}
		} 
	}
#endif // !THRASHING_PROTECTION

	return 2'000; // 2 ms
}

Status KernelSystem::access(ProcessId pid, VirtualAddress address, AccessType type) {

	unsigned long pmt1Num = address >> (pg2w + offsetW);
	unsigned long pmt2Num = (address >> offsetW) & ~(~0UL << pg2w);

	FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0)  // Nije deo segmenta!
		return TRAP;
	
	SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	if (cur->partOfSegment == 0) // Nije deo segmenta!
		return TRAP;

	switch (type) { // Smemo ovu proveru ovde da vrsimo, zato sto znamo da cim je deo segmenta, time je i podatak type validan.
	case READ:
		if (cur->privilegies != READ && cur->privilegies != READ_WRITE)
			return TRAP;
		break;
	case WRITE:
		if (cur->privilegies != WRITE && cur->privilegies != READ_WRITE)
			return TRAP;
		break;
	case READ_WRITE: // Ovo ne moze da se nadje kao opcija type pri access-u, jer se ne moze stranici pristupa i za upis i za citanje.
		if (cur->privilegies == EXECUTE) // Stavljeno zbog celovitosti.
			return TRAP;
		break;
	case EXECUTE:
		if (cur->privilegies != EXECUTE)
			return TRAP;
		break;
	default:
		return TRAP; // Nikada ne bi trebalo da dodje ovde.
	}

	if (cur->valid == 0) // Stranica nije ucitana.
		return PAGE_FAULT;

	if (cur->valid == 1 && (cur->cow == 1 && (type == WRITE || type == READ_WRITE))) // Niko ne bi trebalo
		return PAGE_FAULT;                                                           // da pristupa sa pravom READ_WRITE.

	cur->reference = 1;
	return OK;
}

Process* KernelSystem::cloneProcess(ProcessId pid) {
	
	if (!KernelSystem::allocPMTSpace->haveSpace()) // Nema mesta za PMT 1 nivoa!
		return 0;

	KernelProcess* kp = KernelSystem::allExistsProc[pid];
	if (kp == 0) // Nema procesa sa tom vrednoscu identifikatora. Greska!
		return 0;

	std::list<KernelProcess*> * checkInHashForClones;
	if (kp->parentsPid == -1)
		checkInHashForClones = KernelProcess::hashForClones[kp->pid];
	else
		checkInHashForClones = KernelProcess::hashForClones[kp->parentsPid];

	if (checkInHashForClones == 0) { // Prvi put se klonira!
		std::list<KernelProcess*>* tempListPoint = new std::list<KernelProcess*>();
		tempListPoint->push_back(kp); // Original dodajemo u listu na pocetak!
		KernelProcess::hashForClones[kp->pid] =  tempListPoint;
	}

	Process* proc = new Process(IdGen++);
	kp->clone(kp);
	return proc;
}

KernelSystem::FirstLvlPgDesc* KernelSystem::createFirstLvlPmt() {
	FirstLvlPgDesc *pmtFirstLvl = (FirstLvlPgDesc*)allocPMTSpace->getFreeCluster();
	FirstLvlPgDesc *cur = pmtFirstLvl;

	for (unsigned i = 0; i < pmt1size; i++) {
		cur->frame = 0;
		cur++;
	}

	return pmtFirstLvl;
}

KernelSystem::SecondLvlPgDesc* KernelSystem::createSecondLvlPmt() {
	SecondLvlPgDesc* pmtScndLvl = (SecondLvlPgDesc*)allocPMTSpace->getFreeCluster();
	SecondLvlPgDesc* cur = pmtScndLvl;

	for (unsigned i = 0; i < pmt2size; i++) {
		flushDesc(cur);
		cur++;
	}
	return pmtScndLvl;
}

void KernelSystem::releaseFirstLvlPmt(ProcessId pid) {
	FirstLvlPgDesc* pmt1Lvl = KernelSystem::pmtFirstLvl[pid];
	Cluster* cls = (Cluster*)pmt1Lvl;

	allocPMTSpace->releaseCluster(cls);
	KernelSystem::pmtFirstLvl[pid] = 0;
}

void KernelSystem::releaseSecondLvlPmt(ProcessId pid, PageNum pgn) {
	FirstLvlPgDesc* pmt1Lvl = KernelSystem::pmtFirstLvl[pid];
	Cluster* cls = (Cluster*)((pmt1Lvl + pgn)->frame);

	if (cls == 0)
		return;

	allocPMTSpace->releaseCluster(cls);
	(pmt1Lvl + pgn)->frame = 0;
}

void KernelSystem::flushDesc(SecondLvlPgDesc *cur) {
	cur->valid = cur->partOfSharedSegm = cur->reference = cur->privilegies = cur->swaped = cur->partOfSegment = cur->cow = 0;
	cur->refBits = 0;
	cur->shSegmDesc = 0;
	cur->refCounts = 0;
	cur->vaddrSt = -1;
	cur->clsNo = -1; //cur->block = -1; - Isti deo memorije.
}

KernelSystem::TrashingDesc::TrashingDesc(ProcessId pid, unsigned short sizeOfWS) {
	this->pid = pid;
	this->sizeOfWS = sizeOfWS;
}
