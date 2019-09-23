#include "Process.h"
#include "KernelSystem.h"
#include "KernelProcess.h"
#include "OMAllocator.h"
#include "DiscAllocator.h"
#include <string.h>
#include "Mutex.h"

std::list<KernelProcess::SharedSegmDesc*> *KernelProcess::shSegmentDescs = new std::list<SharedSegmDesc*>();
KernelProcess* KernelProcess::helperWithCloning = 0;
std::vector<std::list<KernelProcess*>* > KernelProcess::hashForClones(KernelSystem::PROCESS_CREATING_STEP);
std::queue<KernelSystem::TrashingDesc*>* KernelProcess::blockedProc = new std::queue<KernelSystem::TrashingDesc*>();

KernelProcess::KernelProcess(ProcessId pid) {
	this->pid = pid;
	this->parentsPid = -1;
	this->isBlocked = false;
	this->mustDiscardOwnership = false;

	segmentDescs = new std::list<SegmentDesc*>(); 
	KernelSystem::allExistsProc[pid] = this;
	trashingMutex = new std::mutex();
	helperWithCloning = this;
}

KernelProcess::~KernelProcess() {
	
	if (parentsPid != -1) {
		std::list<KernelProcess*> * tempLstPoint = hashForClones[parentsPid];
		tempLstPoint->remove(this);
		if (tempLstPoint->empty()) {
			delete tempLstPoint;
			hashForClones[parentsPid] = 0;
		}
	}

	if (segmentDescs != 0) {
		for (std::list<SegmentDesc*>::const_iterator iterator = segmentDescs->begin(), end = segmentDescs->end(); iterator != end;) {
			SegmentDesc* sgDesc = *iterator;
			deleteSegment(sgDesc->vaddrStart, &iterator);
		}
		delete segmentDescs;
		segmentDescs = 0;
	}

	if (trashingMutex != 0)
		trashingMutex = 0;

	KernelSystem::allExistsProc[pid] = 0;
	KernelSystem::releaseFirstLvlPmt(pid);
}

ProcessId KernelProcess::getProcessId() const {
	return pid;
}

Status KernelProcess::createSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags, bool creatingShared,
	KernelProcess* kp, VirtualAddress vaddr, bool parentalSharing, SharedSegmDesc* shDesc) {
	
	if (!haveEnoughSpace(startAddress >> KernelSystem::offsetW, segmentSize)) // Nema dovoljno prostora za PMT2 nivoa!
		return TRAP;
	
	unsigned long pmt1Num = startAddress >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (startAddress >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);
	unsigned long offset = startAddress & ~(~0UL << KernelSystem::offsetW);
	unsigned long pmt2NumPersist = pmt2Num;

	if (offset != 0)                   // Segment nije poravnat na pocetak stranice.
		return TRAP;

	for (SegmentDesc* sgDesc : *segmentDescs) {
		if (((sgDesc->vaddrStart <= startAddress) && (sgDesc->vaddrStart + ((sgDesc->size - 1) << KernelSystem::offsetW) >= startAddress)) ||
			((sgDesc->vaddrStart > startAddress) &&  (startAddress + ((segmentSize - 1) << KernelSystem::offsetW) >= sgDesc->vaddrStart))) {
			return TRAP;              // Preklapa se sa drugim segmentom.
		}
	}

	segmentDescs->push_back(new SegmentDesc(startAddress, segmentSize, flags, shDesc));

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	unsigned short numOfIter = 0;
	unsigned count = 0;
	bool swapped = false;
	ClusterNo clsNo;
	char refCnt = 0;

	while (true) {
		KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame;
		if (pmt2LvlPoint == 0) 
			pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame = KernelSystem::createSecondLvlPmt();

		KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

		unsigned i = 0;
		for (; i < segmentSize; i++) {
			cur->partOfSegment = 1;
			cur->privilegies = (unsigned char)flags;
			if (creatingShared) {
				if (kp != 0) {
					Cluster* temp = (Cluster*)kp->getPhAddrOrClsNo(vaddr + (count << KernelSystem::offsetW), swapped, clsNo,
						parentalSharing, refCnt);
					count++;
					if (temp != 0) {
						cur->valid = 1;
						cur->block = temp;
						if (parentalSharing) {
							cur->refCounts = refCnt; // Broj referenciranja koji dobija od roditelja.
							cur->cow = 1; // v = 1, cow = 1, swapp = 0
						}
					}
					else {
						if (swapped) {
							swapped = false;
							cur->swaped = 1;
							cur->clsNo = clsNo;
							if (parentalSharing) {
								cur->refCounts = refCnt; // Broj referenciranja koji dobija od roditelja.
								cur->cow = 1; // v = 0, cow = 1, swapp = 1
							}
						}
					}
				}
				if (parentalSharing) {
					// cur->cow = 1; // V, CoW, Swapp = 0, 1, 0 - Nema smisla da cow bude 1, za stranice koji nisu ni u OM ni
					if (shDesc != 0) { // na disku!
						cur->cow = 0; // CoW nema smisla za deljene segmente.
						cur->refCounts = 0; // Ni refCounts nema smisla za deljene segmente.
						cur->partOfSharedSegm = 1;
						cur->shSegmDesc = shDesc;
						cur->vaddrSt = (startVAddr)((pmt1Num << KernelSystem::pg2w) | pmt2NumPersist);
					}
				} 
				else {
					cur->partOfSharedSegm = 1;
					cur->shSegmDesc = shDesc;
					cur->vaddrSt = (startVAddr)((pmt1Num << KernelSystem::pg2w) | pmt2NumPersist);
				}
			}
			if (cur == pmt2LvlPoint + KernelSystem::pmt2size - 1) {
				i++;
				break;
			}
			else
				cur++;
		}
		if (i == segmentSize)
			break;
		else
			segmentSize -= i;
		numOfIter++;
		pmt2Num = 0;
	}

	return OK;
}

Status KernelProcess::loadSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags, void * content) {
	
	bool canFitInOM = true;
	if (!KernelSystem::allocProcSpace->canFit(segmentSize))                   // Nema dovoljno prosora za blokove!
		canFitInOM = false;
	
	if (!haveEnoughSpace(startAddress >> KernelSystem::offsetW, segmentSize)) // Nema dovoljno prostora za PMT2 nivoa!
		return TRAP;

	unsigned long pmt1Num = startAddress >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (startAddress >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);
	unsigned long offset = startAddress & ~(~0UL << KernelSystem::offsetW);

	if (offset != 0)                   // Segment nije poravnat na pocetak stranice.
		return TRAP;
	
	for (SegmentDesc* sgDesc : *segmentDescs) {
		if (((sgDesc->vaddrStart <= startAddress) && (sgDesc->vaddrStart + ((sgDesc->size - 1) << KernelSystem::offsetW) >= startAddress)) ||
			((sgDesc->vaddrStart > startAddress) && (startAddress + ((segmentSize - 1) << KernelSystem::offsetW) >= sgDesc->vaddrStart)))
			return TRAP;              // Preklapa se sa drugim segmentom.
	}

	segmentDescs->push_back(new SegmentDesc(startAddress, segmentSize, flags));

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	unsigned short numOfIter = 0;
	Cluster* contentProxy = (Cluster*)content;

	while (true) {
		KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame;
		if (pmt2LvlPoint == 0)
			pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame = KernelSystem::createSecondLvlPmt();
		KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

		unsigned i = 0;
		for (; i < segmentSize; i++) {
			cur->partOfSegment = 1;
			cur->privilegies = (unsigned char)flags;

			if (canFitInOM) {
				cur->valid = 1;
				cur->block = KernelSystem::allocProcSpace->getFreeCluster();
				memcpy(cur->block, contentProxy, PAGE_SIZE);
			}
			else {
				cur->swaped = 1;
				cur->clsNo = KernelSystem::dscAlloc->getFreeCluster();
				char* buffer = (char*)contentProxy;
				KernelSystem::partition->writeCluster(cur->clsNo, buffer);
			}
			contentProxy++;

			if (cur == pmt2LvlPoint + KernelSystem::pmt2size - 1) {
				i++;
				break;
			}
			else
				cur++;
		}
		if (i == segmentSize)
			break;
		else
			segmentSize -= i;
		numOfIter++;
		pmt2Num = 0;
	}

	return OK;
}

Status KernelProcess::deleteSegment(VirtualAddress startAddress, std::list<SegmentDesc*>::const_iterator* iteratorForSegmDesc, 
	bool deleteKernProc) {
	
	unsigned long pmt1Num = startAddress >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (startAddress >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);
	unsigned long offset = startAddress & ~(~0UL << KernelSystem::offsetW);

	if (offset != 0)                   // Segment nije poravnat na pocetak stranice.
		return TRAP;

	bool found = false;
	SegmentDesc* victim;
	for (SegmentDesc* sgDesc : *segmentDescs) {
		if (sgDesc->vaddrStart == startAddress) {
			found = true;
			victim = sgDesc;
			break;
		}
	}

	if (!found)            // Segment ne postoji!
		return TRAP;

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	unsigned short numOfIter = 0;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame;
	if (pmt2LvlPoint == 0)
		return TRAP;                   // Ne bi smelo da se desi.

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;
	PageNum segmentSize = victim->size;
	VirtualAddress address = startAddress >> KernelSystem::offsetW;

	bool last;
	if (victim->shSegm != 0) // Deo je deljenog segmenta. Uklanja se iz liste deljenih segmenata.
		deleteFromSharedList(this, victim->shSegm, last, deleteKernProc);
	
	if (iteratorForSegmDesc != 0)
		*iteratorForSegmDesc = segmentDescs->erase(*iteratorForSegmDesc); // Za poziv iz deskriptora KernelProcess-a.
	else 
		segmentDescs->remove(victim); // Brisemo ga iz liste deskriptora svih segmenta tog procesa.

	delete victim;
	
	while (true) {

		unsigned i = 0;
		for (; i < segmentSize; i++) {
			if (!cur->cow == 1) { // Klon (ili original) kod kojeg je cow na 1, nema sta da dealocira.
				if (cur->valid == 1) {
					if (cur->partOfSharedSegm == 1 && last)
						KernelSystem::allocProcSpace->releaseCluster(cur->block);
					else
						if (cur->partOfSharedSegm == 0) // U ovaj if ulazimo samo ukoliko je valid == 1, sve ostalo 0.
							KernelSystem::allocProcSpace->releaseCluster(cur->block);
				}
				else {
					if (cur->swaped == 1) {
						if (cur->partOfSharedSegm == 1 && last)
							KernelSystem::dscAlloc->releaseCluster(cur->clsNo);
						else
							if (cur->partOfSharedSegm == 0) // U ovaj if ulazimo samo ukoliko je valid == 1, sve ostalo 0.
								KernelSystem::dscAlloc->releaseCluster(cur->clsNo);
					}
				}
			} // Dekrementiraj svima broj referenci za tu adresu.
			else 
				KernelProcess::updateAllRefCountsForPage(this->parentsPid, address << KernelSystem::offsetW, cur->block, cur->clsNo);
			address += 1;

			KernelSystem::flushDesc(cur);
			if (cur == pmt2LvlPoint + KernelSystem::pmt2size - 1) {
				i++;
				break;
			}
			else
				cur++;
		}
		if (isPmt2Empty(pmt2LvlPoint))
			KernelSystem::releaseSecondLvlPmt(pid, pmt1Num + numOfIter);

		if (i == segmentSize)
			break;
		else
			segmentSize -= i;
		numOfIter++;
		pmt2Num = 0;

		pmt2LvlPoint = (pmt1LvlPoint + pmt1Num + numOfIter)->frame;
		if (pmt2LvlPoint == 0)
			return TRAP;
		cur = pmt2LvlPoint;
	}

	return OK;
}

Status KernelProcess::pageFault(VirtualAddress address) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;
	KernelSystem::SecondLvlPgDesc* curReq = pmt2LvlPoint + pmt2Num;

	bool dividingFromParent = false;
	Cluster* parentsContext;

	if (curReq->valid == 1 && curReq->cow == 1) { // Page fault je bio, jer je pokusao upis u stranicu koju deli jos nekim.
		curReq->cow = 0;
		curReq->refCounts = 0; // Jer ce sada on dobiti za sebe blok. Nece ga deliti ni sa kim.
		parentsContext = curReq->block; // parentsContext pokazuje na sadrzaj koji klon mora da vidi nakon sto se odeli od roditelja.
		dividingFromParent = true;
	}

	Cluster* temp;
	KernelSystem::SecondLvlPgDesc* curVictim = 0;
	ProcessId victimPid;
	PageNum victimPage;
	ClusterNo victimsClsNo = -1;

	if (!KernelSystem::allocProcSpace->haveSpace()) {
		victimPage = this->getVictim(victimPid);

		if (victimPid == this->pid && address == (victimPage << KernelSystem::offsetW)) { // Jedino se moze desiti kada se odeljuje
			ClusterNo clsNo = KernelSystem::dscAlloc->getFreeCluster();                   // od roditelja. Jedino tada je v = 1 i 
			char* buffer = (char*)curReq->block;                                          // i ulazi se u pf.
			KernelSystem::partition->writeCluster(clsNo, buffer);
			updateAllRefCountsForPage(this->parentsPid, address, curReq->block, clsNo, true);
			return OK;
		}

		unsigned long pmt1Num = victimPage >> KernelSystem::pg2w; 
		unsigned long pmt2Num = victimPage & ~(~0UL << KernelSystem::pg2w);
		
		KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[victimPid];
		KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;
		curVictim = pmt2LvlPoint + pmt2Num;

		curVictim->valid = 0;
		curVictim->swaped = 1;
		curVictim->refBits = 0;
		//curVictim->reference = 0;

		temp = curVictim->block; //curReq->block = curVictim->block;

		victimsClsNo = KernelSystem::dscAlloc->getFreeCluster();
		char* buffer = (char*)curVictim->block;
		KernelSystem::partition->writeCluster(victimsClsNo, buffer);
		curVictim->clsNo = victimsClsNo; // curVictim->block = 0;
	}
	else 
		temp = KernelSystem::allocProcSpace->getFreeCluster(); //curReq->block = KernelSystem::allocProcSpace->getFreeCluster();
	
	curReq->valid = 1;
	curReq->refBits = 0x80000000;
	
	if (curReq->swaped == 1) {
		curReq->swaped = 0;
		ClusterNo clsNo = curReq->clsNo;
		char* buffer = (char*)temp; //char* buffer = (char*)curReq->block;
		KernelSystem::partition->readCluster(clsNo, buffer);
		KernelSystem::dscAlloc->releaseCluster(clsNo);
	}

	ClusterNo clsNoReq = curReq->clsNo; // Sluzi samo kao provera kod kloniranja.

	curReq->block = temp;
	if (dividingFromParent) { // Jedini slucaj kada moramo da vrsimo kopiranje vec postojeceg sadrzaja bloka. Jer klon mora videti,
		memcpy(curReq->block, parentsContext, PAGE_SIZE); // isto sto i roditelj.
		updateAllRefCountsForPage(this->parentsPid, address, parentsContext, victimsClsNo); // Dekrementira broj refCounts na tu stranicu svim drugim klonovima.
	}
	/*Potrebno za slucaj da je zrtva ujedno deo stabla kloniranja procesa koji se odeljuje. Zrtvin refCountrs mora da se
	azuirara na osnovu jednakosti cur->swapped == 1 && cur->clsNo == clsNo. ClsNo ce u ovom slucaju biti victimsClsNo a ne -1 
	kao ranije sto si radio. Zato ce biti azuiranja.*/
		
	if (curReq->partOfSharedSegm == 1) {
		PageNum differ = (address >> KernelSystem::offsetW) - curReq->vaddrSt;
		updateAllBlocksOfSharedSegm((SharedSegmDesc*)curReq->shSegmDesc, differ, curReq->block, pid);
	}
	else {
		if (curReq->cow == 1) {
			updateAllBlockOrClsNoForCopies(this->parentsPid, address, curReq->block, clsNoReq, true, this->pid);
		}
	}

	if (curVictim != 0 && curVictim->partOfSharedSegm == 1) {
		PageNum differ = victimPage - curVictim->vaddrSt;
		updateAllBlocksOfSharedSegm((SharedSegmDesc*)curVictim->shSegmDesc, differ, 0, victimPid, curVictim->clsNo);
	}
	else {
		if (curVictim != 0 && curVictim->cow == 1) {
			//cout << "Usao u cetvrti if!" << endl;
			/*Preko victimPida zelimo da dobijemo koren (original) da bi smo usli validno u hes i validno azurirali clsNo.*/
			KernelProcess* kp = KernelSystem::allExistsProc[victimPid]; // prvobitno slata 0 u ovoj metodi dole.
			updateAllBlockOrClsNoForCopies(kp->parentsPid, victimPage << KernelSystem::offsetW, temp, curVictim->clsNo, false, kp->pid);
		}
	}
  
	return OK;
}

PhysicalAddress KernelProcess::getPhysicalAddress(VirtualAddress address) {
	
	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);
	unsigned long offset = address & ~(~0UL << KernelSystem::offsetW);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];
	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) // Blok nije ucitana.
		return 0;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	if (cur->valid == 0) // Blok nije ucitana.
		return 0;

	PhysicalAddress paddr = (char*)cur->block + offset;
	return paddr;
}

void KernelProcess::clone(KernelProcess* kp) {

	ProcessId procId = KernelSystem::IdGen - 1;
	KernelSystem::FirstLvlPgDesc* firstLvlPgPoint = KernelSystem::createFirstLvlPmt();
	KernelSystem::pmtFirstLvl[procId] = firstLvlPgPoint;
	ProcessId pidOfOrgProc = kp->pid;
	ProcessId rootPid = -1;

	if (kp->parentsPid == -1)
		kp->parentsPid = pidOfOrgProc; // Kontraintuitivno, ali potrebno. Posto se uklanja podela na kopije i original. Original je otac samom sebi. :)
	else 
		rootPid = kp->parentsPid;

	if (rootPid != -1) 
		KernelProcess::incrementAllRefCounts(rootPid, pidOfOrgProc); // Ide pre nego sto se klon doda u listu.
	
	std::list<KernelProcess*> * tempLstPoint;
	
	if(rootPid != -1)
	    tempLstPoint = hashForClones[rootPid];
	else
		tempLstPoint = hashForClones[pidOfOrgProc];
	
	tempLstPoint->push_back(KernelProcess::helperWithCloning); // Nema potrebe za ponovnim assignovanjem u hes, jer iz hesa se vraca pokazivac
															   // tako da mogu da odmah dodam u lisu.
	if (rootPid != -1)
		helperWithCloning->parentsPid = rootPid;
	else
		helperWithCloning->parentsPid = kp->parentsPid;

	fillClonedProcess(kp);
}

Status KernelProcess::createSharedSegment(VirtualAddress startAddress, PageNum segmentSize, const char* name, AccessType flags) {

	bool first = true;
	SharedSegmDesc* sharedSeg;

	for (SharedSegmDesc* shdsc : *shSegmentDescs) {
		if (!strcmp(shdsc->shSegmName, name)) {
			sharedSeg = shdsc;
			first = false;
			break;
		}
	}

	Status ret;
	if (first) {
		sharedSeg = new SharedSegmDesc(new std::list<KernelProcess*>, new std::list<VirtualAddress>,
			new std::list<PageNum>, (char*)name, flags);
		ret = createSegment(startAddress, segmentSize, flags, true, 0, 0, false, sharedSeg);
		if (ret != OK)
			return ret;

		shSegmentDescs->push_back(sharedSeg);
	}
	else {
		KernelProcess* kp = sharedSeg->kernProcLst->front();
		VirtualAddress vaddr = sharedSeg->vaddLst->front();
		PageNum segmSz = sharedSeg->sgmSz->front();
		
		if (segmSz < segmentSize)  // Mozda bi moglo i da ide samo sa segmentSize = segmSize
			return TRAP; // Segment je veci od onog prvobitno deklarisanog.

	    AccessType accT = sharedSeg->accType;
		if (!validAccessTypes(flags, accT))
			return TRAP;

		ret = createSegment(startAddress, segmentSize, flags, true, kp, vaddr, false, sharedSeg);
		if (ret != OK)
			return ret;
	}

	sharedSeg->kernProcLst->push_back(this);
	sharedSeg->vaddLst->push_back(startAddress);
	sharedSeg->sgmSz->push_back(segmentSize);
	return ret;
}

Status KernelProcess::disconnectSharedSegment(const char* name) {
	
	bool found = false;
	SharedSegmDesc* sharedSeg;

	for (SharedSegmDesc* shdsc : *shSegmentDescs) {
		if (!strcmp(shdsc->shSegmName, name)) {
			sharedSeg = shdsc;
			found = true;
			break;
		}
	}

	if (!found)     // Ne postoji segment sa datim nazivom!
		return TRAP;

	found = false;
	int i = 0;
	KernelProcess* kernProc;
	for (KernelProcess* kp : *sharedSeg->kernProcLst) {
		if (kp->getProcessId() != pid) {
			i++; continue;
		}
		else {
			found = true;
			kernProc = kp;
			break;
		}
	}

	if (!found)     // Nijedan njegov segment nije deo deljenog segmenta sa tim imenom!
		return TRAP;

	VirtualAddress vaddr;
	int j = 0;
	for (VirtualAddress va : *sharedSeg->vaddLst) {
		if (j == i) {
			vaddr = va;
			break;
		}
		else
			j++;
	}

	j = 0;
	PageNum segmentSize;
	for (PageNum ss : *sharedSeg->sgmSz) {
		if (j == i) {
			segmentSize = ss;
			break;
		}
		else
			j++;
	}
	
	bool last;
	deleteFromSharedList(kernProc, sharedSeg, last, true); // Izbacuje i postavlja last na true ili false.

	/*Potrebno je da idemo do tacne duzine segmenta, jer nikako drugacije ne bismo mogli da znamo da smo stigli do kraja
	segmenta. Mozda bi moglo proverom partOfSharedSegmet || partofSegment ali sta raditi onda u slucaju da su svi segmenti
	jedan do drugog. Kako znati koji je koji.*/
	for (PageNum pn = 0; pn < segmentSize; pn++) 
		kernProc->disconnPhysicalAddress(vaddr + (pn << KernelSystem::offsetW), last);
		
	for (SegmentDesc* sgdsc : *this->segmentDescs) { // Ponisti podatak (ime) u deskriptoru segmenta o deljenosti tog segmenta.
		if (sgdsc->vaddrStart == vaddr)
			sgdsc->shSegm = 0;
	}

	return OK;
}

Status KernelProcess::deleteSharedSegment(const char * name) {
	
	bool found = false;
	SharedSegmDesc* sharedSeg;

	for (SharedSegmDesc* shdsc : *shSegmentDescs) {
		if (!strcmp(shdsc->shSegmName, name)) {
			sharedSeg = shdsc;
			found = true;
			break;
		}
	}

	if (!found)  // Ne postoji deljeni segment sa tim nazivom!
		return TRAP;

	for (std::list<KernelProcess*>::const_iterator iteratorKP = sharedSeg->kernProcLst->begin(), end = sharedSeg->kernProcLst->end(); iteratorKP != end;) {
		KernelProcess* kp = *iteratorKP;
		VirtualAddress vaddr = sharedSeg->vaddLst->front();

		kp->deleteSegment(vaddr, 0, false);
		iteratorKP = sharedSeg->kernProcLst->erase(iteratorKP);
	}

	// Nema potrebe za ovi jer ce to biti uradjeno u poslednjem segmentu kojim bude bila pozvana metoda deleteSegment.
	// Nece biti uradjeno, jer tamo ne brises kernProc za deleteKernProc == false, zato nikad nece pasti na ispod 1.
	shSegmentDescs->remove(sharedSeg); // U delete segmentu ce se brisati taj segment iz liste svih segmenata, kao i iz liste
	delete sharedSeg;                  // deljenih segmenata. Tako da ce ovde sharedSeg biti "prazan".

	return OK;
}

void KernelProcess::blockIfThrashing() {
	if (this->mustDiscardOwnership) {
		this->mustDiscardOwnership = false;
		this->trashingMutex->unlock();
	}

	if (this->isBlocked) {
		preventThrashing(this->pid);
		Mutex::sem.unlock();
		this->trashingMutex->lock();
		return;
	}
	Mutex::sem.unlock();
}

bool KernelProcess::isPmt2Empty(KernelSystem::SecondLvlPgDesc* checking) {
	for (unsigned i = 0; i < KernelSystem::pmt2size; i++)
		if ((checking + i)->partOfSegment == 1)
			return false;
	return true;
}

bool KernelProcess::haveEnoughSpace(VirtualAddress vaddrStart, PageNum sgmSz) {
	if (sgmSz == 0)
		return false;
	else
		sgmSz -= 1;

	if (vaddrStart + sgmSz > KernelSystem::MAX_VIRTUAL_ADDRESS)
		return false;

	unsigned long pmt1NumStart = vaddrStart >> KernelSystem::pg2w;
	VirtualAddress vaddrEnd = vaddrStart + sgmSz;
	unsigned long pmt1NumEnd = vaddrEnd >> KernelSystem::pg2w;

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	unsigned long needAllocation = 0;
	unsigned long differ = pmt1NumEnd - pmt1NumStart + 1;
	for (unsigned long i = 0; i < differ; i++) {
		KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1NumStart + i)->frame;
		if (pmt2LvlPoint == 0)
			needAllocation++;
	}

	bool res = KernelSystem::allocPMTSpace->canFit(needAllocation);
	return res;
}

PageNum KernelProcess::getVictim(ProcessId& proccesVictim) {
	
	PageNum minPage = 0;
	unsigned long minRef = 0;
	bool first = true;
	ProcessId pidCount = 0;
	KernelSystem::FirstLvlPgDesc* pmt1Lvl = 0;
	unsigned long size = KernelSystem::pmtFirstLvl.size();

	for (unsigned long i = 0; i < size; i++) {
		pmt1Lvl = KernelSystem::pmtFirstLvl[i];
		if (pmt1Lvl == 0) {
			pidCount++;
			continue;
		}

		for (unsigned pgn1 = 0; pgn1 < KernelSystem::pmt1size; pgn1++) {
			KernelSystem::SecondLvlPgDesc* pmt2Lvl = (pmt1Lvl + pgn1)->frame;

			if (pmt2Lvl == 0)
				continue;

			KernelSystem::SecondLvlPgDesc* cur;
			for (unsigned pgn2 = 0; pgn2 < KernelSystem::pmt2size; pgn2++) {
				cur = pmt2Lvl + pgn2;
				if (cur->valid == 0)
					continue;
				if (first || cur->refBits <= minRef) {
					first = false;
					minRef = cur->refBits;
					minPage = (pgn1 << KernelSystem::pg2w) | pgn2;
					proccesVictim = pidCount;
					if (minRef == 0)
						return minPage;
				}
			}
		}
		pidCount++;
	}

	return minPage;
}

void KernelProcess::preventThrashing(ProcessId pid) {

	KernelSystem::FirstLvlPgDesc* pmt1Lvl = KernelSystem::pmtFirstLvl[pid];

	for (unsigned pgn1 = 0; pgn1 < KernelSystem::pmt1size; pgn1++) {
		KernelSystem::SecondLvlPgDesc* pmt2Lvl = (pmt1Lvl + pgn1)->frame;

		if (pmt2Lvl == 0)
			continue;

		KernelSystem::SecondLvlPgDesc* cur;
		for (unsigned pgn2 = 0; pgn2 < KernelSystem::pmt2size; pgn2++) {
			cur = pmt2Lvl + pgn2;
			if (cur->valid == 1) {
				cur->valid = 0;
				cur->swaped = 1;
				cur->refBits = 0;

				ClusterNo clsNo = KernelSystem::dscAlloc->getFreeCluster();
				char* buffer = (char*)cur->block;
				KernelSystem::partition->writeCluster(clsNo, buffer);
				KernelSystem::allocProcSpace->releaseCluster(cur->block);
				Cluster* temp = cur->block;
				cur->clsNo = clsNo;

				PageNum pagePartOfAddress = pgn1 << KernelSystem::pg2w | pgn2;
				if (cur->partOfSharedSegm == 1) {
					PageNum differ = pagePartOfAddress - cur->vaddrSt;
					updateAllBlocksOfSharedSegm((SharedSegmDesc*)cur->shSegmDesc, differ, 0, pid, cur->clsNo);
				}
				else {
					if (cur->cow == 1) {
						/*Preko victimPida zelimo da dobijemo koren (original) da bismo usli validno u hes i validno azurirali clsNo.*/
						KernelProcess* kp = KernelSystem::allExistsProc[pid];
						updateAllBlockOrClsNoForCopies(kp->parentsPid, pagePartOfAddress << KernelSystem::offsetW, temp, cur->clsNo, false, kp->pid); 
					} 
				}
			}
			//cur->reference = 0;
		}
	}
}

bool KernelProcess::validAccessTypes(AccessType accReq, AccessType accExs) {

	switch (accReq) {
	case READ:
		if (accExs == READ || accExs == READ_WRITE)
			return true;
		else
			return false;
		break;
	case WRITE:
		if (accExs == WRITE || accExs == READ_WRITE)
			return true;
		else
			return false;
		break;
	case READ_WRITE:
		if (accExs == READ_WRITE)
			return true;
		else
			return false;
		break;
	case EXECUTE:
		if (accExs == EXECUTE)
			return true;
		else
			return false;
		break;
	default:
		break;
	}
	return false;
}

void KernelProcess::fillClonedProcess(KernelProcess* kp) {

	for (SegmentDesc* sgdsc : *kp->segmentDescs) { // helperWithCloning == klon koji trenutno kreiramo!
		helperWithCloning->createSegment(sgdsc->vaddrStart, sgdsc->size, sgdsc->accR, true, kp,
			sgdsc->vaddrStart, true, sgdsc->shSegm);
		if (sgdsc->shSegm != 0)
			addInListOfSharedSegm(helperWithCloning, sgdsc->vaddrStart, sgdsc->size, sgdsc->shSegm);
	}
	helperWithCloning = 0;
}

void KernelProcess::updateAllBlocksOfSharedSegm(SharedSegmDesc* sharedSeg, PageNum changedPagePosition,
	Cluster* newCluster, ProcessId pid, ClusterNo clsNo) {

	std::list<VirtualAddress>::const_iterator iteratorVA = sharedSeg->vaddLst->begin();
	for (std::list<KernelProcess*>::const_iterator iteratorKP = sharedSeg->kernProcLst->begin(), 
		end = sharedSeg->kernProcLst->end(); iteratorKP != end; iteratorKP++, iteratorVA++) {
		
		KernelProcess* kp = *iteratorKP;
		if (kp->getProcessId() == pid) // Nema potrebe da onaj koji je inicirao osvezavanje, samom sebi promeni polje blok ili clsNo.
			continue;
		VirtualAddress vaddr = *iteratorVA;

		vaddr >>= KernelSystem::offsetW;
		vaddr += changedPagePosition;
		vaddr <<= KernelSystem::offsetW;

		if (newCluster != 0)
			kp->updateBlockPointer(vaddr, newCluster);
		else
			kp->updateClsBlockNum(vaddr, clsNo);
	}
}

void KernelProcess::addInListOfSharedSegm(KernelProcess* clone, VirtualAddress vaddr, PageNum sgmSize, 
	SharedSegmDesc* sharedSeg) {

	sharedSeg->kernProcLst->push_back(clone);
	sharedSeg->vaddLst->push_back(vaddr);
	sharedSeg->sgmSz->push_back(sgmSize);
	
}

void KernelProcess::deleteFromSharedList(KernelProcess* kernProc, SharedSegmDesc* sharedSeg, bool& last, bool deleteKernProc) {

	std::list<VirtualAddress>::const_iterator iteratorVA = sharedSeg->vaddLst->begin();
	std::list<PageNum>::const_iterator iteratorSN = sharedSeg->sgmSz->begin();
	for (std::list<KernelProcess*>::const_iterator iteratorKP = sharedSeg->kernProcLst->begin(), end = sharedSeg->kernProcLst->end(); iteratorKP != end;) {
		KernelProcess* kp = *iteratorKP;
		if (kp == kernProc) {
			if (deleteKernProc) 
				sharedSeg->kernProcLst->erase(iteratorKP);
			sharedSeg->vaddLst->erase(iteratorVA);
			sharedSeg->sgmSz->erase(iteratorSN);
			break;
		}
		else {
			iteratorKP++; iteratorVA++; iteratorSN++;
		}
	}

	last = false;

	if (!deleteKernProc && sharedSeg->kernProcLst->size() == 1) { // Da je obrisan kernProc, palo bi na 0, ali ne smemo da brisemo,
		last = true;                                              // jer se ovo poziva i za deleteShSegment, a iterator moramo napraviti da bude robustan.
		return;
	}
		
	if (sharedSeg->kernProcLst->size() == 0) {
		last = true;
		shSegmentDescs->remove(sharedSeg);
		delete sharedSeg;
	}
}

void KernelProcess::disconnPhysicalAddress(VirtualAddress address, bool last) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) // Ne bi smelo da se desi.
		return;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;
	
	if (last && cur->swaped == 1)
		KernelSystem::dscAlloc->releaseCluster(cur->clsNo);
	else
		if (last && cur->valid == 1)
			KernelSystem::allocProcSpace->releaseCluster(cur->block);
	unsigned char privilegies = cur->privilegies;
	KernelSystem::flushDesc(cur);
	cur->partOfSegment = 1;
	cur->privilegies = privilegies;

}

void KernelProcess::updateBlockPointer(VirtualAddress address, Cluster * newCluster) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) // Ne bi smelo da se desi.
		return;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	 // Osvezavanje ide pre ostalih provera. Obavezno pre poslednjeg if-a. Moze se permutovati sa gornjim.
	if (cur->partOfSharedSegm == 1) { // Ovde se ulazi nakon sto je za jednu deljenu stranicu obradjen page fault.
		cur->block = newCluster;      // Pozvao smo metodu za neku stranicu koja je deklarisala manji deo od pocetnog       
		cur->valid = 1;               // deljenog segmenta.
		cur->swaped = 0;              // Mozda je newCluster u stvari blok u koji su dovuceni podaci sa disk klastera.
		cur->refBits = 0x80000000;
	}

}

void KernelProcess::updateClsBlockNum(VirtualAddress address, ClusterNo clsNo) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) //Ne bi smelo da se desi.
		return;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

    // Zrtva izbacivanje je bila deo deljenog segmenta.
	if (cur->partOfSharedSegm == 1) { // Ovde se ulazi nakon sto je jedna deljena stranica bila izbacena kao zrtva.
		cur->clsNo = clsNo;    // Pozvao smo metodu za neku stranicu koja je deklarisala manji deo od pocetnog       
		cur->valid = 0;        // deljenog segmenta.
		cur->swaped = 1;
		cur->refBits = 0;
		//cur->reference = 0;
	}

}

PhysicalAddress KernelProcess::getPhAddrOrClsNo(VirtualAddress address, bool & swapped, ClusterNo & clsNo, bool creatingShared,
	char & refCnt) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);
	unsigned long offset = address & ~(~0UL << KernelSystem::offsetW);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return 0;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) // Blok nije ucitana.
		return 0;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	if (cur->swaped == 1) {
		swapped = true;
		clsNo = cur->clsNo;
		if (creatingShared && cur->partOfSharedSegm == 0) {
			cur->cow = 1; // Original deli tu stranicu (koja je u ovom slucaju na disku) sa klonom.
			cur->refCounts++; // Originalu se povecava broj referenciranja.
			refCnt = cur->refCounts;
		}
		return 0;
	}

	if (cur->valid == 0) // Blok nije ucitana.
		return 0;

	if (creatingShared && cur->partOfSharedSegm == 0) { // Swapped == 0 && Valid == 1
		cur->cow = 1; // Original deli tu stranicu (koja je u ovom slucaju u OM) sa klonom.
		cur->refCounts++; // Originalu se povecava broj referenciranja.
		refCnt = cur->refCounts;
	}

	PhysicalAddress paddr = (char*)cur->block + offset;
	return paddr;
}

void KernelProcess::updateAllRefCountsForPage(ProcessId rootPid, VirtualAddress address, Cluster* blockForCmp, ClusterNo clsNo, 
	bool specialCaseOfDecrementation) {

	std::list<KernelProcess*> * tempLstPoint = hashForClones[rootPid];
	if (tempLstPoint == 0)
		return;

	for (KernelProcess* kp : *tempLstPoint) 
		kp->decrementRefCount(address, blockForCmp, clsNo, specialCaseOfDecrementation);	
}

void KernelProcess::decrementRefCount(VirtualAddress address, Cluster* blockForCmp, ClusterNo clsNo, bool specialCaseOfDescrementation) {
	
	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return;

	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) // Ne bi smelo da se desi.
		return;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	if (cur->cow == 1 && cur->refCounts > 0 && ((cur->valid == 1 && cur->block == blockForCmp) 
		|| (cur->swaped == 1 && cur->clsNo == clsNo))) { // Necu uci u ovaj if za onog ko je pokrenuo osvezavanje. Kao i za one stranice koje su se vec odvojile.
		cur->refCounts--;
		
		if (specialCaseOfDescrementation) {
			cur->valid = 0;
			cur->refBits = 0;
			//cur->reference = 0; //Ne stavljam na 0, jer ce mi trebati za working set size.
			cur->swaped = 1;
			cur->clsNo = clsNo;
		}

		if (cur->refCounts == 0)
			cur->cow = 0;
	}
}

void KernelProcess::incrementAllRefCounts(ProcessId rootPid, ProcessId pidOfOrgProc) {

	std::list<KernelProcess*> * tempLstPoint = hashForClones[rootPid];
	KernelSystem::FirstLvlPgDesc* pmt1LvlOrg = KernelSystem::pmtFirstLvl[pidOfOrgProc];

	for (KernelProcess* kp : *tempLstPoint) {
		if (kp->pid == pidOfOrgProc)
			continue; // Originalu ce biti azuiran refCounts kada bude pravio klona u metodi createSegment().

		KernelSystem::FirstLvlPgDesc* pmt1Lvl = KernelSystem::pmtFirstLvl[kp->pid];

		if (pmt1Lvl == 0)
			continue;

		for (unsigned pgn1 = 0; pgn1 < KernelSystem::pmt1size; pgn1++) {
			KernelSystem::SecondLvlPgDesc* pmt2Lvl = (pmt1Lvl + pgn1)->frame;
			KernelSystem::SecondLvlPgDesc* pmt2LvlOrg = (pmt1LvlOrg + pgn1)->frame;

			if (pmt2Lvl == 0 || pmt2LvlOrg == 0)
					continue;

			KernelSystem::SecondLvlPgDesc* cur;
			KernelSystem::SecondLvlPgDesc* curOrg;
			for (unsigned pgn2 = 0; pgn2 < KernelSystem::pmt2size; pgn2++) {
				cur = pmt2Lvl + pgn2;
				curOrg = pmt2LvlOrg + pgn2;
				if (cur->cow == 1 && ((cur->valid == 1 && cur->block == curOrg->block)
					|| cur->swaped == 1 && cur->clsNo == curOrg->clsNo)) {
					cur->refCounts++;
				}
			}
	     }
	}
}	

void KernelProcess::updateAllBlockOrClsNoForCopies(ProcessId pidOfOrgProc, VirtualAddress address,  Cluster* newBlock, 
	ClusterNo newClsNo, bool blockUpdating, ProcessId pidToBeSkipped) {

	std::list<KernelProcess*> * tempLstPoint = hashForClones[pidOfOrgProc];

	for (KernelProcess* kp : *tempLstPoint) {
		if (kp->pid == pidToBeSkipped) continue;
		kp->assignNewValueForBlockOrCls(address, newBlock, newClsNo, blockUpdating);
	}
}

void KernelProcess::assignNewValueForBlockOrCls(VirtualAddress address, Cluster * block, ClusterNo clsNo, bool blockUpdating) {

	unsigned long pmt1Num = address >> (KernelSystem::pg2w + KernelSystem::offsetW);
	unsigned long pmt2Num = (address >> KernelSystem::offsetW) & ~(~0UL << KernelSystem::pg2w);

	KernelSystem::FirstLvlPgDesc* pmt1LvlPoint = KernelSystem::pmtFirstLvl[pid];

	if (pmt1LvlPoint == 0)
		return;
	
	KernelSystem::SecondLvlPgDesc* pmt2LvlPoint = (pmt1LvlPoint + pmt1Num)->frame;

	if (pmt2LvlPoint == 0) //Ne bi smelo da se desi.
		return;

	KernelSystem::SecondLvlPgDesc* cur = pmt2LvlPoint + pmt2Num;

	if (cur->cow == 1) { // Necu uci u ovaj if za onog ko je pokrenuo osvezavanje, kao i za one koji su prestali da dele tu stranicu.
		if (blockUpdating) {
			if (cur->clsNo == clsNo) {
				cur->valid = 1;
				cur->block = block;
				cur->swaped = 0;
				cur->refBits = 0x80000000;
			}
		}
		else {
			if (cur->block == block) {
				cur->valid = 0;
				cur->refBits = 0;
				//cur->reference = 0; //Ne stavljam na 0, jer ce mi trebati za working set size.
				cur->swaped = 1;
				cur->clsNo = clsNo;
			}
		}
	}
}

KernelProcess::SharedSegmDesc::~SharedSegmDesc() {
	if (this->kernProcLst != 0) {
		delete kernProcLst;
		kernProcLst = 0;
	}
	if (this->sgmSz != 0) {
		delete sgmSz;
		sgmSz = 0;
	}
	if (this->vaddLst != 0) {
		delete vaddLst;
		vaddLst = 0;
	}
}

KernelProcess::SharedSegmDesc::SharedSegmDesc(std::list<KernelProcess*>* procIdList, std::list<VirtualAddress>* vaddLst, 
	std::list<PageNum>* sgmSz, char* shSegmName, AccessType accType) {

	this->kernProcLst = procIdList;
	this->vaddLst = vaddLst;
	this->sgmSz = sgmSz;
	this->shSegmName = shSegmName;
	this->accType = accType;
}

KernelProcess::SegmentDesc::SegmentDesc(VirtualAddress vaddrStart, SegmentSize size, AccessType accR, SharedSegmDesc* shSegm) {
	this->vaddrStart = vaddrStart;
	this->size = size;
	this->accR = accR;
	this->shSegm = shSegm;
}
