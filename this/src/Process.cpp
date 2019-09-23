#include "Process.h"
#include "KernelProcess.h"
#include "Mutex.h"
#include "KernelSystem.h"
#include "KernelProcess.h"
#include "OMAllocator.h"

Process::Process(ProcessId pid) {                      // Poziva se iz klase System, koja ce obezbediti atomicnost.
	pProcess = new KernelProcess(pid);
}

Process::~Process() {
	Mutex mtx(&Mutex::sem);
	if (pProcess != 0) {
		delete pProcess;
		pProcess = 0;
	}
}

ProcessId Process::getProcessId() const {             // Poziva korisnik. Nema pristupa deljenim resursima,
	ProcessId pid = pProcess->getProcessId();         // pa nema ni medjusobnog iskljucivanja.
	return pid;
}

Status Process::createSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->createSegment(startAddress, segmentSize, flags);
	return status;
}

Status Process::loadSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags, void * content) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->loadSegment(startAddress, segmentSize, flags, content);
	return status;
}

Status Process::deleteSegment(VirtualAddress startAddress) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->deleteSegment(startAddress);
	return status;
}

Status Process::pageFault(VirtualAddress address) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->pageFault(address);
	return status;
}

PhysicalAddress Process::getPhysicalAddress(VirtualAddress address) {
	Mutex mtx(&Mutex::sem);
	PhysicalAddress paddr = pProcess->getPhysicalAddress(address);
	return paddr;
}

void Process::blockIfThrashing() {
	Mutex::sem.lock();   // Mutex mtx(&Mutex::sem);
	pProcess->blockIfThrashing();
}

Process* Process::clone(ProcessId pid) {
	Mutex mtx(&Mutex::sem);

	if (!KernelSystem::allocPMTSpace->haveSpace()) // Nema mesta za PMT 1 nivoa!
		return 0;

	KernelProcess* kp = KernelSystem::allExistsProc[pid];
	if (kp == 0)  // Ne bi smelo da se desava!
		return 0;

	std::list<KernelProcess*> *checkInHashForClones;
	if(kp->parentsPid == -1)
	    checkInHashForClones = KernelProcess::hashForClones[kp->pid];
	else
		checkInHashForClones = KernelProcess::hashForClones[kp->parentsPid];

	if (checkInHashForClones == 0) { // Prvi put se klonira!
		std::list<KernelProcess*>* tempListPoint = new std::list<KernelProcess*>();
		tempListPoint->push_back(kp); // Original dodajemo u listu na pocetak!
		KernelProcess::hashForClones[kp->pid] =  tempListPoint;	
	}

	Process* proc = new Process(KernelSystem::IdGen++);
	pProcess->clone(kp);
	return proc;
}

Status Process::createSharedSegment(VirtualAddress startAddress, PageNum segmentSize, const char * name,  AccessType flags) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->createSharedSegment(startAddress, segmentSize, name, flags);
	return status;
}

Status Process::disconnectSharedSegment(const char * name) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->disconnectSharedSegment(name);
	return status;
}

Status Process::deleteSharedSegment(const char * name) {
	Mutex mtx(&Mutex::sem);
	Status status = pProcess->deleteSharedSegment(name);
	return status;
}
