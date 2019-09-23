#include "System.h"
#include "KernelSystem.h"
#include "Mutex.h"

System::System(PhysicalAddress processVMSpace, PageNum processVMSpaceSize, 
	           PhysicalAddress pmtSpace, PageNum pmtSpaceSize, Partition * partition) {
	pSystem = new KernelSystem(processVMSpace, processVMSpaceSize, pmtSpace, pmtSpaceSize, partition);
}

System::~System() {
	Mutex mtx(&Mutex::sem);
	if (pSystem != 0) {
		delete pSystem;
		pSystem = 0;
	}
}

Process* System::createProcess() {
	Mutex mtx(&Mutex::sem);
	Process* proc = pSystem->createProcess();
	return proc;
}

Time System::periodicJob() {
	Mutex mtx(&Mutex::sem);
	Time time = pSystem->periodicJob();
	return time;
}

Status System::access(ProcessId pid, VirtualAddress address, AccessType type) {
	Mutex mtx(&Mutex::sem);
	Status status = pSystem->access(pid, address, type);
	return status;
}

Process* System::cloneProcess(ProcessId pid) {
	Mutex mtx(&Mutex::sem);
	Process* proc = pSystem->cloneProcess(pid);
	return proc;
}
