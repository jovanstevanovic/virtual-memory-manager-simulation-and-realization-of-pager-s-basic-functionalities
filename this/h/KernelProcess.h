// File: KernelProcess.h
#pragma once
#include "KernelSystem.h"
#include "vm_declarations.h"
#include <list>
#include <mutex>
#include <queue>

class Process;
class System;
class KernelSystem;

class KernelProcess {
private:
	KernelProcess(ProcessId pid);
	~KernelProcess();

	ProcessId getProcessId() const;

	Status loadSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags, void* content);
	Status pageFault(VirtualAddress address);
	PhysicalAddress getPhysicalAddress(VirtualAddress address);

	//Second part
	void clone(KernelProcess* kp);
	Status createSharedSegment(VirtualAddress startAddress, PageNum segmentSize, const char* name, AccessType flags);
	Status disconnectSharedSegment(const char* name);
	Status deleteSharedSegment(const char* name);
	void blockIfThrashing();

private:
	friend class System;
	friend class KernelSystem;
	friend class Process;

	struct SharedSegmDesc {
		std::list<KernelProcess*>* kernProcLst;
		std::list<VirtualAddress>* vaddLst;
		std::list<PageNum>* sgmSz;
		char* shSegmName;
		AccessType accType;
		~SharedSegmDesc();
		SharedSegmDesc(std::list<KernelProcess*>* procIdList, std::list<VirtualAddress>* vaddLst,
			std::list<PageNum>* sgmSz, char* shSegmName, AccessType accType);
	};

	struct SegmentDesc {
		VirtualAddress vaddrStart;
		SegmentSize size;
		AccessType accR;
		SharedSegmDesc* shSegm;
		SegmentDesc(VirtualAddress vaddrStart, SegmentSize size, AccessType accR, SharedSegmDesc* shSegm = 0);
	};

	Status createSegment(VirtualAddress startAddress, PageNum segmentSize, AccessType flags, bool creatingShared = false,
		KernelProcess* kp = 0, VirtualAddress vaddr = 0, bool parentalSharing = false, SharedSegmDesc* shDesc = 0);
	Status deleteSegment(VirtualAddress startAddress, std::list<SegmentDesc*>::const_iterator* iteratorForSegmDesc = 0,
		bool deleteKernProc = true);

	static bool isPmt2Empty(KernelSystem::SecondLvlPgDesc* checking);
	       bool haveEnoughSpace(VirtualAddress vaddr, PageNum sgmSz);

	static PageNum getVictim(ProcessId& proccesVictim);
	static void preventThrashing(ProcessId pid);
	static bool validAccessTypes(AccessType accReq, AccessType accExs);
	static void fillClonedProcess(KernelProcess* kp);
	static void updateAllBlocksOfSharedSegm(SharedSegmDesc* sharedSeg, PageNum changedPagePosition, Cluster* newCluster, 
		ProcessId pid, ClusterNo clsNo = -1);
	static void addInListOfSharedSegm(KernelProcess* kp, VirtualAddress vaddr, PageNum sgmSize, SharedSegmDesc* sharedSeg);
	static void deleteFromSharedList(KernelProcess* kernProc, SharedSegmDesc* sharedSeg, bool& last, bool deleteKernProc);

	       void disconnPhysicalAddress(VirtualAddress address, bool last);
		   void updateBlockPointer(VirtualAddress address, Cluster* newCluster);
		   void updateClsBlockNum(VirtualAddress address, ClusterNo clsn);

    PhysicalAddress getPhAddrOrClsNo(VirtualAddress vaddr, bool& swapped, ClusterNo& clsNo, bool creatingShared, char & refCnt);

	static void updateAllRefCountsForPage(ProcessId pidOfOrgProc, VirtualAddress address, Cluster* blockForCmp, 
		ClusterNo clsNo, bool specialCaseOfDecrementation = false);
	       void decrementRefCount(VirtualAddress address, Cluster* blockForCmp, ClusterNo clsNo, bool specialCaseOfDescrementation = false);
    static void incrementAllRefCounts(ProcessId rootPid, ProcessId pidOfOrgProcess);
	static void updateAllBlockOrClsNoForCopies(ProcessId pidOfOrgProc, VirtualAddress address, Cluster* newBlock, 
		ClusterNo newClsNo, bool blockUpdating, ProcessId pidToBeSkipped);
	       void assignNewValueForBlockOrCls(VirtualAddress address, Cluster* block, ClusterNo clsNo, bool blockUpdating);

	static std::list<SharedSegmDesc*>* shSegmentDescs;
	       std::list<SegmentDesc*>* segmentDescs;
    static std::vector<std::list<KernelProcess*>* > hashForClones;
	static KernelProcess* helperWithCloning;

	ProcessId pid;
	ProcessId parentsPid;
	std::mutex* trashingMutex;
	bool isBlocked;
	bool mustDiscardOwnership;
	
	static std::queue<KernelSystem::TrashingDesc*>* blockedProc;
};
