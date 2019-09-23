// File: KernelSystem.h
#pragma once
#include "vm_declarations.h"
#include <unordered_map>
#include "part.h"

class Partition;
class Process;
class KernelProcess;
class System;
class OMAllocator;
class DiscAllocator;
class Cluster;

class KernelSystem {
private:
	KernelSystem(PhysicalAddress processVMSpace, PageNum processVMSpaceSize,
		PhysicalAddress pmtSpace, PageNum pmtSpaceSize, Partition* partition);
	~KernelSystem();

	Process* createProcess();
	Time periodicJob();

	// Hardware job
	Status access(ProcessId pid, VirtualAddress address, AccessType type);

	//Second part
	Process* cloneProcess(ProcessId pid);

private:
	friend class Process;
	friend class KernelProcess;
	friend class System;

	struct SecondLvlPgDesc {
		union {
			Cluster* block;
			ClusterNo clsNo;
		};
		void* shSegmDesc;
		RefBitsHistory refBits;   
		startVAddr vaddrSt;         
		char refCounts;  // Broj referenci na jedan blok u OM.
		unsigned char cow : 1; // Prosirena semantika cow bita. CoW je 1 i kod READ i EXCECUTE	blokova, s tim da predstavlja           
		unsigned char partOfSegment : 1;  // da je blok zajednicki za vise stranica, sve kao posledica clone metode.
		unsigned char swaped : 1;
		unsigned char privilegies : 2;
		unsigned char reference : 1;   
		unsigned char partOfSharedSegm : 1;
		unsigned char valid : 1;
	};

	struct FirstLvlPgDesc {
		SecondLvlPgDesc* frame;
	};

	struct TrashingDesc {
		ProcessId pid;
		unsigned short sizeOfWS;
		TrashingDesc(ProcessId pid, unsigned short sizeOfWS);
	};

	static FirstLvlPgDesc* createFirstLvlPmt();
	static SecondLvlPgDesc* createSecondLvlPmt();
	static void releaseFirstLvlPmt(ProcessId pid);
	static void releaseSecondLvlPmt(ProcessId pid, PageNum pgn);
	static void flushDesc(SecondLvlPgDesc* cur);

	static OMAllocator* allocProcSpace;
	static OMAllocator* allocPMTSpace;
	static DiscAllocator* dscAlloc;
	static Partition* partition;

	static unsigned int IdGen;

	static std::vector<FirstLvlPgDesc*> pmtFirstLvl;
	static std::vector<KernelProcess*> allExistsProc;

	static const unsigned short pg1w, pg2w, offsetW;
	static const unsigned pmt1size, pmt2size;
	static const unsigned long MAX_VIRTUAL_ADDRESS;
	static const unsigned short PROCESS_CREATING_STEP;
};
