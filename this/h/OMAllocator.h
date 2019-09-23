// File: OMAllocator.h
#pragma once
#include "vm_declarations.h"

class Cluster { // Pomocna klasa OMAllocatora.
private:
	char dummyArr[PAGE_SIZE];
};

class OMAllocator {
public:
	OMAllocator(PhysicalAddress pa, PageNum pn);

	Cluster* getFreeCluster();
	void releaseCluster(Cluster* cluster);
	bool haveSpace() const;
	bool canFit(PageNum pgn) const;
	unsigned long getNumOfFreeBlocks() const;

private:
	void formatFreeSpace(PhysicalAddress pa, PageNum pn);

	struct FreeCluster {
		FreeCluster* next;
		FreeCluster(FreeCluster* fc) {
			next = fc;
		}
	};

	FreeCluster* head, *tail;
	unsigned long length;
};

