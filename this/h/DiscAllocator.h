// File: DiscAllocator.h
#pragma once
#include "vm_declarations.h"
#include "part.h"

class Partition;

class DiscAllocator {
public:
	DiscAllocator(Partition* par);
	~DiscAllocator();

	ClusterNo getFreeCluster();
	void releaseCluster(ClusterNo clsNo);
	bool haveSpace() const;

private:
	void formatFreeSpace(Partition* par);
	ClusterNo* allocated;
	ClusterNo head, tail;
	ClusterNo length;
};

