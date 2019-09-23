#include "DiscAllocator.h"

DiscAllocator::DiscAllocator(Partition* par) {
	formatFreeSpace(par);
}

void DiscAllocator::formatFreeSpace(Partition* par) {
	allocated = new ClusterNo[length = par->getNumOfClusters()];
	head = 0;
	tail = length - 1;

	for (unsigned int i = 1; i < length; i++)
		allocated[i - 1] = i;

	allocated[tail] = -1;
}

ClusterNo DiscAllocator::getFreeCluster() {
	if (length == 0) return -1;  // Greska! Ne bi trebalo nikada da se desi.

	ClusterNo ret = head;
	head = allocated[head];
	allocated[ret] = 0;
	length--;
	return ret;
}

void DiscAllocator::releaseCluster(ClusterNo clsNo) {
	if (allocated[clsNo] != 0) return;

	allocated[tail] = clsNo;
	tail = allocated[tail];
	allocated[tail] = -1;
	if (length == 0)
		head = tail;
	length++;
}

bool DiscAllocator::haveSpace() const {
	return length > 0;
}

DiscAllocator::~DiscAllocator() {
	if (allocated != 0)
		delete[] allocated;
}