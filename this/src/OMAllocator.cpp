#include "OMAllocator.h"

OMAllocator::OMAllocator(PhysicalAddress pa, PageNum pn) {
	formatFreeSpace(pa, pn);
}

void OMAllocator::formatFreeSpace(PhysicalAddress pa, PageNum pn) {
	Cluster* cluster = (Cluster*)pa;
	FreeCluster* cur = 0;
	this->length = pn;

	for (unsigned int i = 0; i < pn; i++) {
		FreeCluster* temp = (FreeCluster*)cluster;
		temp->next = cur;
		if (i == 0)
			tail = temp;
		if (i == pn - 1)
			head = temp;
		cur = temp;
		cluster++;
	}
}

Cluster* OMAllocator::getFreeCluster() {
	if (!haveSpace()) 
		return 0;
	Cluster* cluster = (Cluster*)head;
	head = head->next;
	if (head == 0)
		tail = 0;
	length--;
	return cluster;
}

void OMAllocator::releaseCluster(Cluster* cluster) {
	FreeCluster* temp = (FreeCluster*)cluster;
	temp->next = 0;
	if (tail == 0)
		head = tail = temp;
	else
		tail = tail->next = temp;
	length++;
}

bool OMAllocator::haveSpace() const {
	return length > 0;
}

bool OMAllocator::canFit(PageNum pgn) const {
	return length >= pgn;
}

unsigned long OMAllocator::getNumOfFreeBlocks() const {
	return length;
}

