#include "Mutex.h"

std::mutex Mutex::sem;

Mutex::Mutex(std::mutex* mt) : mtx(mt) {
	if(mtx != 0)
	   mtx->lock();
}

Mutex::~Mutex() {
	if(mtx != 0)
	   mtx->unlock();
}
