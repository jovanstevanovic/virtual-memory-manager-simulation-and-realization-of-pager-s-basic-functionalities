// File: Mutex.h
#pragma once
#include<mutex>

class Process;
class System;
class KernelProcess;

class Mutex {
public:
	Mutex(std::mutex* mx);
	~Mutex();

private:
	friend Process;
	friend System;
	friend KernelProcess;

	std::mutex* mtx;
	static std::mutex sem;
};
