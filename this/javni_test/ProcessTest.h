#ifndef VM_PROCESSTEST_H
#define VM_PROCESSTEST_H

#include <thread>
#include <vector>
#include "vm_declarations.h"
#include "Process.h"

class SystemTest;

class ProcessTest {
public:
    explicit ProcessTest(System& system, SystemTest& systemTest_);
    Status addCodeSegment(VirtualAddress address, PageNum size);
    Status addDataSegment(VirtualAddress address, PageNum size);
    void writeToAddress(VirtualAddress address, char value);
	void markDirty(VirtualAddress address);
    char readFromAddress(VirtualAddress address);
    void checkValue(VirtualAddress address, char value);
    bool isFinished() const;
    void run();
    ~ProcessTest();

private:
    typedef std::pair<char *, bool *> MemoryBackup;

    VirtualAddress alignToPage(VirtualAddress address);
    VirtualAddress getOffset(VirtualAddress address);
    PhysicalAddress getPhyAddress(VirtualAddress address);
    std::tuple<MemoryBackup, VirtualAddress, PageNum> getSegmentInfo(VirtualAddress address);

    std::vector<std::tuple<MemoryBackup, VirtualAddress, PageNum>> checkMemory;
    Process *process;
    SystemTest &systemTest;
    bool finished;
};


#endif //VM_PROCESSTEST_H
