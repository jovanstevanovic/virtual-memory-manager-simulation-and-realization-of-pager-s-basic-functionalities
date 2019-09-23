#ifndef VM_SYSTEMTEST_H
#define VM_SYSTEMTEST_H


#include <mutex>
#include <vector>
#include "vm_declarations.h"
#include "Process.h"
#include "RandomNumberGenerator.h"
#include "System.h"

class ProcessTest;

class SystemTest {
public:
    explicit SystemTest(System& system_, void *processVMSpace, PageNum processVMSpaceSize);
    Status doInstruction(Process &process, const std::vector<std::tuple<VirtualAddress, AccessType, char>> addresses,
                         ProcessTest &processTest);
    std::mutex& getGlobalMutex();
private:
    void checkAddress(void *address) const;
    std::mutex mutex;
    System& system;
    void *beginSpace;
    void *endSpace;
};


#endif //VM_SYSTEMTEST_H
