#include <cassert>
#include "SystemTest.h"
#include "ProcessTest.h"

SystemTest::SystemTest(System &system_, void *processVMSpace, PageNum processVMSpaceSize)
        : mutex(), system(system_), beginSpace(processVMSpace),
          endSpace((void *) ((uint8_t *) beginSpace + PAGE_SIZE * processVMSpaceSize)) {
}

Status SystemTest::doInstruction(Process &process,
                                 const std::vector<std::tuple<VirtualAddress, AccessType, char>> addresses,
                                ProcessTest &processTest) {
    for (auto iter = addresses.begin(); iter != addresses.end(); iter++) {
        AccessType accessType = std::get<1>(*iter);
        VirtualAddress address = std::get<0>(*iter);
        char expectedValue = std::get<2>(*iter);
        switch (accessType) {
            case READ:
            case EXECUTE: {
                std::lock_guard<std::mutex> guard(mutex);

                char value;
                Status success = system.access(process.getProcessId(), address, accessType);
                if (success != OK) {
                    success = process.pageFault(address);
                    if (success != OK) {
                        return success;
                    }
                    success = system.access(process.getProcessId(), address, accessType);
                }
                assert (success == OK);

                PhysicalAddress pa = process.getPhysicalAddress(address);
                checkAddress(pa);
                value = *(char *) pa;
                processTest.checkValue(address, expectedValue);
                break;
            }
            case WRITE: {
                std::lock_guard<std::mutex> guard(mutex);

                Status success = system.access(process.getProcessId(), address, accessType);
                if (success != OK) {
                    success = process.pageFault(address);
                    if (success != OK) {
                        return success;
                    }
                    success = system.access(process.getProcessId(), address, accessType);
                }
                assert (success == OK);

                PhysicalAddress pa = process.getPhysicalAddress(address);
                checkAddress(pa);
                *(char *) pa = expectedValue;
				processTest.markDirty(address);
                break;
            }
            default: break;
        }
    }
    return OK;
}

void SystemTest::checkAddress(void *address) const {
    assert(address);
    assert(address >= beginSpace);
    assert(address <= endSpace);
}

std::mutex &SystemTest::getGlobalMutex() {
    return mutex;
}
