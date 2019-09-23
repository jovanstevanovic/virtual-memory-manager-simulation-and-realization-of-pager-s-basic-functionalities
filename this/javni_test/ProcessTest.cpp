#include <cassert>
#include <iostream>
#include "ProcessTest.h"
#include "System.h"
#include "RandomNumberGenerator.h"
#include "SystemTest.h"

#define POWER_OF_NUMBER_OF_INSTRUCTIONS (15)

ProcessTest::ProcessTest(System &system, SystemTest &systemTest_) : systemTest(systemTest_), finished(false) {
    process = system.createProcess();

    VirtualAddress address;
    PageNum size;
    address = alignToPage(PAGE_SIZE);
    size = 100;

    if (OK != addCodeSegment(address, size)) {
        std::cout << "Cannot create code segment in process " << process->getProcessId() << std::endl;
        throw std::exception();
    }

    for (int i = 0; i < 10; i++) {
        address += PAGE_SIZE * (size + 1);
        address = alignToPage(address);
        if (OK != addDataSegment(address, size)) {
            std::cout << "Cannot create data segment in process " << process->getProcessId() << std::endl;
            throw std::exception();
        }
    }
}

Status ProcessTest::addCodeSegment(VirtualAddress address, PageNum size) {
    char *initData = new char[size * PAGE_SIZE];
    bool *dirtyData = new bool[size * PAGE_SIZE];

    for (int i = 0; i < size * PAGE_SIZE; i++) {
        initData[i] = i;
        dirtyData[i] = true;
    }

    Status status = process->loadSegment(address, size, EXECUTE, initData);
    if (status != OK) {
        delete[] initData;
        return status;
    }

    MemoryBackup backup;
    backup.first = initData;
    backup.second = dirtyData;

    checkMemory.emplace_back(std::make_tuple<MemoryBackup, VirtualAddress, PageNum>(
            std::move(backup), std::move(address), std::move(size)));

    return OK;
}

Status ProcessTest::addDataSegment(VirtualAddress address, PageNum size) {
    char *data = new char[size * PAGE_SIZE];
    bool *dirtyData = new bool[size * PAGE_SIZE];

    for (int i = 0; i < size * PAGE_SIZE; i++) {
        dirtyData[i] = false;
    }

    Status status = process->createSegment(address, size, READ_WRITE);
    if (status != OK) {
        delete[] data;
        return status;
    }

    MemoryBackup backup;
    backup.first = data;
    backup.second = dirtyData;

    checkMemory.emplace_back(std::make_tuple<MemoryBackup, VirtualAddress, PageNum>(
            std::move(backup), std::move(address), std::move(size)));

    return OK;
}

ProcessTest::~ProcessTest() {
    for (auto iter = checkMemory.begin(); iter != checkMemory.end(); iter++) {
        MemoryBackup &backup = std::get<0>(*iter);
        delete [] backup.first;
        delete [] backup.second;
    }

    delete process;
}

VirtualAddress ProcessTest::getOffset(VirtualAddress address) {
    return address % PAGE_SIZE;
}

VirtualAddress ProcessTest::alignToPage(VirtualAddress address) {
    return address / PAGE_SIZE * PAGE_SIZE;
}

void ProcessTest::writeToAddress(VirtualAddress address, char value) {
    char *writeAddr = (char *) getPhyAddress(address);
    *writeAddr = value;
}

char ProcessTest::readFromAddress(VirtualAddress address) {
    char *readAddress = (char *) getPhyAddress(address);
    return *readAddress;
}

PhysicalAddress ProcessTest::getPhyAddress(VirtualAddress address) {
    std::tuple<MemoryBackup, VirtualAddress, PageNum> segment = getSegmentInfo(address);

    VirtualAddress begin = std::get<1>(segment);
    PhysicalAddress pa = std::get<0>(segment).first;
    VirtualAddress offset = address - begin;

    return (PhysicalAddress) ((char *) pa + offset);
}



void ProcessTest::run() {
    VirtualAddressGenerator rN(0);
    VirtualAddressGenerator::NumberLimits limits;

    for (auto iter = checkMemory.begin(); iter != checkMemory.end(); iter++) {
        VirtualAddress begin = std::get<1>(*iter);
        VirtualAddress end = begin + PAGE_SIZE * std::get<2>(*iter) - 1;

        limits.emplace_back(begin, end);
    }

    for (int i = 0; i < (1 << POWER_OF_NUMBER_OF_INSTRUCTIONS); i++) {
        for (int j = 2; j < checkMemory.size(); j++) {
            std::vector<VirtualAddress> numbers = rN.getRandomNumbers(limits, j);
            std::vector<std::tuple<VirtualAddress, AccessType, char>> addresses;

            addresses.emplace_back(numbers[0], EXECUTE, readFromAddress(numbers[0]));
            for (int k = 1; k < numbers.size(); k++) {
                char data;
                AccessType type;
                if ((k + j) % 3) {
                    data = rN.getRandomNumber();
                    writeToAddress(numbers[k], data);
                    type = WRITE;
                } else {
                    data = readFromAddress(numbers[k]);
                    type = READ;
                }
                addresses.emplace_back(numbers[k], type, data);
            }
            Status status = systemTest.doInstruction(*process, addresses, *this);
            if (status != OK) {
                std::cout << "Instruction in process " << process->getProcessId() << " failed.\n";
                std::cout << "Terminating process\n";
                throw std::exception();
            }
        }
    }

    finished = true;
}

bool ProcessTest::isFinished() const {
    return finished;
}

std::tuple<ProcessTest::MemoryBackup, VirtualAddress, PageNum>
ProcessTest::getSegmentInfo(VirtualAddress address) {
    std::tuple<MemoryBackup, VirtualAddress, PageNum> segment;

    auto iter = checkMemory.begin();
    for (; iter != checkMemory.end(); iter++) {
        VirtualAddress begin = std::get<1>(*iter);
        VirtualAddress end = begin + PAGE_SIZE * std::get<2>(*iter);

        if (begin <= address && address < end) {
            segment = *iter;
            break;
        }
    }

    assert(iter != checkMemory.end());

    return segment;
}

void ProcessTest::checkValue(VirtualAddress address, char value) {
    std::tuple<MemoryBackup, VirtualAddress, PageNum> segment = getSegmentInfo(address);
    MemoryBackup &backup = std::get<0>(segment);

    VirtualAddress begin = std::get<1>(segment);
    VirtualAddress offset = address - begin;

    if (backup.second[offset]) {
        assert(backup.first[offset] == value);
    }
}

void ProcessTest::markDirty(VirtualAddress address) {
    std::tuple<MemoryBackup, VirtualAddress, PageNum> segment = getSegmentInfo(address);

    MemoryBackup &backup = std::get<0>(segment);

    VirtualAddress begin = std::get<1>(segment);
    VirtualAddress offset = address - begin;

    backup.second[offset] = true;
}



