// File: vm_declarations.h
#pragma once

typedef unsigned long RefBitsHistory;

typedef unsigned long PageNum;

typedef unsigned short int VMPageNum;

typedef unsigned long VirtualAddress;

typedef void* PhysicalAddress;

typedef unsigned long Time;

typedef unsigned long SegmentSize;

typedef unsigned short startVAddr;

enum Status { OK, PAGE_FAULT, TRAP };

enum AccessType { READ, WRITE, READ_WRITE, EXECUTE };

typedef unsigned ProcessId;

#define PAGE_SIZE 1024

