#pragma once
#include <Windows.h>
#include "Structs.h"


#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#define dbg_print(msg, ...) printf(msg , ##__VA_ARGS__);
#endif
#ifndef DEBUG
#define dbg_print(msg, ...) do {} while (0);
#endif

/* x64 op codes */
#define RET         0xC3
#define MOV         0x4C
#define MOV2        0xB8
#define R10         0x8B
#define RCX         0xD1
#define JMP         0xE9
#define NULL_BYTE   0x00

typedef struct _DLL_
{
    PDWORD		Addresses;
    PDWORD		Names;
    PWORD		Ordinals;
    DWORD		NumberOfNames;
    ULONG_PTR	DllBaseAddress;
    BOOL		bInitialized;
} DLL, * PDLL;

typedef struct _SYSTEM_CALL
{
    DWORD SSN;
    PVOID JumpAddress;
} SYSTEM_CALL, * PSYSTEM_CALL;

#define HASH_SEED 7627
#define hash_NTDLLDLL_sdbm 0x45FB4B09
#define NTDLL hash_NTDLLDLL_sdbm
#define hash_KERNEL32DLL_sdbm 0x2AB7033D
#define KERNEL32 hash_KERNEL32DLL_sdbm
#define hash_LOADLIBRARYA_sdbm 0x7A63D8B7
#define LOADLIBRARYA hash_LOADLIBRARYA_sdbm
#define hash_NTALLOCATEVIRTUALMEMORY_sdbm 0xEDEBBBFE
#define hash_NTFREEVIRTUALMEMORY_sdbm 0x215B656F
#define hash_NTCREATETHREADEX_sdbm 0x9AE1FB4A
#define hash_NTWRITEVIRTUALMEMORY_sdbm 0x9EA23BFE
#define hash_NTWAITFORSINGLEOBJECT_sdbm 0xA41B21EA

#define NT_API_FUNCTION_HASH_LIST hash_NTALLOCATEVIRTUALMEMORY_sdbm,hash_NTFREEVIRTUALMEMORY_sdbm,hash_NTCREATETHREADEX_sdbm,hash_NTWRITEVIRTUALMEMORY_sdbm,hash_NTWAITFORSINGLEOBJECT_sdbm

typedef struct _SYSTEM_CALLS_TABLE {
    SYSTEM_CALL NtAllocateVirtualMemory;
    SYSTEM_CALL NtFreeVirtualMemory;
    SYSTEM_CALL NtCreateThreadEx;
    SYSTEM_CALL NtWriteVirtualMemory;
    SYSTEM_CALL NtWaitForSingleObject;
} SYSTEM_CALLS_TABLE, * PSYSTEM_CALLS_TABLE;

#define OBFUSCATED_SYSCALL 0xCA6B
#define SYSCALL_XOR_KEY 0xCF64

BOOL InitializeSystemCalls();