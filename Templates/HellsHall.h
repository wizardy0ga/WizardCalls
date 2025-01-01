#pragma once
#include <Windows.h>
#include "Structs.h"

//#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#define dbg_print(msg, ...) printf(msg , ##__VA_ARGS__);
#endif
#ifndef DEBUG
#define dbg_print(msg, ...) do {} while (0);
#endif

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

<Insert>

BOOL InitializeSystemCalls();