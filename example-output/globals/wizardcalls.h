/*
 * Generated with wizardcalls v-2.0.0
 * Template version: 2.0.0
 * Commandline: .\wizardcalls.py --apicalls NtOpenProcess NtWriteVirtualMemory NtCreateThreadEx NtProtectVirtualMemory NtFreeVirtualMemory --outdir example-output\globals\ --globals
 * ID: 4a440cd8-c044-436a-a6de-9a62543f7f07
 * Using syscalls:
 * 	[+] - NtAllocateVirtualMemory
 * 	[+] - NtOpenProcess
 * 	[+] - NtWriteVirtualMemory
 * 	[+] - NtCreateThreadEx
 * 	[+] - NtProtectVirtualMemory
 * 	[+] - NtFreeVirtualMemory
*/

# pragma once
# include <Windows.h>

/* ---------------------- Macros ---------------------- */

// Values
# define SYSCALL_LIST_NAME pSyscallList
# define NT_SUCCESS		    0x0

// Functions
# define WzDInit() SYSCALL_LIST_NAME = InitializeSystemCalls()
# define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\
	NtAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\

# define WzDOpenProcess( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId )\
	NtOpenProcess( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId )\

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\
	NtWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\

# define WzDCreateThreadEx( hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\
	NtCreateThreadEx( hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\

# define WzDProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\
	NtProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\
	NtFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\

/* -------------------- Structures -------------------- */

typedef struct _SYSCALL_ 
{
    DWORD SSN;
    PVOID JumpAddress;
}
SYSCALL, *PSYSCALL;

typedef struct
{
	 SYSCALL NtAllocateVirtualMemory;
	 SYSCALL NtOpenProcess;
	 SYSCALL NtWriteVirtualMemory;
	 SYSCALL NtCreateThreadEx;
	 SYSCALL NtProtectVirtualMemory;
	 SYSCALL NtFreeVirtualMemory;
}
SYSCALL_LIST, *PSYSCALL_LIST;

/* -------------------- Externals --------------------- */

extern PSYSCALL_LIST SYSCALL_LIST_NAME;

/* -------------------- Prototypes -------------------- */

/*
    @brief
        Intializes the system call list. Needs to be called prior to using system calls.

    @return
        A pointer to the system call list structure (PSYSCALL_LIST)
*/
PSYSCALL_LIST InitializeSystemCalls();

NTSTATUS NtAllocateVirtualMemory ( HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtOpenProcess ( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId );
NTSTATUS NtWriteVirtualMemory ( HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten );
NTSTATUS NtCreateThreadEx ( PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtProtectVirtualMemory ( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtFreeVirtualMemory ( HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );