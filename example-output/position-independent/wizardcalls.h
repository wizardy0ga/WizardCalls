/*
 * Generated with wizardcalls v-2.0.0
 * Template version: 2.0.0
 * Commandline: .\wizardcalls.py --apicalls NtOpenProcess NtWriteVirtualMemory NtCreateThreadEx NtProtectVirtualMemory NtFreeVirtualMemory --outdir .\example-output\position-independent\
 * ID: bb7837bf-0a12-4824-8779-1da5a580b80c
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
# define WzDInit() PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls()
# define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\
	NtAllocateVirtualMemory( PSYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\

# define WzDOpenProcess( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId )\
	NtOpenProcess( PSYSCALL_LIST_NAME, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId )\

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\
	NtWriteVirtualMemory( PSYSCALL_LIST_NAME, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\

# define WzDCreateThreadEx( hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\
	NtCreateThreadEx( PSYSCALL_LIST_NAME, hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\

# define WzDProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\
	NtProtectVirtualMemory( PSYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\
	NtFreeVirtualMemory( PSYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\

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

/* -------------------- Prototypes -------------------- */

/*
    @brief
        Intializes the system call list. Needs to be called prior to using system calls.

    @return
        A pointer to the system call list structure (PSYSCALL_LIST)
*/
PSYSCALL_LIST InitializeSystemCalls();

NTSTATUS NtAllocateVirtualMemory ( PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtOpenProcess ( PSYSCALL_LIST pSyscallList, PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId );
NTSTATUS NtWriteVirtualMemory ( PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten );
NTSTATUS NtCreateThreadEx ( PSYSCALL_LIST pSyscallList, PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtProtectVirtualMemory ( PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtFreeVirtualMemory ( PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );