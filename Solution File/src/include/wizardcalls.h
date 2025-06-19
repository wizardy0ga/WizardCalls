/*
	Wizardcalls v2. An indirect syscall utility with hook bypassing capabilities.

	Based on:
		https://github.com/am0nsec/HellsGate
		https://github.com/Maldev-Academy/HellHall
		https://github.com/trickster0/TartarusGate
*/
# pragma once
# include <Windows.h>

/* ---------------------- Macros ---------------------- */

# ifdef GLOBAL
# define WzDInit() SYSCALL_LIST_NAME = InitializeSystemCalls() 
# endif

# ifndef GLOBAL
# define WzDInit() PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls()
# endif

# define SYSCALL_LIST_NAME	pSyscallList
# define NT_SUCCESS		    0x0

/* ----------------- Function Macros ------------------ */

# define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\
	NtAllocateVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )

# define WzDProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\
	NtProtectVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit )\
	NtWriteVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit )

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis ) \
	NtFreeVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )

# define WzDCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList ) \
	NtCreateThreadEx( SYSCALL_LIST_NAME, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )

# define WzDWaitForSingleObject(Handle, Alertable, Timeout) \
	NtWaitForSingleObject( SYSCALL_LIST_NAME, Handle, Alertable, Timeout )

/* -------------------- Structures -------------------- */

typedef struct _SYSCALL_ 
{
    DWORD SSN;
    PVOID JumpAddress;
}
SYSCALL, *PSYSCALL;

typedef struct _SYSCALL_LIST_ 
{
	SYSCALL NtAllocateVirtualMemory;
	SYSCALL NtFreeVirtualMemory;
	SYSCALL NtWriteVirtualMemory;
	SYSCALL	NtProtectVirtualMemory;
	SYSCALL NtCreateThreadEx;
	SYSCALL NtWaitForSingleObject;
}
SYSCALL_LIST, *PSYSCALL_LIST;

/* -------------------- Externals --------------------- */


# ifdef GLOBAL
extern PSYSCALL_LIST SYSCALL_LIST_NAME;
# endif

/* -------------------- Prototypes -------------------- */

/*
    @brief
        Intializes the system call list. Needs to be called prior to using system calls.

    @return
        A pointer to the system call list structure (PSYSCALL_LIST)
*/
PSYSCALL_LIST InitializeSystemCalls();

NTSTATUS NtProtectVirtualMemory  ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtWriteVirtualMemory    ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWrittenit );
NTSTATUS NtAllocateVirtualMemory ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtWaitForSingleObject   ( PSYSCALL_LIST pSyscallList, HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout );
NTSTATUS NtCreateThreadEx		 ( PSYSCALL_LIST pSyscallList, PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtFreeVirtualMemory	 ( PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );
