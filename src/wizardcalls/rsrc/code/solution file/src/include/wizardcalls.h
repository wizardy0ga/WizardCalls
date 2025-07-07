/*
	Wizardcalls v2. An indirect syscall utility with hook bypassing capabilities.

	Based on:
		https://github.com/am0nsec/HellsGate
		https://github.com/Maldev-Academy/HellHall
		https://github.com/trickster0/TartarusGate
*/
# pragma once
# include <Windows.h>

/* ------------------ Control Macros ------------------ */
// # define GLOBAL

/* ---------------------- Macros ---------------------- */

// Values
# define SYSCALL_LIST_NAME	pSyscallList
# define NT_SUCCESS		    0x0


// Functions
# ifdef GLOBAL
# define WzDInit() SYSCALL_LIST_NAME = InitializeSystemCalls()

# define WzDAllocateVirtualMemory( ... )	NtAllocateVirtualMemory( ##__VA_ARGS__ )
# define WzDProtectVirtualMemory( ... )		NtProtectVirtualMemory( ##__VA_ARGS__ )
# define WzDWriteVirtualMemory( ... )		NtWriteVirtualMemory( ##__VA_ARGS__ )
# define WzDFreeVirtualMemory( ... )		NtFreeVirtualMemory( ##__VA_ARGS__ )
# define WzDCreateThread( ... )				NtCreateThreadEx( ##__VA_ARGS__ )
# define WzDWaitForSingleObject( ... )		NtWaitForSingleObject( ##__VA_ARGS__ )
# endif


# ifndef GLOBAL
# define WzDInit() PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls()

# define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\
	NtAllocateVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )

# define WzDProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\
	NtProtectVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit )\
	NtWriteVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit )

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis ) \
	NtFreeVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )

# define WzDCreateThreadEx( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList ) \
	NtCreateThreadEx( SYSCALL_LIST_NAME, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )

# define WzDWaitForSingleObject(Handle, Alertable, Timeout) \
	NtWaitForSingleObject( SYSCALL_LIST_NAME, Handle, Alertable, Timeout )

# endif

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

# ifdef GLOBAL
NTSTATUS NtProtectVirtualMemory  ( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtWriteVirtualMemory    ( HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWrittenit );
NTSTATUS NtAllocateVirtualMemory ( HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtWaitForSingleObject   ( HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout );
NTSTATUS NtCreateThreadEx		 ( PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtFreeVirtualMemory	 ( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );
# endif

# ifndef GLOBAL
NTSTATUS NtProtectVirtualMemory  ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtWriteVirtualMemory    ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWrittenit );
NTSTATUS NtAllocateVirtualMemory ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtWaitForSingleObject   ( PSYSCALL_LIST pSyscalls, HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout );
NTSTATUS NtCreateThreadEx		 ( PSYSCALL_LIST pSyscalls, PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtFreeVirtualMemory	 ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );
# endif