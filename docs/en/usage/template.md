# Using the wizardcalls template 
Wizardcalls will generate a few files which need to be imported to your implants code base. This is reffered to as the 'wizardcalls template'.

## About the Header
The wizardcalls header exports a variable number of functions. The first function is an initialization routine, the rest of the functions are wrappers for each syscall baked into the template.

### WzD* Macros
Wizardcalls offers a series of macros for each syscall where **Nt** has been replaced by **WzD**. These are intended to wrap the syscall function prototypes & provide the **SYSCALL_LIST** pointer to the syscall prototype on non-global templates. This allows the developer to exclude the syscall list pointer parameter in their function call, shortening development time & reducing code. Instead of providing an extra parameter, developers only need to specify the parameters required by the syscall.

> [!IMPORTANT]
> The macros are designed for non-global templates however they can still be used in global templates.

### WzDInit
This macro is a wrapper for **InitializeSystemCalls**. This macro changes based on the usage of global variables. **It is intended for developers to use macro over a direct call to InitializeSystemCalls. This ensures the function used properly based on how global variables are being used**.

###### Global syscall structure
```c
SYSCALL_LIST_NAME = InitializeSystemCalls()
```

###### Non-global syscall structure
```c
PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls()
```

### Functions
Wizardcalls only exports a single function which is documented below. All other exports are syscall prototypes.

#### InitializeSystemCalls()
This function initializes the **SYSCALL_LIST** structure & returns a pointer to the newly allocated structure. This structure can be used to access the syscalls where necessary. On global templates, this pointer will be assigned to a variable marked as external for usage in other parts of the implants source.

> [!IMPORTANT]
> Developers should use the **WzDInit** macro to call this function. It is not intended for developers to call this function directly. Based on how global variables are used in the program, this function will need to be called in a different manner. **WzDInit** takes care of this on behalf of the developer.

### Example Header
```c
/*
 * Generated with wizardcalls v-2.0.0
 * Template version: 2.0.0
 * Commandline: C:\Users\Admin\AppData\Roaming\Python\Python313\Scripts\wizardcalls --syscalls NtWriteVirtualMemory NtProtectVirtualMemory NtCreateThreadEx NtFreeVirtualMemory
 * ID: 7ba9fd08-8a41-459d-8034-42823cc99ad3
 * Using syscalls:
 * 	[+] - NtAllocateVirtualMemory
 * 	[+] - NtWriteVirtualMemory
 * 	[+] - NtProtectVirtualMemory
 * 	[+] - NtCreateThreadEx
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
	NtAllocateVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\
	NtWriteVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten )\

# define WzDProtectVirtualMemory( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\
	NtProtectVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection )\

# define WzDCreateThreadEx( hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\
	NtCreateThreadEx( SYSCALL_LIST_NAME, hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )\

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\
	NtFreeVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )\

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
	 SYSCALL NtWriteVirtualMemory;
	 SYSCALL NtProtectVirtualMemory;
	 SYSCALL NtCreateThreadEx;
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

NTSTATUS NtAllocateVirtualMemory ( PSYSCALL_LIST SYSCALL_LIST_NAME, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
NTSTATUS NtWriteVirtualMemory ( PSYSCALL_LIST SYSCALL_LIST_NAME, HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten );
NTSTATUS NtProtectVirtualMemory ( PSYSCALL_LIST SYSCALL_LIST_NAME, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection );
NTSTATUS NtCreateThreadEx ( PSYSCALL_LIST SYSCALL_LIST_NAME, PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList );
NTSTATUS NtFreeVirtualMemory ( PSYSCALL_LIST SYSCALL_LIST_NAME, HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis );
```