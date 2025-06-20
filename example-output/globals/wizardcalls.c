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

# include <windows.h>
# include "../include/wizardcalls.h"

/* ------------------ Control Macros ------------------ */

//# define RANDOMIZE_JUMP_ADDRESS
//# define DEBUG

/* ------------------- Value Macros ------------------- */

// Misc
# define HASH_SEED 2189
# define UP					-32
# define DOWN				32
# define SYSCALL_STUB_SIZE	32

// Dlls
# define NTDLL 0x350914C7 // ntdll.dll

// Functions
# define NTALLOCATEVIRTUALMEMORY 0xDA1C0CBC
# define NTOPENPROCESS 0x5E806FB2
# define NTWRITEVIRTUALMEMORY 0xC4041CC0
# define NTCREATETHREADEX 0xDE45DE0C
# define NTPROTECTVIRTUALMEMORY 0xD948F970
# define NTFREEVIRTUALMEMORY 0x1EAB342D

// Hash list. This is important. Hashes must be defined in order the order they are defined in syscall list. This allows hashes to be resolved to appropriate syscall
// structure in parallel.
# define HASHES NTALLOCATEVIRTUALMEMORY, NTOPENPROCESS, NTWRITEVIRTUALMEMORY, NTCREATETHREADEX, NTPROTECTVIRTUALMEMORY, NTFREEVIRTUALMEMORY

// x64 op codes
# define RET		0xC3
# define JNE		0x75
# define MOV		0x4C
# define MOV2		0xB8
# define R10		0x8B
# define RCX		0xD1
# define JMP		0xE9
# define NULL_BYTE	0x00

// Offsetts
# define SYSCALL_OFFSET		18
# define JNE_INT2E_OFFSET	3

/* ------------------ Function Macros ----------------- */

# ifdef DEBUG
# include <stdio.h>
# define dbg( msg, ... )        printf( "[DEBUG]::Wizardcalls.%s.L%d -> " msg "\n", __func__, __LINE__, ##__VA_ARGS__ )
# endif

# ifndef DEBUG
# define dbg( msg, ... )        do {} while (0)
# endif

# define HashStringA( String )	HashStringSdbmA( String )
# define HashStringW( String )	HashStringSdbmW( String )

/* ---------------------- Globals --------------------- */

PSYSCALL_LIST SYSCALL_LIST_NAME;

/* --------------------- Externals -------------------- */

/*
    @brief
        Sets RBX to syscall structure pointer

    @param[in]    PSYSCALL pSyscall
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

/* -------------------- Prototypes -------------------- */

typedef ( NTAPI* fpWzDAllocate ) ( HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );

/* -------------------- Structures -------------------- */

typedef struct _CLIENT_ID_
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
}
CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
}
UNICODE_STRING_, * PUNICODE_STRING_;

typedef struct _LOADER_DATA_TABLE_ENTRY
{
    LIST_ENTRY		InLoadOrderLinks;
    LIST_ENTRY		InMemoryOrderLinks;
    LIST_ENTRY		InInitializationOrderLinks;
    PVOID			DllBase;
    PVOID			EntryPoint;
    ULONG			SizeOfImage;
    UNICODE_STRING_	FullDllName;
    UNICODE_STRING_ BaseDllName;
}
LOADER_DATA_TABLE_ENTRY, * PLOADER_DATA_TABLE_ENTRY;

typedef struct _PEB_LOADER_DATA
{
    ULONG		Length;
    BOOLEAN		Initialized;
    HANDLE		SsHandle;
    LIST_ENTRY	InLoadOrderModuleList;
    LIST_ENTRY	InMemoryOrderModuleList;
    LIST_ENTRY	InInitializationOrderModuleList;
    PVOID		EntryInProgress;
    BOOLEAN		ShutdownInProgress;
    HANDLE		ShutdownThreadId;
} 
PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING_ DosPath;
    HANDLE			Handle;
}
CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG			MaximumLength;
    ULONG			Length;
    ULONG			Flags;
    ULONG			DebugFlags;
    HANDLE			ConsoleHandle;
    ULONG			ConsoleFlags;
    HANDLE			StandardInput;
    HANDLE			StandardOutput;
    HANDLE			StandardError;
    CURDIR			CurrentDirectory;
    UNICODE_STRING_ DllPath;
    UNICODE_STRING_ ImagePathName;
    UNICODE_STRING_ CommandLine;
    PVOID			Environment;
} 
RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PROC_ENV_BLOCK
{
    BOOLEAN							InheritedAddressSpace;
    BOOLEAN							ReadImageFileExecOptions;
    BOOLEAN							BeingDebugged;
    HANDLE							Mutant;
    PVOID							ImageBaseAddress;
    PPEB_LOADER_DATA				Ldr;
    PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;
} 
PROC_ENV_BLOCK, * PPROC_ENV_BLOCK;

typedef struct _TEB_ 
{
    NT_TIB				ThreadInformationBlock;
    PPROC_ENV_BLOCK		ProcessEnvironmentBlock;
    CLIENT_ID			ClientId;
} 
THREAD_ENV_BLOCK, *PTHREAD_ENV_BLOCK;

/* -------------------- Functions --------------------- */

/*
	@brief
		Generate a random number using Linear Congruential Generation (LCG).

	@param[in] seed
		Any random number, used to generate entropy

	@return
		Returns a random number as int
*/
static int _rand( int seed )
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
static DWORD HashStringSdbmW( _In_ LPCWSTR String )
{
	ULONG Hash = HASH_SEED;
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
static DWORD HashStringSdbmA(_In_ LPCSTR String)
{
	ULONG Hash = HASH_SEED;
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
static VOID ZeroMem(PVOID pMemory, SIZE_T Size)
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
static HMODULE GetPebModuleByHash( DWORD Hash ) 
{

	WCHAR						ModuleName[ MAX_PATH ];
	WCHAR						Letter;
	INT							Index;
	PLOADER_DATA_TABLE_ENTRY	pLoadedModule;
	PPROC_ENV_BLOCK				pPeb;

	/* Get a pointer to the process environment block */
	if ( ( pPeb = ( PPROC_ENV_BLOCK )__readgsqword( 0x60 ) ) == NULL ) 
	{
		dbg( "NULL was returned for PEB." );
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
				dbg( "Resolved 0x%0.8X to %S at 0x%p", Hash, ModuleName, pLoadedModule->DllBase );
				return ( HMODULE )pLoadedModule->DllBase;
			}
		}
	}

	dbg( "Could not resolve 0x%0.8X to any module in this process.", Hash );
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
	DWORD						Hashes[ sizeof( HASHES ) * sizeof( HASHES ) ] = { HASHES };
	SIZE_T						SyscallListSize = sizeof(SYSCALL_LIST);

	dbg( "Initializing system calls..." );

	/* Acquire NTDLLs base address */
	if ( ( DllBase = ( ULONG_PTR ) GetPebModuleByHash( NTDLL ) ) == 0 )
		return NULL;

	/* Parse NT Headers */
	pNtHeaders = ( PIMAGE_NT_HEADERS ) ( DllBase + ( ( PIMAGE_DOS_HEADER )DllBase )->e_lfanew );
	if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) 
	{
		dbg( "NT signature mismatch while parsing ntdll at 0x%p", ( PVOID )DllBase );
		return NULL;
	}

	/* Get export directory, function names, addresses & ordinals */
	pExportDirectory	= ( PIMAGE_EXPORT_DIRECTORY ) ( DllBase + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	pFunctionAddreses	= ( PDWORD ) ( DllBase + pExportDirectory->AddressOfFunctions );
	pFunctionNames		= ( PDWORD ) ( DllBase + pExportDirectory->AddressOfNames );
	pOrdinals			= ( PWORD )  ( DllBase + pExportDirectory->AddressOfNameOrdinals );

	/* Locate NtAllocateVirtualMemory to create the syscall list*/
	for ( unsigned int OrdinalIndex = 0; OrdinalIndex < pExportDirectory->NumberOfNames; OrdinalIndex++ )
		if ( HashStringA( ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ) ) == NTALLOCATEVIRTUALMEMORY )
		{
			WzDAllocate = ( fpWzDAllocate ) ( DllBase + pFunctionAddreses[ pOrdinals [ OrdinalIndex ] ] );
		}

	if ( !WzDAllocate )
	{
		dbg( "Could not locate NtAllocateVirtualMemory" );
		return NULL;
	}

	/* Create & populate syscall list */
	if ( ( Status = WzDAllocate( ( HANDLE )-1, ( PVOID* )&pSyscallList, 0, &SyscallListSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) != NT_SUCCESS )
	{
		dbg( "Could not allocate memory for syscall list. 0x%0.8X", Status );
		return NULL;
	}
	ZeroMem( ( PVOID )pSyscallList, sizeof( SYSCALL_LIST ) );

	/* Populate syscall list */
	pSyscall = ( PSYSCALL )pSyscallList;
	for ( unsigned int SyscallIndex = 0; SyscallIndex < ( sizeof( SYSCALL_LIST ) / sizeof( SYSCALL ) ); SyscallIndex++ )	// Iterate over each syscall in syscall list structure
	{
		for ( unsigned int OrdinalIndex = 0; OrdinalIndex < pExportDirectory->NumberOfNames; OrdinalIndex++ )				// Iterate over each function in ntdll
		{
			if ( HashStringA( ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ) ) == Hashes[ SyscallIndex ] )			// Check if function hash matches specified hash. If match, begin resolving SSN.
			{

# ifndef DEBUG
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
					dbg( "Detected a hook in %s", ( PCHAR )( DllBase + pFunctionNames[ OrdinalIndex ] ) );
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
					dbg( "Could not locate SSN." );
					return NULL;
				}

				/* Fail if no ssn or hook is found */
				else 
				{
					dbg( "Could not locate an SSN." );
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
					dbg( "Could not locate either SSN or syscall jump address." );
					return NULL;
				}

# ifndef RANDOMIZE_JUMP_ADDRESS
				dbg( "Resolved 0x%0.8X to %s at 0x%p\n\t[+] > SSN: 0x%0.2X\n\t[+] > Jump Address: 0x%p", Hashes[ SyscallIndex ], ( PCHAR ) ( DllBase + pFunctionNames[ OrdinalIndex ] ), pFuncAddr, pSyscall->SSN, pSyscall->JumpAddress );
# endif

# ifdef RANDOMIZE_JUMP_ADDRESS
				dbg( "Resolved 0x%0.8X to %s at 0x%p\n\t[+] > SSN: 0x%0.2X\n\t[+] > Jump Address: 0x%p ( %s )", Hashes[ SyscallIndex ], ( PCHAR )( DllBase + pFunctionNames[ OrdinalIndex ] ), pFuncAddr, pSyscall->SSN, pSyscall->JumpAddress, ( PCHAR ) ( DllBase + pFunctionNames[ Seed ] ) );
# endif
			}
		}

		/* Move to next syscall */
		pSyscall++;
	}
	
	dbg( "Syscall initialization successful!" );
	return pSyscallList;
}

/* ---------------- System call wrappers ------------------ */

NTSTATUS NtAllocateVirtualMemory ( HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtAllocateVirtualMemory ) );
	return SystemCall( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection );
}

NTSTATUS NtOpenProcess ( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtOpenProcess ) );
	return SystemCall( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );
}

NTSTATUS NtWriteVirtualMemory ( HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtWriteVirtualMemory ) );
	return SystemCall( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );
}

NTSTATUS NtCreateThreadEx ( PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtCreateThreadEx ) );
	return SystemCall( hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList );
}

NTSTATUS NtProtectVirtualMemory ( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtProtectVirtualMemory ) );
	return SystemCall( ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection );
}

NTSTATUS NtFreeVirtualMemory ( HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeTypeThis )
{
	SetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->NtFreeVirtualMemory ) );
	return SystemCall( ProcessHandle, BaseAddress, RegionSize, FreeTypeThis );
}
