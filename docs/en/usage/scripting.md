# Scripting with Wizardcalls
Wizardcalls offers developers an interface for use in python scripts. Developers can use this interface when writing their own implant related scripts.

## The WizardCalls object
```py
class WizardCalls( object ):
    """ Container object for all 3 related source file objects """
    def __init__( self, globals: bool, syscalls: list, syscall_list_name:str, hash_seed: int, hash_algo:str, randomize_jump_address:bool, debug: bool ):
        self.header     = WizardCallsHeader( globals, syscalls, syscall_list_name )
        self.source     = WizardCallsSource( globals, syscalls, hash_seed, hash_algo, randomize_jump_address, debug )
        self.asm_source = WizardCallsAsm( globals )
```
The WizardCalls object contains 3 properties, each representing a source code file. To use wizardcalls in a script, developers will need to import & initialize this object within their script. Each of the properties are described below.

> ![IMPORTANT]
> Each of the parameters are objects which share the same parent class, **SourceCode**. They each share a set of methods used for source code manipulation. 

| Property | Description |
| - | - |
| header | Represents the wizardcalls header file (wizardcalls.h)
| source | Represents the wizardcalls source file (wizardcalls.c)
| asm_source | Represents the assembly file used by wizardcalls (wizardcalls.x64.asm)

### Object Initialization Parameters
#### Globals (bool)
This is a boolean option which determines the scope of the wizardcalls API. If **true**, wizardcalls will generate a template which produces a syscall API that's globally available throughout the program. If **false**, the syscall API will only be accessible within the scope of the program that it's initialized in. Additionally references to the API will need to be passed to necessary functions.

#### Syscalls (list)
This is a list of syscalls to include in the template. Wizardcalls will bake these functions into the syscall API & resolve their addresses at run time.

#### Syscall_list_name (string)
This represents the name of the syscall API variable. Developers will use this variable name when accessing the syscall api in their source code.

#### Hash_seed (int)
This is an integer which initializes the hash for all available hashing alorithms.

#### Hash_algo (string)
This is a string that determines which hashing algorithm wizardcalls will use when resolving the syscall addresses.

#### Randomize_jump_address (bool)
This is a boolean option which instructs wizardcalls to use a random syscall address when jumping to the syscall instruction after setting EAX to the SSN of the syscall. This obfuscates the call stack by returning to a syscall function address other than the actual function that was called. This may throw off malware analysts if they're not paying attention to the SSN that was passed.

#### debug (bool)
This is a boolean option which enables debug statements within the wizardcalls source code.

### Nested Object Properties
Since each of the WizardCalls object properties are a child of the same parent class, this means they share common properties. Important properties are listed below.

#### Content (string)
This contains the files source code. Use this to view / access the source code represented by the object.
```py
print(wizardcalls.header.content)
print(wizardcalls.source.content)
print(wizardcalls.asm.content)
```

#### Filename (string)
This is the name of the file when it's written to a directory.
```py
print(wizardcalls.header.filename)
print(wizardcalls.source.filename)
print(wizardcalls.asm.filename)
```

### Nested Object Methods
The objects also share common methods. These methods have been described below.

#### replace_content
Uses regex matching to locate & replace code content.
```py
def replace_content( self, new_content: str, pattern: str, count = 1 ) -> None:
    """ Replace the content of a file via regex matching """
```
| argument | description |
| - | - |
| new_content | This will be the new content in the file |
| pattern | A regex pattern for the content to replace |
| count | The amount of times to match & replace the content. Defaults to 1st match. Use 0 to replace all matches |

#### write_to_dir
Writes the code files content to the specified directory.
```py
def write_to_dir( self, directory: str ) -> None:
    """ Write the source file to a directory """
```
| argument | description |
| - | - |
| directory | The path of the directory to write the source code

#### remove_comments
Strips all comments from the source code except for the banner comment at the top of each file.
```py
def remove_comments( self ) -> None:
    """ Remove comments from the source code. """
```

#### remove_blank_lines
Removes all empty lines from the file where consecutive empty lines are >= 2
```py
def remove_blank_lines( self ) -> str:
    """ Remove all blank lines greater than 2 from source """
```

## Script Example
The example script is [test_build.py](../../../tests/test_build.py). This script is used to test the module to ensure everything is working correctly.

The **build** function initializes a wizardcalls object & passes it to the **compile** function which bakes the wizardcalls source with some main source code & compiles it to create an executable.

This script demonstrates how the interface can be used by developers in their own compilation or other scripts.

```py
import random
import subprocess
import os
import shutil
from wizardcalls import WizardCalls

def compile( wizardsource: WizardCalls, compiler_args: list, linker_args: list ) -> int:
    """ Compile the source code & return status object from subprocess.run """
    # Create file paths & code for compiler
    temp_dir      = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'temp' )
    main_source   = os.path.join( '..', 'src', 'wizardcalls', 'rsrc', 'code', 'solution file', 'src', 'source', 'main.c' )
    main_dest     = os.path.join( temp_dir, 'main.c' )
    compiler_file = os.path.join( 'temp', 'compiler.bat' )
    
    compiler_code = f"""@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
cd "{ temp_dir }"
ml64.exe /c /Fo wizardcalls.x64.obj "{ wizardsource.asm_source.filename }"
cl main.c { wizardsource.source.filename } wizardcalls.x64.obj /O2
link.exe main.obj wizardcalls.obj wizardcalls.x64.obj
"""
    # Write source code to directory
    os.makedirs( temp_dir, exist_ok = True )
    wizardsource.header.write_to_dir( temp_dir )
    wizardsource.source.write_to_dir( temp_dir )
    wizardsource.asm_source.write_to_dir( temp_dir )
    with open( main_source, 'r' ) as source_file:
        data = source_file.read().replace( '# include "../Include/wizardcalls.h"', '# include "wizardcalls.h"' )
    with open( main_dest, 'w') as dest_file:
        dest_file.write(data)
    with open( compiler_file, 'w' ) as compiler_script:
        compiler_script.write( compiler_code )

    # Run compiler script, remove temp dir & return status
    if subprocess.run( ['cmd.exe', '/c', compiler_file ], check=False, capture_output=NO_SHOW_COMPILATION_OUTPUT ).returncode != 0:
        assert "Failed to compile the source code."
    
    status = subprocess.run(['cmd.exe', '/c', 'main.exe'], check=False, capture_output=NO_SHOW_EXECUTION_OUTPUT, cwd=temp_dir)
    #shutil.rmtree( temp_dir )
    return status.returncode

def build( hash_algo: str, globals: bool, randomize_jump_address: bool, compiler_args = [], linker_args = [] ) -> bool:
    """ Create & compile wizard calls using specifications defined in parameters """
    if compile( WizardCalls(
        syscalls                 = [ 'NtAllocateVirtualMemory','NtFreeVirtualMemory','NtWriteVirtualMemory','NtCreateThreadEx','NtWaitForSingleObject' ]
        , syscall_list_name      = 'pSyscallz'
        , hash_seed              = random.randint( 0, 10000 )
        , globals                = globals
        , hash_algo              = hash_algo
        , randomize_jump_address = randomize_jump_address
        , debug                  = True
    ), compiler_args = compiler_args, linker_args = linker_args ) != 0:
        return False
    return True
```