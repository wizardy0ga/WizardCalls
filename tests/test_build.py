import random
import subprocess
import os
import shutil
from pytest import fail
from wizardcalls import WizardCalls

NO_SHOW_COMPILATION_OUTPUT  = True # When true, hide stdout from compilation process
NO_SHOW_EXECUTION_OUTPUT    = True # When true, hide stdout from executed binary program

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
cl main.c { wizardsource.source.filename } wizardcalls.x64.obj { ' '.join(compiler_args) }
link.exe main.obj wizardcalls.obj wizardcalls.x64.obj { ' '.join(linker_args) }
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

def test_hashing_functions():
    for algo in [ 'sdbm', 'djb2', 'jenkins', 'murmur' ]:
        if not build( hash_algo = algo, globals = False, randomize_jump_address = False ):
            fail( f"Failed on { algo } hashing algo test" )
        else:
            print( f"Passed { algo } hashing algo test" )

def test_globals():
    if not build( hash_algo = 'sdbm', globals = True, randomize_jump_address = False, compiler_args = ['/O2'] ):
        fail( "Failed on globals test" )
    else:
        print( "Passed globals test" )

def test_position_independence():
    if not build( hash_algo = 'sdbm', globals = False, randomize_jump_address = False ):
        fail( "Failed on position independence test" )
    else:
        print ("Passed position indenpendence test" )

def test_jump_address_randomization():
    if not build( hash_algo = 'sdbm', globals = False, randomize_jump_address = True):
        fail( "Failed jump address randomization test" )
    else:
        print( "Passed jump address randomization test" )