import os
import random
import argparse

def dir_exists( path: str ) -> str:
    """ Validate directory existence for arguments """
    if not os.path.isdir( path ):
        raise argparse.ArgumentTypeError( f"The directory '{ path }' does not exist." )
    return path

def file_exists( path:str ) -> str:
    """ Validate file existence for arguments """
    if not os.path.isfile( path ):
        raise argparse.ArgumentTypeError( f"The file '{ path }' does not exist." )
    return path

def parse_user_args() -> argparse.ArgumentParser:
    # ------------------------ Arguments -----------------------
    parser = argparse.ArgumentParser( add_help = False )

    parser.add_argument(
        '-h'
        , '--help'
        , default   = False
        , action    = 'store_true'
        , help      = 'Show this message and exit'
    )

    parser.add_argument(
        '-v'
        , '--version'
        , default   = False
        , action    = 'store_true'
        , help      = 'Show the version & exit.'
    )

    parser.add_argument(
        '-q'
        , '--quiet'
        , action    = 'store_true'
        , default   = False
        , help      = 'Suppress the banner & config output when building the source code.'
    )

    parser.add_argument( 
        '-o'
        , '--outdir'
        , default   = os.getcwd()
        , type      = dir_exists
        , help      = 'A directory to write the source files to. Defaults to "Out" directory.'
    )

    # ------------------- Build Options --------------------
    build_opt_group = parser.add_argument_group( title = "Build Options", description = "Set options to control how wizardcalls functions" )
    build_opt_group.add_argument( 
        '-s'
        , '--seed'
        , type      = int
        , default   = random.randrange( 1, 10000 )
        , help      = 'Seed for the hashing algorithm. Generates a random seed if none is provided.' 
    )

    build_opt_group.add_argument(
        '-a'
        , '--algo'
        , choices   = [ 'sdbm', 'djb2', 'jenkins', 'murmur' ]
        , default   = 'sdbm'
        , help      = 'An algorithm to hash the syscalls with. Defaults to sdbm.'
    )
    
    build_opt_group.add_argument(
        '-d'
        , '--debug'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables debug mode in the header file.' 
    )
    
    build_opt_group.add_argument( 
        '-r'
        , '--random_syscall_addr'
        , action    = 'store_true'
        , default   = False
        , help      = 'Use random syscall instructions when performing indirect jump. Obfuscates the callstack a bit.'
    )

    build_opt_group.add_argument(
        '-g'
        , '--globals'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enable the use of global variables. Code will no longer be position independent.'
    )

    build_opt_group.add_argument(
        '-rm'
        , '--remove_comments'
        , action    = 'store_true'
        , default   = False
        , help      = 'Remove comments from the source code.'
    )
    
    build_opt_group.add_argument(
        '-n'
        , '--syscall_list_name'
        , type      = str
        , default   = 'pSyscallList'
        , help      = 'Set the name of the PSYSCALL_LIST variable, to be used throughout the code.'
    )
    
    # ------------------ API Call Inputs -------------------
    input_arg_group = parser.add_mutually_exclusive_group()
    input_arg_group.add_argument(
        '-sc'
        , '--syscalls'
        , type      = str
        , nargs     = "+"
        , help      = 'List of win32 native api calls to generate the template for.'
    )
    
    input_arg_group.add_argument(
        '-f'
        , '--file'
        , type    = file_exists
        , default = False
        , help    = 'Path to file containing a list of api calls. Use a new line [\\n] to seperate each api call.' 
    )

    return parser