import os
import re
import sys
import json
import random
import argparse


# -------------------------- Constants --------------------------

SCRIPT_VERSION      = "2.0.0"
TEMPLATE_VERSION    = "2.0.0"

GREEN   = "\033[1;32m"
RED     = "\033[0;31m"
CYAN    = "\033[1;36m"
PURPLE  = "\033[1;35m"
WHITE   = "\033[1;37m"
END     = "\033[0m"
YELLOW  = "\033[1;33m"

NT_DATA      = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'data', 'nt_api.json' )
ASM_GLOBAL   = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'Solution File', 'src', 'source' , 'wizardcalls.global.x64.asm' )
ASM          = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'Solution File', 'src', 'source' , 'wizardcalls.x64.asm' )
HEADER       = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'Solution File', 'src', 'include', 'wizardcalls.h' )
SOURCE       = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'Solution File', 'src', 'source' , 'wizardcalls.c' )
DJB2         = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'data', 'templates', 'Djb2.c' )

# --------------------- Import NT API Data ----------------------

with open( './Data/nt_api.json', 'r' ) as file:
    nt_api_data = json.loads( file.read() )

# --------------------------- Classes ---------------------------

class Syscall( object ):
    """ Represents an NT API call in the source code """

    def __init__( self, name: str, _global: bool ):
        if name not in nt_api_data.keys():
            raise Exception( f"{RED}{name}{END} is not a valid syscall in { os.path.join( os.getcwd(), NT_DATA ) }" )
        
        self.data           = nt_api_data[name]
        self.syscall_name   = name
        self.is_global      = _global
        self.wzd_macro      = self.create_macro()
        self.wrapper        = self.create_wrapper()
        self.prototype      = self.create_prototype()

    def build_parameter_string( self, is_macro_params = False, is_macro_func_params = False ) -> str:
        """ Builds a parameter string for a function or macro -> ( ProcessHandle, BaseAddress ) || ( HANDLE ProcessHandle, PVOID BaseAddress ) """
        match is_macro_params:
            case True:
                match is_macro_func_params:
                    case True:
                        string = "( " if self.is_global else "( PSYSCALL_LIST_NAME, "
                    case False:
                        string = "( "
            case False:
                string = "( " if self.is_global  else "( PSYSCALL_LIST pSyscallList, "

        for param, index in zip( self.data[ 'arguments' ], range( 0, len( self.data[ 'arguments' ] ) ) ):
            match is_macro_params:
                case True:
                    string += f"{ param['name'].replace('*', '') } )" if index == ( len( self.data[ 'arguments'] ) - 1 ) else f"{ param['name'].replace('*', '')  }, "
                case False:
                    string += f"{ param['type'] } { param ['name'] } )" if index == ( len( self.data['arguments'] ) - 1 ) else f"{ param['type'] } { param ['name'] }, " 

        return string


    def create_hash_macro( self ) -> str:
        return f"# define { self.syscall_name.upper() }\t{ self.hash_algo( self.seed, self.syscall_name ) }"


    def create_macro( self ) -> str:
        """
        Creates a macro definition for the syscall

        # define WzDAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection )\\
            NtAllocateVirtualMemory( PSYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection ) 
        """
        macro =  f"# define WzD{ self.syscall_name[2:] }" if self.syscall_name.startswith("Nt") else self.syscall_name
        macro += f"{ self.build_parameter_string( is_macro_params = True ) }\\\n"
        macro += f"\t{ self.syscall_name }{ self.build_parameter_string( is_macro_params = True, is_macro_func_params = True) }\\\n"
        return macro

    def create_prototype( self ) -> str:
        """
        Creates a function prototype

        NTSTATUS NtAllocateVirtualMemory ( PSYSCALL_LIST pSyscalls, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection );
        """
        prototype =  f"NTSTATUS { self.syscall_name } "
        prototype += f"{ self.build_parameter_string() };"
        return prototype

    def create_wrapper( self ) -> str:
        """
        Creates a function wrapper for the syscall

        NTSTATUS NtAllocateVirtualMemory( HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protection )
        {
            SetSyscallPointer( ( PSYSCALL ) & ( SYSCALL_LIST_NAME->NtAllocateVirtualMemory ) );
            return SystemCall( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection );
        }
        """
        wrapper =  f"{ self.create_prototype().replace( ';', '' ) }\n{{\n"
        wrapper += f"\tSetSyscallPointer( ( PSYSCALL ) & ( pSyscallList->{ self.syscall_name } ) );\n"
        wrapper += f"\treturn SystemCall{ self.build_parameter_string( is_macro_params=True ).replace( "PSYSCALL_LIST pSyscallList, ", "" ) };\n}}\n"
        return wrapper

class SourceCode( object ):
    """ Parent object for source code files """

    def __init__ ( self, source_file: str, filename: str ):
        self.filename       = filename
        self.path_on_disk   = ""
        self.language       = ""
        self.comment_regex  = []
        self.source_file    = source_file
        self.header_content = \
            f"Generated with wizardcalls v-{ SCRIPT_VERSION }\nTemplate version: { TEMPLATE_VERSION }\nCommandline: { ' '.join( sys.argv ) }" 
        
        with open( self.source_file, 'r' ) as file:
            self.content = file.read()
    
    def replace_content( self, new_content: str, pattern: str, count = 1 ) -> None:
        """ Replace the content of a file via regex matching """
        self.content    = re.sub( pattern = pattern, repl = new_content, string = self.content, count = count )

    def write_to_dir( self, directory: str ) -> None:
        """ Write the source file to a directory """
        if not os.path.isdir( directory ):
            raise Exception( f"{ directory } is not a valid directory on the file system" )
        self.path_on_disk = os.path.join( directory, self.filename )
        with open( self.path_on_disk, 'w' ) as file:
            file.write( self.content )
        self.path_on_disk = self.path_on_disk
            
    def remove_comments( self ) -> None:
        """ Remove comments from the source code. Under construction!"""
        for pattern in self.comment_regex:
            self.replace_content( new_content = '', pattern = pattern, count = 0 )
    
    def remove_blank_lines( self ) -> str:
        """ Remove all blank lines greater than 2 from source """
        self.replace_content( new_content = '\n', pattern = r'(?m)(?:^[ \t]*\r?\n){2,}', count = 0 )

    def insert_header( self, additional_content = "" ) -> str:
        """ Insert a comment block at the top of the file, describing the file """
        header = ""
        match self.language:
            case 'asm':
                for line in self.header_content.splitlines():
                    header += f"; { line }\n"
                    for line in additional_content.splitlines():
                        header += f"; { line }\n"
            case 'c':
                header = "/*\n"
                for line in self.header_content.splitlines():
                    header += f" * { line }\n"
                for line in additional_content.splitlines():
                    header += f" * { line }\n"
                header += "*/\n"

        header += self.content
        self.content = header

class WizardCallsAsm( SourceCode ):
    """ Represents the wizardcalls assembly file """

    def __init__( self, globals: bool ):
        super().__init__( 
            source_file = ASM_GLOBAL if globals else ASM 
            , filename  = 'wizardcalls.global.x64.asm' if globals else 'wizardcalls.x64.asm' 
        )
        self.comment_regex += [ r';.*' ]
        self.language       = "asm"

class WizardCallsFile( SourceCode ):
    """ Base object for the wizardcalls .c & .h files """
    
    def __init__( self, syscalls: list, globals: bool, source_file: str, filename: str ):
        super().__init__( source_file, filename = filename)
        
        self.language      = 'c'
        self.comment_regex += [ 
            r'//.*'                             # Single line starting with //
            , r'\/\*.*?\*\/'                    # Single line comments between /* */
            , r'(?s)/\*(?:(?!@brief).)*?\*/'    # Multi line comments between /* */ without @brief comment (Keep function info)
        ]
        
        # Initialize system call objects
        self.syscalls = {}
        for syscall in syscalls:
            self.syscalls[ syscall ] = Syscall( name = syscall, _global = globals )

        # Remove initial comment banner
        self.replace_content( new_content = '', pattern = r'(?s)\/\*\n\sWizardcalls v2.*?\*\/' )

class WizardCallsSource( WizardCallsFile ):
    """ Represents the source code (.c) file for wizard calls """

    def __init__( self, globals: bool, syscalls: bool, hash_seed: int, hash_algo: str, randomize_jump_address: bool, debug: bool ):
        super().__init__( syscalls = syscalls, globals = globals, source_file = SOURCE, filename = 'wizardcalls.c' )

        self.hash_seed  = hash_seed
        hash_algo       = hash_algo.lower()

        match hash_algo:
            case 'sdbm':
                self.hash_algo      = self.hash_sdbm
                self.hash_function  = 'HashStringSdbm'
            case 'djb2':
                self.hash_algo          = self.hash_djb2
                self.hash_function      = 'HashStringDjb2'
                self.hash_function_code = DJB2
            case _:
                raise Exception( f"{ hash_algo } is not a hashing algorithm currently implemented in wizard calls." )

        # Set jump address randomization
        if not randomize_jump_address:
            self.replace_content(
                new_content = '//# define RANDOMIZE_JUMP_ADDRESS'
                , pattern   = r'# define RANDOMIZE_JUMP_ADDRESS'
            )

        # Set debug statements
        if not debug:
            self.replace_content(
                new_content = '//# define DEBUG'
                , pattern   = r'# define DEBUG'
            )

        # Set hash seed
        self.replace_content( 
            new_content = f"# define HASH_SEED { hash_seed }"
            , pattern   = r'# define HASH_SEED\s*\d{4}'    
        )

        # Set ntdll hash
        self.replace_content(
            new_content = f"# define NTDLL { self.hash_algo( "ntdll.dll" ) } // ntdll.dll"
            , pattern   = r"# define NTDLL\s*0x.{8}"
        )

        # Set syscall hash macros & syscall hash list
        syscall_hash_macros     = ""
        syscall_hash_list_macro = "# define HASHES "
        for syscall in self.syscalls:
            syscall_hash_macros     += f"# define { syscall.upper() } { self.hash_algo( syscall ) }\n"
            syscall_hash_list_macro += f"{ syscall.upper() }, "
        syscall_hash_list_macro = syscall_hash_list_macro[ :len( syscall_hash_list_macro ) - 2 ] # Remove trailing ', '
        self.replace_content( 
            new_content = syscall_hash_macros
            , pattern   = r'(?s)# define NTALLOC.*# define NTPROTECT\w*\s*0x.{8}'
        )
        self.replace_content(
            new_content = syscall_hash_list_macro
            , pattern   = r'# define HASHES .*'
        )

        # Set the hashing function if it's not the default function
        if hash_algo != 'sdbm':
            self.replace_content(
                new_content = f"# define HashStringA( String ) { self.hash_function }A( String )\n# define HashStringW( String ) { self.hash_function }W( String )"
                , pattern   = r'# define HashStringA.*\n.*\( String \)'
            )
            with open( self.hash_function_code, 'r' ) as file:
                self.replace_content(
                    new_content = file.read()
                    , pattern   = r'(?s)\/\*\n\s@brief\n\s\sConvert.*HashStringSdbmA.*\sreturn Hash;\n}'
                )
        
        # Create or remove global pointer decleration
        self.replace_content(
            new_content = 'PSYSCALL_LIST SYSCALL_LIST_NAME;' if globals else ''
            , pattern   = r'# ifdef GLOBAL\n.*\n# endif'
        )
        if not globals:
            self.replace_content(
                new_content = ''
                , pattern   = r'\/\* -.*Globals -.*\*\/\n\n\n\n'
            )

        # Add syscall wrapper function bodies
        self.replace_content(
            new_content = '\n'.join( [ syscall.wrapper for syscall in self.syscalls.values() ] )
            , pattern   = r'(?s)# ifndef GLOBAL\nNTSTATUS NtAllocate.*?NTSTATUS NtFree.*?# endif.*ifdef GLOBAL\nNTSTATUS NtAllocate.*?NTSTATUS NtFree.*?# endif'
        )

    def hash_djb2( self, string: str ):
        """ Hash a string using DJB2 algorithm """
        hash = self.hash_seed
        for i in string:
            hash = ( ( hash << 5 ) + hash ) + ord( i )
        return hex( hash & 0xFFFFFFFF ).upper().replace( 'X', 'x' )


    def hash_sdbm( self, string: str ) -> str:
        """ Hash a string using the SDBM hash algorithm -> 0xDEADBEEF """
        Hash = self.hash_seed
        for x in list( string ):
            Hash = ord( x ) + ( Hash << 6 ) + ( Hash << 16 ) - Hash
        return "0x%X" % ( Hash & 0xFFFFFFFF )
        
class WizardCallsHeader( WizardCallsFile ):
    """ Represents the header file for wizardcalls """

    def __init__( self, syscall_list_name:str, globals: bool,  syscalls: list ):
        super().__init__( source_file=HEADER, syscalls = syscalls, globals = globals, filename = 'wizardcalls.h' )

        # Remove global macro reference
        self.replace_content(
            new_content = ""
            , pattern   = r'\n\/\* -* Control Macros -* \*\/\n\/\/ # define GLOBAL\n' 
        )

        # Set syscall list name macro
        self.replace_content( 
            new_content = f"# define SYSCALL_LIST_NAME { syscall_list_name }"
            , pattern   = r'# define SYSCALL_LIST_NAME	pSyscallList'
        )
        
        # Set WzD function macros
        macros = []
        macros += [ "# define WzDInit() PSYSCALL_LIST SYSCALL_LIST_NAME = InitializeSystemCalls()" ] if not globals else [ "# define WzDInit() SYSCALL_LIST_NAME = InitializeSystemCalls()" ]        
        macros += [ syscall.wzd_macro for syscall in self.syscalls.values() ]
    
        self.replace_content(
            new_content  = '\n'.join( macros )
            , pattern = r'(?s)#\s*ifdef\s+GLOBAL.*?# endif.*?# endif'
        )

        # Create & set syscall list structure
        syscall_list_structure = "typedef struct\n{\n"
        for syscall in self.syscalls:
            syscall_list_structure += f"\t SYSCALL { syscall };\n"
        syscall_list_structure += "}\nSYSCALL_LIST, *PSYSCALL_LIST;"
        self.replace_content( 
            new_content  = syscall_list_structure
            , pattern = r'(?s)typedef struct _SYSCALL_LIST_.*?PSYSCALL_LIST;'
        )

        # Set or remove external refernce depending on global variable specification
        self.replace_content(
            new_content = "extern PSYSCALL_LIST SYSCALL_LIST_NAME;" if globals else ""
            , pattern = r'(?s)# ifdef GLOBAL\nextern.*?\n# endif'
        )
        if not globals:
            self.replace_content( pattern = r'\/\*.*?Externals.*?\*\/\n\n\n\n', new_content = '' )
        
        # Add function prototypes
        self.replace_content(
            new_content = '\n'.join([ syscall.prototype for syscall in self.syscalls.values() ])
            , pattern = r'(?s)# ifdef GLOBAL\nNTSTATUS.*?# ifndef GLOBAL\nNTSTATUS.*?# endif'
        )

# -------------------------------- Entry --------------------------------

if __name__ == "__main__":

# --------------------------- Private Classes ---------------------------

    class AlignedHelpFormatter( argparse.HelpFormatter ):
        def __init__( self, prog ):
            super().__init__( prog, max_help_position=35 )

# -------------------------- Private Functions --------------------------

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

    def wc_print( msg: str ):
        """ Print general messages """
        print( GREEN + "[" + PURPLE + " > " + GREEN + "] " + WHITE + msg + END )

    def wc_error( msg: str ):
        """ Print error messages """
        print( f"{ WHITE }[{ RED } ! { WHITE }] { YELLOW }{ msg }{ END }")

    def print_dict_table( dictionary ):
        """ Internal function to print banner and configuration"""

        # Get widths of key & value fields
        key_width = max( len( str( key ) ) for key in dictionary ) + 1
        val_width = max( len( str( val ) ) for val in dictionary.values() ) + 2

        # Print the banner
        print( f"{ GREEN }╔{ '═' * ( key_width + val_width + 4) }╗" )
        print( f"║{ PURPLE }{ 'WIZARDCALLS 🧙'.center( key_width + val_width + 2, ' ' ) }{ GREEN } ║")
        print( f"║{ RED }{ 'Evading teh h00ks'.center( key_width + val_width + 4, ' ' ) }{ GREEN }║")
        print( f"║{ RED }{ 'jmp 0x0F05'.center( key_width + val_width + 4, ' ' ) }{ GREEN }║")
        print( f"║{ ' ' * ( key_width + val_width + 4 ) }║")
        print( f"║{ f"By:{ WHITE } wizardy0ga".center( key_width + val_width + 11 ) }{ GREEN }║")
        print( f"║{ f"Builder Version:  { CYAN }{ SCRIPT_VERSION }".center( key_width + val_width + 11 ) }{ GREEN }║")
        print( f"║{ f"Template Version: { CYAN }{ TEMPLATE_VERSION }".center( key_width + val_width + 11 ) }{ GREEN }║")

        # Create sections of the config
        top         = f"{ GREEN }╠{ '═' * ( key_width + 1 ) }╦{ '═' * ( val_width + 2) }╣"
        header      = f"║{ WHITE } { 'Option'.ljust( key_width ) }{ GREEN }║ { WHITE }{ 'Setting'.ljust( val_width ) }{ GREEN } ║"
        separator   = f"╠{ '═' * ( key_width + 1 ) }╬{ '═' * ( val_width + 2 ) }╣"
        bottom      = f"╚{ '═' * ( key_width + 1 ) }╩{ '═' * ( val_width + 2)  }╝"

        # Print top half of config
        for obj in [ top, header, separator ]:
            print( obj )

        # Print items in config
        for key, val in dictionary.items():
            print(f"║ { PURPLE }{ str( key ).ljust( key_width ) }{ GREEN }║ { CYAN }{ str( val ).ljust( val_width ) }{ GREEN } ║")

        # Print the bottom of the config
        print(bottom)

# -------------------------- Main --------------------------

    parser = argparse.ArgumentParser( formatter_class=AlignedHelpFormatter )

    parser.add_argument( 
        '-o'
        , '--outdir'
        , default   = os.getcwd()
        , type      = dir_exists
        , help      = 'A directory to write the source files to. Defaults to "Out" directory.'
    )

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
        , choices   = [ 'sdbm', 'djb2' ]
        , default   = 'sdbm'
        , help      = 'An algorithm to hash the syscalls with. Defaults to sdbm.'
    )
    
    build_opt_group.add_argument(
        '--debug'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enables debug mode in the header file.' 
    )
    
    build_opt_group.add_argument( 
        '--random_syscall_addr'
        , action    = 'store_true'
        , default   = False
        , help      = 'Use random syscall instructions when performing indirect jump. Obfuscates the callstack a bit.'
    )

    build_opt_group.add_argument(
        '--globals'
        , action    = 'store_true'
        , default   = False
        , help      = 'Enable the use of global variables. Code will no longer be position independent.'
    )

    build_opt_group.add_argument(
        '--remove_comments'
        , action    = 'store_true'
        , default   = False
        , help      = 'Remove comments from the source code.'
    )
    
    build_opt_group.add_argument(
        '--syscall_list_name'
        , type      = str
        , default   = 'pSyscallList'
        , help      = 'Set the name of the PSYSCALL_LIST variable, to be used throughout the code.'
    )

    input_arg_group = parser.add_mutually_exclusive_group()

    input_arg_group.add_argument(
        '--apicalls'
        , type      = str
        , nargs     = "+"
        , help      = 'List of win32 native api calls to generate the template for.'
    )
    
    input_arg_group.add_argument(
        '--file'
        , type    = file_exists
        , default = False
        , help    = 'Path to file containing a list of api calls. Use a new line [\\n] to seperate each api call.' 
    )
    args = parser.parse_args()
    
    ouptut_directory = os.path.join( os.getcwd(), args.outdir )

    # Import API calls from user
    #
    syscalls             = [ "NtAllocateVirtualMemory" ]
    user_syscall_import  = None
    match args.file:
        case type(str):
            with open( args.file, 'r' ) as file:
                user_syscall_import = file.read().split( '\n' )
        case False:
            user_syscall_import = args.apicalls   
    
    # Validate syscall imports
    #
    for syscall in user_syscall_import:
        if syscall not in nt_api_data:
            wc_error( f"{ RED }{ syscall }{ YELLOW } is not a valid syscall in { NT_DATA }. Adjust the dataset if this is a mistake.{ END }" )
            exit( 1 )    
        if syscall not in syscalls:
            syscalls += [ syscall ]

    # Print banner & config
    # 
    args_dict = vars( args )
    for arg in [ 'apicalls', 'file' ]:
        del args_dict[ arg ]
    print_dict_table(args_dict)

    # Print syscall import information
    #
    wc_print( f"Imported { len( syscalls ) } system calls" )
    for syscall in syscalls:
        print( f"\t{ GREEN }+{ WHITE } { syscall } ( { GREEN }Default{ WHITE } )" if syscall == "NtAllocateVirtualMemory" else f"\t{ GREEN }+{ WHITE } { syscall }" )

    # Creaate and write source files
    #
    asm_file    = WizardCallsAsm( globals = args.globals )
    header_file = WizardCallsHeader( globals = args.globals, syscalls = syscalls, syscall_list_name = args.syscall_list_name ) 
    source_file = WizardCallsSource( globals = args.globals, syscalls = syscalls, randomize_jump_address = args.random_syscall_addr, debug = args.debug, hash_algo = args.algo, hash_seed = args.seed )
    
    # Remove comments if specified
    #
    if args.remove_comments:
        [ file.remove_comments() for file in [ asm_file, header_file, source_file ] ]
    
    # Cleanup new lines
    #
    [ file.remove_blank_lines() for file in [ asm_file, header_file, source_file ] ]

    # Insert file header
    asm_file.insert_header()
    [ file.insert_header( additional_content = 'Using syscalls:\n\t[+] - ' + '\n\t[+] - '.join( file.syscalls ) ) for file in [ header_file, source_file ] ]

    source_file.write_to_dir( ouptut_directory )
    header_file.write_to_dir( ouptut_directory )
    asm_file.write_to_dir( ouptut_directory )
    
    # Print new file paths
    #
    for name, file in {
        'assembly': asm_file,
        'source': source_file,
        'header': header_file
    }.items():
        wc_print( f"Wrote {CYAN}{ name }{WHITE} file to { GREEN }{ file.path_on_disk.replace('\\..', '') }{ END }" )
    