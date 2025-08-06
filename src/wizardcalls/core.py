import os
import re
import sys
import json
from wizardcalls.colors import *


# -------------------------- Constants --------------------------
SCRIPT_VERSION      = "2.1.0"
TEMPLATE_VERSION    = "2.0.0"


NT_DATA      = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'data', 'nt_api.json' )
ASM_GLOBAL   = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'source' , 'wizardcalls.global.x64.asm' )
ASM          = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'source' , 'wizardcalls.x64.asm' )
HEADER       = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'include', 'wizardcalls.h' )
SOURCE       = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'solution file', 'src', 'source' , 'wizardcalls.c' )
DJB2         = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'templates', 'Djb2.c' )
JENKINS      = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'templates', 'Jenkins.c' )
MURMUR       = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'code', 'templates', 'Murmur.c' ) 
TYPE_LOOKUP  = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'rsrc', 'data', 'type-conversion.json' )

# --------------------- Import Data ----------------------
with open( NT_DATA, 'r' ) as file:
    nt_api_data = json.loads( file.read() )
with open( TYPE_LOOKUP, 'r' ) as file:
    type_lookup = json.loads( file.read() )

# --------------------------- Classes ---------------------------
class Syscall( object ):
    """ Represents an NT API call in the source code """

    def __init__( self, name: str, _global: bool ):
        if name not in nt_api_data.keys():
            raise Exception( f"{ RED }{ name }{ END } is not a valid syscall in { os.path.join( os.getcwd(), NT_DATA ) }" )
        
        self.data           = nt_api_data[ name ]
        # Cleanup function parameters to prevent invalid data types from appearing in source code (breaks compilation)
        for param in self.data['arguments']:
            if param['type'] in type_lookup.keys():
                param['type'] = type_lookup[param['type']]
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
                        string = "( " if self.is_global else "( SYSCALL_LIST_NAME, "
                    case False:
                        string = "( "
            case False:
                string = "( " if self.is_global  else "( PSYSCALL_LIST SYSCALL_LIST_NAME, "

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
            NtAllocateVirtualMemory( SYSCALL_LIST_NAME, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protection ) 
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
        wrapper += f"\tSetSyscallPointer( ( PSYSCALL ) & ( SYSCALL_LIST_NAME->{ self.syscall_name } ) );\n"
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
        match self.language:
            case 'asm':
                header = ";\n"
                for line in self.header_content.splitlines():
                    header += f"; { line }\n"
                for line in additional_content.splitlines():
                    header += f"; { line }\n"
                header += ";\n"
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

        # Remove initial banner comment
        self.replace_content( new_content = '', pattern = r';.*\n;\w.*\n.*\n.*\n.*' )

class WizardCallsFile( SourceCode ):
    """ Base object for the wizardcalls .c & .h files """
    def __init__( self, globals: bool, syscalls: list, source_file: str, filename: str ):
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
    def __init__( self, globals: bool, syscalls: list, hash_seed: int, hash_algo: str, randomize_jump_address: bool, debug: bool ):
        super().__init__( syscalls = syscalls, globals = globals, source_file = SOURCE, filename = 'wizardcalls.c' )

        self.hash_seed  = hash_seed
        hash_algo       = hash_algo.lower()

        match hash_algo:
            case 'sdbm':
                self.hash_algo          = self.hash_sdbm
                self.hash_function      = 'HashStringSdbm'
            case 'djb2':
                self.hash_algo          = self.hash_djb2
                self.hash_function      = 'HashStringDjb2'
                self.hash_function_code = DJB2
            case 'jenkins':
                self.hash_algo          = self.hash_jenkins
                self.hash_function      = 'HashStringJenkinsOneAtATime'
                self.hash_function_code = JENKINS
            case 'murmur':
                self.hash_algo          = self.hash_murmur
                self.hash_function      = 'HashStringMurmur'
                self.hash_function_code = MURMUR
            case _:
                raise Exception( f"{ hash_algo } is not a hashing algorithm currently implemented in wizard calls." )

        # Change wizardcalls include statement
        self.replace_content(
            new_content = '# include "wizardcalls.h"'
            , pattern   = r'# include "../include/wizardcalls.h"'
        )

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
    
    def hash_jenkins( self, string: str) -> str:
        """ Hash a string with the Jenkins One At A Time algo """
        Hash = self.hash_seed
        for c in string: 
            Hash += ord(c)
            Hash = (Hash + (Hash << 10)) & 0xFFFFFFFF
            Hash ^= (Hash >> 6)
        Hash = (Hash + (Hash << 3)) & 0xFFFFFFFF
        Hash ^= (Hash >> 11)
        Hash = (Hash + (Hash << 15)) & 0xFFFFFFFF
        return "0x%X" % ( Hash & 0xFFFFFFFF )
    
    def hash_murmur( self, string: str ) -> str:
        """ Hash a string with MurmurHash3 algo """
        string = string.encode()
        length = len(string)
        Hash = self.hash_seed
        if length > 3:
            idx = length >> 2
            for i in range(idx):
                start = i * 4
                cnt = int.from_bytes(string[start:start+4], byteorder='little')
                cnt = (cnt * 0xcc9e2d51) & 0xffffffff
                cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
                cnt = (cnt * 0x1b873593) & 0xffffffff
                Hash ^= cnt
                Hash = ((Hash << 13) | (Hash >> 19)) & 0xffffffff
                Hash = ((Hash * 5) + 0xe6546b64) & 0xffffffff
        remaining = length & 3
        if remaining:
            cnt = 0
            start_pos = (length >> 2) * 4 + remaining - 1
            for i in range(remaining):
                cnt = (cnt << 8) & 0xffffffff
                cnt |= string[start_pos - i]
            cnt = (cnt * 0xcc9e2d51) & 0xffffffff
            cnt = ((cnt << 15) | (cnt >> 17)) & 0xffffffff
            cnt = (cnt * 0x1b873593) & 0xffffffff
            Hash ^= cnt
        Hash ^= length
        Hash ^= Hash >> 16
        Hash = (Hash * 0x85ebca6b) & 0xffffffff
        Hash ^= Hash >> 13
        Hash = (Hash * 0xc2b2ae35) & 0xffffffff
        Hash ^= Hash >> 16
        return "0x%X" % Hash
    

class WizardCallsHeader( WizardCallsFile ):
    """ Represents the header file for wizardcalls """
    def __init__( self, globals: bool,  syscalls: list, syscall_list_name:str ):
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

class WizardCalls( object ):
    """ Container object for all 3 related source file objects """
    def __init__( self, globals: bool, syscalls: list, syscall_list_name:str, hash_seed: int, hash_algo:str, randomize_jump_address:bool, debug: bool ):
        self.header     = WizardCallsHeader( globals, syscalls, syscall_list_name )
        self.source     = WizardCallsSource( globals, syscalls, hash_seed, hash_algo, randomize_jump_address, debug )
        self.asm_source = WizardCallsAsm( globals )