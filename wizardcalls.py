import argparse
import random
import os
import json
import shutil

BANNER = """
┓ ┏•      ┓┏┓  ┓┓ 
┃┃┃┓┓┏┓┏┓┏┫┃ ┏┓┃┃┏
┗┻┛┗┗┗┻┛ ┗┻┗┛┗┻┗┗┛ 
a syscall code generation tool using the Hells Hall approach.

Author
    Wizardy0ga

Hells Hall Creators
    @mrd0x
    @NUL0x4C

Versions
    Builder: 1.0.0
    C Source: 1.0.0

Compiler
    MSVC

Architecture
    x64
"""

REPLACEMENT_MARKER  = "<Insert>"
SYSCALL_OPCODE = 0x050F

with open("Templates/HellsHall.h", 'r') as file:
    HellsHallHeaderFile = file.read()

with open('./Data/nt_api.json', 'r') as file:
    nt_api_data = json.loads(file.read())


class HashMacro(object):
    """
        Represents a hashed string C macro
    """
    def __init__(self, Name, HashSeed, Algo):
        self.string = Name
        self.c_macro_name = "hash_%s_%s" % (self.string.upper().replace(".", ""), Algo)
        self.hash = self.hash_string(Name, HashSeed, Algo)

    def hash_string(self, string, hash_seed, algo) -> int:
        match algo:
            case 'sdbm':
                return hash_sdbm(string, hash_seed)
            case 'djb2':
                print("Djb2 algorithm is not implemented yet. Quitting.\n")
                exit()

    def get_definition(self) -> str:
        return "#define %s 0x%X" % (self.c_macro_name, self.hash)


class NtApiCall(HashMacro):
    """
        Subclass of the hash macro for validating api calls
    """
    def __init__(self, Name, HashSeed, Algo):
        super().__init__(Name, HashSeed, Algo)
        if Name not in nt_api_data.keys():
            raise Exception("%s is not a valid syscall from the native windows api." % Name)
        print("Initialized system call: %s" % Name)
        self.data = nt_api_data[Name]

    def get_prototype(self):
        prototype = "NTSTATUS %s(" % self.string
        count = 1
        for parameter in self.data['arguments']:
            format_string = "%s %s, " if count != len(self.data['arguments']) else "%s %s"
            prototype += (format_string % (parameter['type'], parameter['name']))
            count += 1
        prototype += ");\n"
        return prototype

    def get_code(self):
        code = self.get_prototype().replace(";", " {")
        code += "\tSET_SYSCALL_POINTER(g_SystemCalls.%s);\n" % self.string
        code += "\treturn SystemCall("
        count = 1
        for parameter in self.data['arguments']:
            format_string = "%s, " if count != len(self.data['arguments']) else "%s "
            code += (format_string % parameter['name'].replace("*", ""))
            count += 1
        code += ");\n};\n\n"
        return code


class NtApiCallTable(object):

    """
        Represents the table of syscalls & how they need to be defined in the header file
    """

    def __init__(self, NtApiCallTableList):
        self.syscall_list = NtApiCallTableList
        self.sorted_function_names = self.get_syscall_names()

    def get_syscall_object(self, function_name) -> HashMacro or None:
        for api_call in self.syscall_list:
            if api_call.string == function_name:
                return api_call
        return None

    def get_syscall_names(self) -> list:
        return [nt_api_call.string for nt_api_call in self.syscall_list]
        
    def get_hash_definitions(self) -> str:
        definitions = ""
        for api_call in self.syscall_list:
            definitions += "%s\n" % api_call.get_definition()
        return definitions

    def get_hashlist_definition(self) -> str:
        definition = "#define NT_API_FUNCTION_HASH_LIST "
        Count = 0
        for function_name in self.sorted_function_names:
            api_call = self.get_syscall_object(function_name)
            definition += ("%s," % api_call.c_macro_name) if Count != (len(self.sorted_function_names) -1) else ("%s" % api_call.c_macro_name)
            Count += 1
        return definition

    def get_structure_definition(self) -> str:
        structure = "typedef struct _SYSTEM_CALLS_TABLE{\n"
        for api_call in self.sorted_function_names:
            structure += ("\tSYSTEM_CALL %s;\n" % api_call) 
        structure += "} SYSTEM_CALLS_TABLE, *PSYSTEM_CALLS_TABLE;"
        return structure

    def get_function_prototypes(self) -> str:
        prototypes = ""
        for api_call in table.syscall_list:
            prototypes += api_call.get_prototype()
        return prototypes

    def get_code_component(self) -> str:
        return "%s\n%s\n\n%s\n\n%s\n\n" % (
            self.get_hash_definitions(), 
            self.get_hashlist_definition(), 
            self.get_structure_definition(),
            self.get_function_prototypes()
        )

def file_exists(path):
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"The file {path} does not exist or is not a valid file.")
    return path

def hash_sdbm(string: str, seed: int) -> int:
    Hash = seed
    for x in list(string):
        Hash = ord(x) + (Hash << 6) + (Hash << 16) - Hash
    return Hash & 0xFFFFFFFF

if __name__ == "__main__":

    Parser = argparse.ArgumentParser()
    MutexGroup = Parser.add_mutually_exclusive_group()

    Parser.add_argument('--seed', type=int, default=random.randrange(1, 10000), help='Seed for the hashing algorithm. Generates a random seed if none is provided.')
    Parser.add_argument('--algo', choices=['sdbm', 'djb2'], default='sdbm', help='A hashing algorithm to use. Defaults to sdbm.')
    Parser.add_argument('--outdir', default='Out', type=str, help='A directory to write the source files to. Defaults to "Out" directory.')
    MutexGroup.add_argument('--apicalls', type=str, nargs="+", help='List of win32 native api calls to generate the template for. See https://www.geoffchappell.com/studies/windows/win32/ntdll/api/native.htm for more information on the win32 native api.')
    MutexGroup.add_argument('--file', type=str, help='Path to file containing a list of api calls. Use a new line [\\n] to seperate each api call.')
    MutexGroup.add_argument('--source_file', type=str, help='A C source file using the NT API. Under development. Not available at the moment.')
    Parser.add_argument('--seperate_structures', action='store_true', default=False, help='Create the NT / Win32 structure file seperately from the hells hall header file')
    Args = Parser.parse_args()

    print(BANNER)

    NewHeaderFileContent = "#define HASH_SEED %i\n" % Args.seed

    # Collect nt api calls
    ApiCalls = []
    if Args.apicalls:
            ApiCalls += [NtApiCall(api_call, Args.seed, Args.algo) for api_call in Args.apicalls]
    elif Args.file:
        with open(Args.file, 'r') as file:
            ApiCalls += [NtApiCall(api_call, Args.seed, Args.algo) for api_call in file.read().split('\n')]
    elif Args.source_file:
        print("Source file parsing has not been implemented. Quitting.\n")
        exit(1)

    # add static hash definitions
    for string in ["ntdll.dll", "kernel32.dll", "LoadLibraryA"]:
        HashedString = HashMacro(string, Args.seed, Args.algo)
        NewHeaderFileContent += "%s\n" % (HashedString.get_definition())
        NewHeaderFileContent += "#define %s %s\n" % (HashedString.string.replace(".dll", "").upper(), HashedString.c_macro_name)

    # Add syscall table to source code
    table = NtApiCallTable(ApiCalls)
    NewHeaderFileContent += table.get_code_component()

    # Add xor'd syscall instruction & key to header file
    syscall_opcode_xor_key = random.randrange(1, 65535)
    NewHeaderFileContent += "\n#define OBFUSCATED_SYSCALL 0x%X\n#define SYSCALL_XOR_KEY 0x%X\n" % ((SYSCALL_OPCODE ^ syscall_opcode_xor_key), syscall_opcode_xor_key)

    HellsHallHeaderFile = HellsHallHeaderFile.replace(REPLACEMENT_MARKER, NewHeaderFileContent)

    # Clear & create default out directory in project root if outdir arg is default
    if Args.outdir == "Out":
        if os.path.exists(Args.outdir):
            shutil.rmtree(Args.outdir)
        os.mkdir(Args.outdir)

    outpath_hells_hall_header = os.path.join(Args.outdir, 'HellsHall.h')
    outpath_hells_hall_source = os.path.join(Args.outdir, 'HellsHall.c')
    outpath_x64_asm           = os.path.join(Args.outdir, 'HellsHall.x64.asm')
    outpath_structs_header    = os.path.join(Args.outdir, 'Structs.h')

    # write stucture headers
    with open("Source/Include/Structs.h", "r") as file:
        if not Args.seperate_structures:
            HellsHallHeaderFile += ("\n" + file.read().replace('#include <Windows.h>', ""))
            HellsHallHeaderFile = HellsHallHeaderFile.replace('#include "Structs.h"', "") 
        else:
            with open(outpath_structs_header, "w") as struct_file:
                struct_file.write(file.read())
    
    # copy source files
    shutil.copy("Source/Source/HellsHall.c", outpath_hells_hall_source)
    shutil.copy("Source/Source/HellsHall.x64.asm", outpath_x64_asm)

    # write header file
    with open(os.path.join(Args.outdir, 'HellsHall.h'), 'w') as file:
        file.write(HellsHallHeaderFile)

    # Write the code for each syscall wrapper function
    with open(os.path.join(Args.outdir, 'HellsHall.c'), 'a') as file:
        for api_call in table.syscall_list:
            file.write(api_call.get_code())

    print(f"\nWrote source files to {Args.outdir}\n")