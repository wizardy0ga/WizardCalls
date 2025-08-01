import uuid
from wizardcalls.core import *
from wizardcalls.args import parse_user_args


# -------------------------- Private Functions --------------------------
def wc_print( msg: str ) -> None:
    """ Print general messages """
    print( GREEN + "[" + PURPLE + " > " + GREEN + "] " + WHITE + msg + END )


def wc_error( msg: str ) -> None:
    """ Print error messages """
    print( f"{ WHITE }[{ RED } ! { WHITE }] { YELLOW }{ msg }{ END }")


def _format_args( action, default_metavar: str ) -> str:
    """ 
    Format an arguments syntax. Taken from argparse.HelpFormatter class. This is a combination of the 
    the _format_args & _metavar_formatter() methods fo the HelpFormatter class.
    """
    # Set the metavar for the argument
    if action.metavar is not None:
        metavar = action.metavar
    elif action.choices is not None:
        metavar = '{%s}' % ','.join( map( str, action.choices ) )
    else:
        metavar = default_metavar
    
    # Format argument string based on number of arguments
    match action.nargs:
        case None:
            result = '%s' % metavar
        case '?':               # OPTIONAL:
            result = '[%s]' % metavar
        case '*':               # ZERO_OR_MORE:
            metavar = metavar
            if len(metavar) == 2:
                result = '[%s [%s ...]]' % metavar
            else:
                result = '[%s ...]' % metavar
        case '+':               # ONE_OR_MORE:
            result = '%s [%s ...]' % (metavar, metavar)
        case '...':             # REMAINDER:
            result = '...'
        case 'A...':            # PARSER:
            result = '%s ...' % metavar
        case '==SUPPRESS==':    # SUPPRESS:
            result = ''
        case _:
            result = ''
    return result


def print_help( parser ) -> str:
    """ Prints a table using the arguments stored in an argparse.ArgumentParser object as a table"""
    max_key_width   = 0
    max_val_width   = 0
    args            = {}
    # Collect argument group, variable name & help inforamation. Get the max lengths
    # of each argument & description string for formatting the table.
    # Examples -> Arg = -k, --key KEY | Desc = 'Your API key'
    # Structure -> { 'Argument Group': [{'Arg': '-k, --key KEY', 'Desc': 'Your API key'}] }
    for argument_group in parser._action_groups:
        if argument_group._group_actions:
            if argument_group.title == 'options':
                setattr( argument_group, 'title', 'Module Options' )
            args[ argument_group.title ] = []
            for argument, index in zip( argument_group._group_actions, range( 0, len( argument_group._group_actions ) ) ):
                args[ argument_group.title ] += [ { 'arg': f'{ ', '.join( argument.option_strings ) } { _format_args(argument, argument.dest.upper()) }', 'desc': argument.help } ]
                key_width = len( args[ argument_group.title ][ index ][ 'arg' ] ) + 4
                val_width = len( args[ argument_group.title ][ index ][ 'desc' ] ) + 4
                max_key_width = key_width if key_width > max_key_width else max_key_width
                max_val_width = val_width if val_width > max_val_width else max_val_width

    print_banner( ( max_key_width + max_val_width - 4 ) )

    # Begin building the table string
    max_width = max_key_width + max_val_width
    table = f"╠{ '═' * max_width }╣\n"
    for argument_group, arguments in args.items():
        table += f'║{ YELLOW }{ argument_group.center(max_width, ' ') }{ GREEN }║\n'
        table += f'╠{ '═' * max_key_width }╦{ '═' * ( max_val_width - 1 ) }╣\n'
        for argument in arguments:
            table += f'║ { WHITE }{ argument['arg'].ljust( max_key_width - 1 ) }{ GREEN }║ { CYAN }{ argument['desc'].ljust( max_val_width - 2 ) }{ GREEN }║\n'
            if argument_group == list( args.keys() )[-1] and argument == arguments[-1]:
                table += f'╚{ '═' * max_key_width }╩{ '═' * ( max_val_width - 1 ) }╝'
            elif argument == arguments[-1]:
                table += f'╠{ '═' * max_key_width }╩{ '═' * ( max_val_width - 1 ) }╣\n'
            else:
                table += f'╠{ '═' * max_key_width }╬{ '═' * ( max_val_width - 1 ) }╣\n'    
    print( table + END )


def print_banner( spacing: int ) -> None:
    """ Print the wizardcalls banner """
    print( f"{ GREEN }╔{ '═' * ( spacing + 4) }╗" )
    print( f"║{ PURPLE }{ 'WIZARDCALLS 🧙'.center( spacing + 2, ' ' ) }{ GREEN } ║")
    print( f"║{ RED }{ 'Evading teh h00ks'.center( spacing + 4, ' ' ) }{ GREEN }║")
    print( f"║{ RED }{ 'jmp 0x0F05'.center( spacing + 4, ' ' ) }{ GREEN }║")
    print( f"║{ ' ' * ( spacing + 4 ) }║")
    print( f"║{ f"By:{ WHITE } wizardy0ga".center( spacing + 11 ) }{ GREEN }║")
    print( f"║{ f" Module Version:  { CYAN }{ SCRIPT_VERSION }".center( spacing + 11 ) }{ GREEN }║")
    print( f"║{ f"Template Version: { CYAN }{ TEMPLATE_VERSION }".center( spacing + 11 ) }{ GREEN }║")


def print_dict_table( dictionary: dict ) -> None:
    """ Internal function to print banner and configuration """
    # Get widths of key & value fields
    key_width = max( len( str( key ) ) for key in dictionary ) + 1
    val_width = max( len( str( val ) ) for val in dictionary.values() ) + 2

    # Create sections of the config
    top         = f"{ GREEN }╠{ '═' * ( key_width + 1 ) }╦{ '═' * ( val_width + 2) }╣"
    header      = f"║{ WHITE } { 'Option'.ljust( key_width ) }{ GREEN }║ { WHITE }{ 'Setting'.ljust( val_width ) }{ GREEN } ║"
    separator   = f"╠{ '═' * ( key_width + 1 ) }╬{ '═' * ( val_width + 2 ) }╣"
    bottom      = f"╚{ '═' * ( key_width + 1 ) }╩{ '═' * ( val_width + 2)  }╝"

    print_banner( (key_width + val_width) )

    # Print top half of config
    for obj in [ top, header, separator ]:
        print( obj )

    # Print items in config
    for key, val in dictionary.items():
        print(f"║ { PURPLE }{ str( key ).ljust( key_width ) }{ GREEN }║ { CYAN }{ str( val ).ljust( val_width ) }{ GREEN } ║")

    # Print the bottom of the config
    print(bottom)

def main():
    parser = parse_user_args()
    args   = parser.parse_args()

    if args.help:
        print_help( parser )
        exit()

    if args.version:
        print_banner( spacing = 50 )
        print(f"╚{ '═' * 54 }╝{ END }")
        exit()

    try:
        output_directory = os.path.join( os.getcwd(), args.outdir )

        # Import API calls from user
        syscalls             = [ "NtAllocateVirtualMemory" ]
        user_syscall_import  = None
        if not args.file and not args.syscalls:
            wc_print('No syscalls were given to the script. Specify a list of functions with --file or --syscalls. Use -h for further information')
            exit()
        if args.syscalls:
            user_syscall_import = args.syscalls
        else:
            with open( args.file, 'r' ) as file:
                user_syscall_import = file.read().split( '\n' ) 
        
        # Validate syscall imports
        for syscall in user_syscall_import:
            if syscall not in nt_api_data:
                wc_error( f"{ RED }{ syscall }{ YELLOW } is not a valid syscall in { NT_DATA }. Adjust the dataset if this is a mistake.{ END }" )
                exit( 1 )    
            if syscall not in syscalls:
                syscalls += [ syscall ]

        # Print banner & config
        if not args.quiet:
            args_dict = vars( args )
            for arg in [ 'syscalls', 'file' ]:
                del args_dict[ arg ]
            print_dict_table(args_dict)

        # Print syscall import information
        wc_print( f"Imported { len( syscalls ) } system calls" )
        for syscall in syscalls:
            print( f"\t{ GREEN }+{ WHITE } { syscall } ( { GREEN }Default{ WHITE } )" if syscall == "NtAllocateVirtualMemory" else f"\t{ GREEN }+{ WHITE } { syscall }" )

        # Create source code object 
        wizard_calls = WizardCalls( 
            globals                     = args.globals
            , syscalls                  = syscalls
            , syscall_list_name         = args.syscall_list_name
            , randomize_jump_address    = args.random_syscall_addr
            , debug                     = args.debug
            , hash_algo                 = args.algo
            , hash_seed                 = args.seed 
        )

        # Remove comments if specified
        if args.remove_comments:
            [ file.remove_comments() for file in [ wizard_calls.asm_source, wizard_calls.source, wizard_calls.header ] ]
        
        # Cleanup new lines
        [ file.remove_blank_lines() for file in [ wizard_calls.asm_source, wizard_calls.source, wizard_calls.header ] ]

        # Insert file headers
        build_id = str(uuid.uuid4())
        wizard_calls.asm_source.insert_header( additional_content = f'ID: { build_id }\n' )
        for file in [ wizard_calls.source, wizard_calls.header ]:
            file.insert_header( additional_content = f'ID: { build_id }\n' + 'Using syscalls:\n\t[+] - ' + '\n\t[+] - '.join( file.syscalls ) )

        # Write to disk
        wizard_calls.source.write_to_dir( output_directory )
        wizard_calls.header.write_to_dir( output_directory )
        wizard_calls.asm_source.write_to_dir( output_directory )
        
        # Print new file paths
        for name, file in {
            'assembly': wizard_calls.asm_source,
            'source': wizard_calls.source,
            'header': wizard_calls.header
        }.items():
            wc_print( f"Wrote {CYAN}{ name }{WHITE} file to { GREEN }{ file.path_on_disk.replace('\\..', '') }{ END }" )
    
    except Exception as e:
        wc_error( f"Wizardcalls failed with unexpected exception: { e }" )

    except KeyboardInterrupt:
        wc_print( f"Detected user exit request. Quitting..." )