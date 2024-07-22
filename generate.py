import argparse
import sys
import logging
    
def parse_input_file(filename):
    """
    Parses the input file of key value pairs
    
    Args:
        filename (str): the input file
        
    Returns:
        dict: contains the source as the key and list of targets as value
    """
    
    with open(filename, 'r') as f:
        for line_number, line in enumerate(f, start=1):
            newLine = line.strip()
            newLine = newLine.replace('\t', ' ')
            
            colon_index = newLine.find(':')
            space_index = newLine.find(' ')
            
            if colon_index == -1:
                entry = newLine.split(' ')
            elif space_index == -1 or colon_index < space_index:
                entry = newLine.split(':')
            else:
                # colon_index >= space_index:
                entry = newLine.split(' ')

            username = entry[0].strip()
            
            if username in entry_to_filename:
                entry_to_filename[username].append(f"{filename}-{line_number}")
                logger.warning(f"Entry {username} was found in {entry_to_filename[username]}")
            else:
                entry_to_filename[username] = [(f"{filename}-{line_number}")]
                
            entries[username] = []
            for email in entry[len(entry) - 1].split(','):
                entries[username].append(email.strip())
    

def write_to_file(filename):
    """
    Writes the entries into an LDIF file
    
    Args:
        filename (str): the output file
        
    Returns:
        None
    """
    with open(filename, 'w') as f:
        for username in entries:
            f.write(f"dn: {username}\n")
            f.write(f"uid: {username}\n")

            if '@' not in username: 
                f.write(f"mail: {username}@ncsa.illinois.edu\n")    
            else:
                f.write(f"mail: {username}\n")
            
            if len(entries[username]) == 1:
                f.write(f"profileType: 0\n")
                target_key = 'mailRoutingAddress'
            else:
                f.write(f"profileType: 1\n")
                target_key = 'listMember'
                
            for email in entries[username]:
                if email == 'devnull' or email == '/dev/null':
                    f.write(f"{target_key}: no-reply@illinois.edu\n") 
                elif email == 'postmaster':
                    f.write(f"{target_key}: postmaster@illinois.edu\n")        
                elif '@' not in email:
                    f.write(f"{target_key}: {email}@ncsa.illinois.edu\n")
                else:
                    f.write(f"{target_key}: {email}\n")
            f.write("\n")
def dump():
    """
    Dumps the entries to the console. One line per entry. 
    """
    for username in entries:
        print(f"dn: {username}", end=',')
        print(f"uid: {username}", end=',')

        if '@' not in username: 
            print(f"mail: {username}@ncsa.illinois.edu", end=',')    
        else:
            print(f"mail: {username}", end=',')
        
        if len(entries[username]) == 1:
            print(f"profileType: 0", end=',')
            target_key = 'mailRoutingAddress'
        else:
            print(f"profileType: 1", end=',')
            target_key = 'listMember'
            
        target_string = ''
        
        for email in entries[username]:
            if email == 'devnull' or email == '/dev/null':
                target_string += f"{target_key}: no-reply@illinois.edu,"
            elif email == 'postmaster':
                target_string += f"{target_key}: postmaster@illinois.edu,"
            elif '@' not in email:
                target_string += f"{target_key}: {email}@ncsa.illinois.edu,"
            else:
                target_string += f"{target_key}: {email},"
        
        if target_string[-1] == ',':
            target_string = target_string[:len(target_string) - 1]
        print(target_string)


def process_args():
    parser = argparse.ArgumentParser(
        prog = 'LDIF generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description = 'Generate LDIF file from input file(s)')
    
    parser.add_argument("-d", "--dump", action='store_true', help="Dump output to console")
    parser.add_argument("-o", "--output", type=str, help="Filename to output LDIF content")       
    parser.add_argument("-i", "--input",  nargs='+', type=str, help="Source file(s) to be parsed")
    return parser.parse_args()

def main():
    args = process_args()
    if args.input == None:
        logger.error("Provide input file(s). Run python3 generate.py -h for help")
        sys.exit(1)
    if args.output == None and args.dump == False:
        logger.error("Provide an output option. Run python3 generate.py -h for help")
        sys.exit(1)

    for file in args.input:
        parse_input_file(file)
        
    if args.output != None:
        write_to_file(args.output)

    if args.dump:
        dump()

if __name__ == '__main__':
    # GLOBAL VARIABLES
    entries = {}
    entry_to_filename = {}
    # LOGGING 
    
    logging.basicConfig(level=logging.WARNING,
                        format='%(levelname)s:%(message)s',
                        handlers=[
                            logging.StreamHandler()
                        ])
    logger = logging.getLogger(__name__)    
    main()