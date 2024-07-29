import argparse
from dataclasses import dataclass
import sys
import logging
import re

@dataclass 
class Entry:
   source: str
   targets: list[str]

def resolve_symlinks_helper(entries, entry, visited):
    if entry.source in visited:
        return None
    
    visited.add(entry.source)
    new_targets = []
    for link in entry.targets:
        if link in entries:
            res = resolve_symlinks_helper(entries, entries[link], visited)
            if res:
                new_targets.extend(res)
        else:
            new_targets.append(link)
    return new_targets

def resolve_symlinks(entries):
    """ 
    Modify entries in place
    """
    tmp_entries = {}
    for key, entry in entries.items():
        visited = set()
        entry.target = resolve_symlinks_helper(entries, entry, visited)
        
    # print("OUTPUT")
    # print(entries)
    

def assign_new_address(address, address_mapping):
    address_components = address.split('@')
    
    if len(address_components) == 1:
        return f"{address}@{address_mapping["default"]}"
    
    domain = address_components[1]
    if domain in address_mapping:
        # print(f"Change {address}")
        return f"{address_components[0]}@{address_mapping[domain]}"
    return address

def standardize_entries(entries, address_mapping):
    tmp_entries = {}
    for key in entries:
        entry = entries[key]
        source_address = assign_new_address(entry.source, address_mapping)
        entry.source = source_address
        target_addresses = []
        for target in entry.targets:
            target_addresses.append(assign_new_address(target, address_mapping))
        entry.targets = target_addresses
        tmp_entries[source_address] = entry
    return tmp_entries

def is_special_address(address, special_addresses):
    for special_address in special_addresses:
        if special_address in address or "@ncsa" not in address:
            return True
        if  not valid_email(address):
            # print(f"'{address}'")
            return True
    return False

def dump_special_addresses(entries, special_addresses):
    tmp_entries = {}
    for key, entry in entries.items():
        addresses = [entry.source] + entry.targets
        for address in addresses:
            if is_special_address(address, special_addresses):
                special_address_entries.append(entry)
                continue
        tmp_entries[key] = entry
    return tmp_entries

def valid_email(address):
    regex = r'\b[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if re.fullmatch(regex, address):
        # print("Valid Email")
        return True
    else:
        # print("Invalid Email")
        return False
        
def parse_input_file(filename, entries):
    """
    Parses the input file of key value pairs
    
    Args:
        filename (str): the input file
        
    Returns:
        dict: contains the source as the key and list of targets as value
    """
    tmp_entries = dict(entries)
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

            targets = []
            
            for target in entry[len(entry) - 1].split(','):
                targets.append(target.strip())
            
            targets.sort()
            source = entry[0].strip() 
               
            if source in tmp_entries and targets == tmp_entries[source].targets:
                continue
                    
            if source in tmp_entries or source in duplicate_entries:
                duplicate_entries[source].append(f"{filename}-{line_number}")
                tmp_entries.pop(source)
                continue
            else:
                duplicate_entries[source] = [f"{filename}-{line_number}"]
    
            entry = Entry(source, targets)
            tmp_entries[source] = entry    
    return tmp_entries    

def write_to_file(filename, entries):
    """
    Writes the entries into an LDIF file
    
    Args:
        filename (str): the output file
        
    Returns:
        None
    """
    with open(filename, 'w') as f:
        for key in entries:
            entry = entries[key]
            f.write(f"dn: {entry.source}\n")
            f.write(f"uid: {entry.source}\n")
            f.write(f"mail: {entry.source}\n")
            
            target_key = 'mailRoutingAddress'
            if len(entry.targets) == 1:
                f.write(f"profileType: 0\n")
            else:
                f.write(f"profileType: 1\n")
                target_key = 'listMember'
                            
            for target in entry.targets:
                f.write(f"{target_key}: {target}\n")
            f.write("\n")
                
            
# def dump():
#     """
#     Dumps the entries to the console. One line per entry. 
#     """
#     for username in entries:
#         print(f"dn: {username}", end=',')
#         print(f"uid: {username}", end=',')

#         if '@' not in username: 
#             print(f"mail: {username}@ncsa.illinois.edu", end=',')    
#         else:
#             print(f"mail: {username}", end=',')
        
#         if len(entries[username]) == 1:
#             print(f"profileType: 0", end=',')
#             target_key = 'mailRoutingAddress'
#         else:
#             print(f"profileType: 1", end=',')
#             target_key = 'listMember'
            
#         target_string = ''
        
#         for email in entries[username]:
#             if email == 'devnull' or email == '/dev/null':
#                 target_string += f"{target_key}: no-reply@illinois.edu,"
#             elif email == 'postmaster':
#                 target_string += f"{target_key}: postmaster@illinois.edu,"
#             elif '@' not in email:
#                 target_string += f"{target_key}: {email}@ncsa.illinois.edu,"
#             else:
#                 target_string += f"{target_key}: {email},"
        
#         if target_string[-1] == ',':
#             target_string = target_string[:len(target_string) - 1]
#         print(target_string)


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
    
    entries = {}
    for file in args.input:
        entries = parse_input_file(file, entries)
        
    entries = standardize_entries(entries, address_mapping)
    resolve_symlinks(entries)
    
    for key, e in entries.items():
        print(e)
    
    # entries = dump_special_addresses(entries, special_addresses)
    
    # for entry in special_address_entries:
    #     print(entry)
        
    if args.output != None:
        write_to_file(args.output, entries)
        
    # for key in duplicate_entries:
    #     if len(duplicate_entries[key]) != 1:
    #         print(f"{key}: {duplicate_entries[key]}")
            
    # if args.dump:
    #     dump()

    
if __name__ == '__main__':
    # GLOBAL VARIABLES
    # entries = {}
    duplicate_entries = {}
    special_address_entries = []
    
    address_mapping = {
        "default": "ncsa.illinois.edu",
        "uiuc.edu": "illinois.edu",
        "ncsa.edu": "ncsa.illinois.edu", 
        "ncsa.uiuc.edu": "ncsa.illinois.edu"
    }
    
    special_addresses = {
        "devnull",
        "postmaster",
        "no-reply",
        "security",
        "jira",
        "train",
        "root",
        "campuscluster",
        "majordomo",
        "help"
    }


    # LOGGING 
    
    logging.basicConfig(level=logging.WARNING,
                        format='%(levelname)s:%(message)s',
                        handlers=[
                            logging.StreamHandler()
                        ])
    logger = logging.getLogger(__name__)    
    main()
    # test()