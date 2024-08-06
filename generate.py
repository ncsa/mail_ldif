import argparse
from dataclasses import dataclass
import sys
import logging
import re

@dataclass 
class Entry:
   source: str
   targets: list[str]
   filename: str

def resolve_symlinks_helper(entries, entry, visited):
    """
    Recursive function that resolves dependencies 
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
        entry (Entry): The current entry the recursive function is on 
        visited (str): A set of nodes that have been visited
        
    Returns:
        new_targets (str): A list of endpoints (leaf nodes) from source entry
    """
    if entry.source in visited:
        return None
    
    visited.add(entry.source)
    new_targets = []
    for link in entry.targets:
        if link not in entries:
            new_targets.append(link)
            continue
            
        res = resolve_symlinks_helper(entries, entries[link], visited)
        if res:
            new_targets.extend(res)
    return new_targets

def resolve_symlinks(entries):
    """ 
    Resolve the dependecies for each entry. Assign a source node with a list of endpoints (leaf nodes)
    that source resolves to. Modify entries in place. 
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
    
    Returns:
        None
    """
    for key, entry in entries.items():
        visited = set()
        entry.target = resolve_symlinks_helper(entries, entry, visited)    

def assign_new_address(address, address_mapping):
    """
    Assigns a new domain to an email address if the domain exist in address_mapping
    
    Args:
        address (str): an email address
        address_mapping (str to str dict): A dictionary that is used to replace specified domains
    
    Returns:
        (str) An email address with the desired domain
    """
    address_components = address.split('@')
    
    if len(address_components) == 1:    
        return f"{address}@{address_mapping["default"]}"
    
    domain = address_components[1]
    if domain in address_mapping:
        return f"{address_components[0]}@{address_mapping[domain]}"
    return address

def is_special_address(address, special_addresses):
    """
    Checks whether the address is one of the special addresses
    
    Args:
        address (str): The email address 
        special_addresses (set of str): A set containg special addresssses
    
    Returns:
        bool: whether the address is a special address or nots
    """
    for special_address in special_addresses:
        if special_address in address:
            return True
    return False

def remove_special_addresses(entries, special_addresses):
    """
    Removes entries with special addresses (specified by user) from entries. 
    Modify entries in place
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
        special_addresses (set of str): A set containg special addresssses
    
    Returns:
        None
    """
    tmp_entries = dict(entries)
    for key, entry in tmp_entries.items():
        found_special_address = False
        for address in entry.targets:
            if is_special_address(address, special_addresses):
                found_special_address = True
                break
        if found_special_address:
            special_address_entries.append(entry)
            entries.pop(key)

def remove_non_ncsa_addresses(entries):
    """
    Removes entries with non@ncsa domain sources.
    Modify in place
    Args:
        entries (dict): A dictionary of str to Entry pairs
        
    Returns:
        None
    """
    tmp_entries = dict(entries)
    for key, entry in tmp_entries.items():
        if "@ncsa" not in entry.source:
            non_ncsa_domain_entries.append(entry)
            entries.pop(key)

def remove_invalid_emails(entries):
    """
    Checks whether the emails (source and targets) are valid emails. If not, it will 
    be removed from entries
    Modify entries in place
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
        
    Returns:
        None
    """
    tmp_entries = dict(entries)
    for key, entry in tmp_entries.items():
        invalid = False
        combined = [entry.source] + entry.targets
        for target in combined:
            if not valid_email(target):
                invalid = True
                break    
        if invalid:
            invalid_email_entries.append(entry)
            entries.pop(key)

def valid_email(address):
    """
    Checks whether the address is valid with the regex
    
    Args:
        address (str): The email address 
        
    Returns:
        bool: whether or not address is valid
    """
    regex = r'\b[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return True if re.fullmatch(regex, address) else False
        
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
            
            tmp_entry = []
            
            for v in entry:
                if len(v) != 0:
                    tmp_entry.append(v)
            entry = tmp_entry
            
            if len(entry) != 2:
                # print(f"Messed Up: {entry}")
                unparseable_entries.append(line)
                continue
                
            for target in entry[1].split(','):
                target_address = assign_new_address(target.strip(), address_mapping)
                targets.append(target_address)
            
            targets.sort()
            source = assign_new_address(entry[0].strip() , address_mapping)
            entry = Entry(source, targets, filename)
               
            if source in tmp_entries and targets == tmp_entries[source].targets:
                continue
                    
            if source in tmp_entries:
                duplicate_entries.append(entry)
                if tmp_entries[source] not in duplicate_entries:
                    duplicate_entries.append(tmp_entries[source])
                continue
            
            # By this step, entry should be standardized
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
            
def dump(entries):
    """
    Dumps the entries to the console. One line per entry. 
    """
    for key, entry in entries.items():
        print(f"dn: {entry.source}", end=',')
        print(f"uid: {entry.source}", end=',')

        target_key = 'mailRoutingAddress'
        if len(entry.target) == 1:
            print(f"profileType: 0", end=',')
        else:
            print(f"profileType: 1", end=',')
            target_key = 'listMember'
            
        target_string = ''
        for target in entry.targets:
            target_string += f"{target_key}: {target},"
        
        print(target_string[:len(target_string) - 1])

def write_errors_to_file(filename, error_entries):
    """
    Writes out the various errors found in the input files 
    
    Args:
        filename: The filename of the particular error is written to
        error_entries (list of Entry)
    
    Returns:
        None
    """
    with open(filename, 'w') as f:
        for entry in error_entries:
            f.write(f"{entry.filename}: {entry.source} => {entry.targets}\n")

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
        
    
    for entry in duplicate_entries:
        # If pop returns -1, that means that the entry has been removed once already
        entries.pop(entry.source, -1) 

    resolve_symlinks(entries)
    remove_non_ncsa_addresses(entries)
    remove_special_addresses(entries, special_addresses)
    remove_invalid_emails(entries)
    
    
    if args.output != None:
        write_to_file(args.output, entries)        
        
    if args.dump:
        dump(entries)
    
    write_errors_to_file("duplicates.txt", duplicate_entries)
    write_errors_to_file("special_address.txt", special_address_entries)
    write_errors_to_file("invalid_email.txt", invalid_email_entries)
    write_errors_to_file("non_ncsa_domain_src.txt", non_ncsa_domain_entries)
    
    with open("unparseable.txt", 'w') as f:
        for line in unparseable_entries:
            f.write(f"{line}")

    
if __name__ == '__main__':
    # GLOBAL VARIABLES
    # entries = {}
    duplicate_entries = []
    special_address_entries = []
    invalid_email_entries = []
    non_ncsa_domain_entries = []
    unparseable_entries = []
    
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