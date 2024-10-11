import argparse
from dataclasses import dataclass
import sys
import logging
import re
import dns.resolver
import time
import yaml
from datetime import datetime
import csv
import collections

@dataclass 
class Entry:
   source: str
   targets: list[str]
   filename: str

def parse_file(filename: str) -> tuple[list[Entry], list[Entry]]:
    """
    Parses filename for sources and targets. Expect 1 source and a comma 
    seperated list for targerts (if more than one target)
    
    Args:
        filename (str): name of file to be parsed
    
    Returns:
    tuple[list[Entry], list[Entry]]: A tuple containing two lists of `Entry` 
    objects. The first list includes `Entry` objects that meet the expected 
    line format, while the second list contains those that do not.
    """
    valid_entries = []
    invalid_entries = []

    with open(filename, 'r') as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            components = line.split(' ')
            
            if len(components) != 2:
                invalid_entries.append(line)
                continue

            source = components[0]
            targets = components[1].split(',')
            targets.sort()
            valid_entries.append(Entry(source, targets, filename))

    return (valid_entries, invalid_entries)

def assign_domain(address: str, domain_mapping: dict[str, str]) -> str: 
    """
    Assigns a new domain to an email address if the domain exist in 
    domain_mapping
    
    Args:
        address (str): an email address
        domain_mapping (dict[str, str]): A dictionary that is used to replace 
        specified domains
    
    Returns:
        (str) An email address with the desired domain
    """
    address_components = address.split('@')
    
    if len(address_components) == 1:    
        return f"{address}@{domain_mapping["default"]}"
    
    domain = address_components[1]

    new_domain = domain_mapping.get(domain, None)

    if domain in domain_mapping:
        return f"{address_components[0]}@{domain_mapping[domain]}" 
    return address

def check_and_replace_domain(entries: list[Entry], 
                             domain_mapping: list[str, str]) \
                             -> list[Entry]:
    """
    Reassigns the addresses contain in each 'Entry' object from entries 
    if their domain exist in domain_mapping

    Args:
        entries (list[Entry]): A list of 'Entry' objects 
        domain_mapping (dict[str, str]): A dictionary that is used to replace 
        specified domains

    Returns:
        list[Entry]:A list of 'Entry' objects with their addresses modified
    """
    if not domain_mapping:
        return entries

    for entry in entries:
        entry.source = assign_domain(entry.source, domain_mapping)

        for i, address in enumerate(entry.targets):
            entry.targets[i] = assign_domain(address, domain_mapping)
    return entries

def find_exact_match(entries: list[Entry]) -> list[Entry]:
    """
    Traverses through entries and find unique 'Entry' objects, where sources 
    are the same, but targets are not

    Args:
        entries (list[Entry]): A list of entries where their sources are the 
        same 

    Returns:
        list['Entry']: A list of unique 'Entry' objects with the same source,
        but different targets
    """
    entries.sort(key=lambda v: v.source)
    unique_targets_entries = [entries[0]]
    
    for entry in entries[1:]:
        if entry.targets != unique_targets_entries[-1].targets:
            unique_targets_entries.append(entry)
    return unique_targets_entries

def remove_duplicates(entries: list[Entry]) \
                      -> tuple[list[Entry], list[Entry]]:
    """
    Finds unique 'Entry' objects

    Note: In case that there are duplicates with same source and different 
    targets, and user wants combine the targets together. Add these entries 
    to entries_to_remove, and add the desired entry to additional_entries.  

    Args:
        entries (list[Entry]): A list of 'Entry' objects 
    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects that are 
        unique, while the second list contains those are not. 

    """
    valid_entries = []
    invalid_entries = []

    entries.sort(key=lambda v: v.source)

    # 2 pointer approach

    l = 0

    for r, entry in enumerate(entries):
        if entries[l].source == entry.source:
            continue

        if r - l > 1:
            unique_duplicates = find_exact_match(entries[l:r])
            if len(unique_duplicates) == 1:
                valid_entries.append(unique_duplicates[0])
            else:
                invalid_entries.extend(unique_duplicates)
        else:
            valid_entries.append(entries[l])
        l = r 

    if l == r: 
        valid_entries.append(entry)
    else:
        unique_duplicates = find_exact_match(entries[l:r + 1])
        if len(unique_duplicates) == 1:
            valid_entries.append(unique_duplicates[0])
        else:
            invalid_entries.extend(unique_duplicates)

    return (valid_entries, invalid_entries)

def remove_non_ncsa_source_domains(entries: list[Entry]) \
                                   -> tuple[list[Entry], list[Entry]]:
    """
    Removes entries with non@ncsa domain sources.

    Args:
        entries (list[Entry]): A list of 'Entry' objects

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with sources 
        that doesn't have a ncsa domain, while the second list contains 
        those that do. 
    """
    valid_entries = []
    invalid_entries = []

    for entry in entries:
        if "@ncsa" not in entry.source:
            invalid_entries.append(entry)
        else:
            valid_entries.append(entry)
    return (valid_entries, invalid_entries)

def is_special_address(address: str, special_addresses: set[str]) -> bool:
    """
    Checks whether the address is one of the special addresses

    Args:
        address (str): The email address 
        special_addresses (set[str]): contains keywords that 
        should be filtered out
    
    Returns:
        bool: whether the address is a special address or not
    """
    for special_address in special_addresses:
        if special_address in address:
            return True
    return False

def remove_special_addresses(entries: list[Entry],
                             special_addresses: set[str]) \
                             -> tuple[list[Entry], list[Entry]]:
    """
    Removes entries with special addresses from entry's targets. 
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
        special_addresses (set[str] ): contains keywords that should be 
        filtered out
   
    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with 
        non-special addresses, while the second list contains those that do. 
    """
    if not special_addresses:
        return (entries, None)

    valid_entries = []
    invalid_entries = []

    for entry in entries:
        found_special_address = False
        for address in entry.targets:
            if is_special_address(address, special_addresses):
                found_special_address = True 
                break
        if found_special_address:
            invalid_entries.append(entry)
        else:
            valid_entries.append(entry)
    return (valid_entries, invalid_entries)

def has_mx_record(domain: str) -> bool:
    """
    Checks whether there is a valid MX record for domain

    Args:
        domain (str): a domain
    
    Returns:
        bool: Whether a valid MX record for domain
    """
    try:
        # Perform a DNS query for MX records
        dns.resolver.resolve(domain, 'MX')
        return True
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def valid_email_format(address: str, index: int) -> bool:
    """
    Checks whether the address is syntactically correct
    
    Args:
        address (str): The email address 
        index (int): source (0) or target (1)
        
    Returns:
        bool: Whether or not address is syntactically correct
    """
    if index == 0:
        regex = r'\b[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    else:
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        
    return True if re.fullmatch(regex, address) else False

def remove_misformatted_addresses(entries: list[Entry]) \
                                  -> tuple[list[Entry], list[Entry]]:
    """
    Removes 'Entry' objects that are not syntactically correct

    Args: 
        entries (list[Entry]): A list of 'Entry' objects

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with 
        addresses that are syntactically correct, while the second list 
        contains those that are not  
    """
    valid_entries = []
    invalid_entries = []

    for entry in entries:
        combination = [entry.source] + entry.targets
        found_misformatted_address = False
        for index, address in enumerate(combination):
            if not valid_email_format(address, index):
                invalid_entries.append(entry)
                found_misformatted_address = True
                break   
        if not found_misformatted_address:
            valid_entries.append(entry)
    return (valid_entries, invalid_entries)

def get_valid_domain(domain: str) -> list[str]:
    """ 
    Check and obtain a domain with a valid MX record. Checks whether the 
    given domain has a valid record and attempts domain devolution if not.

    Args:
      domain (str): The domain of an email address

    Returns:
      list[str]: A list of domains containing a history of the devolution
      of the given domain. If a valid domain exist, the last value is 
      a str. Otherwise, it is None. 
    """
    #print(domain)
    if has_mx_record(domain):
        return [domain]
    
    components = domain.split('.')
    
    if len(components) == 2:
        return [None]
    
    new_domain = '.'.join(components[1:])
    res = [domain]
    res.extend(get_valid_domain(new_domain))
    return res 

def remove_invalid_addresses(entries: list[Entry]) \
                             -> tuple[list[Entry], list[Entry]]:
    """
    Checks whether the emails (source and targets) have MX records 

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        
    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with 
        addresses that have MX records, while the second list 
        contains those that do not 
    """

    known_domains = dict()
    valid_entries = []
    invalid_entries = []

    for entry in entries:
        combination = [entry.source] + entry.targets
        new_addresses = []
        for index, address in enumerate(combination):

            address_components = address.split('@')
            username = address_components[0]
            domain = address_components[1]

            if domain in known_domains:
                if not known_domains[domain]:
                    invalid_entries.append(entry)
                    break
                else:
                    new_addresses.append(f"{username}@{known_domains[domain]}")
                    continue

            res = get_valid_domain(domain)
            for invalid_domain in res:
                # res[len(res) - 1] could be None or a str (for valid domain)
                known_domains[invalid_domain] = res[-1]
            
            if res[-1]:
                new_address = f"{username}@{res[-1]}"
                new_addresses.append(new_address)
            else:
                invalid_entries.append(entry)
                break

        if len(new_addresses) == len(combination): 
            # All domains are accounted for 
            entry.source = new_addresses[0]
            entry.targets = new_addresses[1:]
            valid_entries.append(entry)

    return (valid_entries, invalid_entries)

def resolve_symlinks_helper(source_to_targets: dict[str, list[str]],
                            address: str,
                            visited: set[str]) \
                            -> list[str]:
    """
    Recursive function that resolves dependencies 
    
    Args:
        entries (dict): A dictionary of str to Entry pairs
        entry (Entry): The current entry the recursive function is on 
        visited (str): A set of nodes that have been visited
        
    Returns:
        new_targets (lst[str]): A list of endpoints (leaf nodes) 
        from source entry
    """
    new_targets = []
    for neighbor in source_to_targets[address]:
        if neighbor not in source_to_targets:
            new_targets.append(neighbor)
            continue
        if neighbor in visited:
            continue

        visited.add(neighbor)    
        res = resolve_symlinks_helper(source_to_targets, neighbor, visited)

        if res:
            new_targets.extend(res)
    return new_targets


def resolve_symlinks(entries: list[Entry]) -> list[Entry]:
    """ 
    Resolve the dependecies for each 'Entry' object's targets. 

    Args:
        entries (list[Entry]): A list of 'Entry' objects
    
    Returns:
        list[Entry]: a list of 'Entry' objects with their targets resolved
        to an end distination
    """

    # Create an adjency list

    source_to_targets = dict()

    for entry in entries:
        source_to_targets[entry.source] = entry.targets
      
    for entry in entries:
        visited = set()
        visited.add(entry.source)
        res = resolve_symlinks_helper(source_to_targets, 
                                      entry.source, 
                                      visited)
        if res:
            entry.targets = res

    return entries

def print_list_entries(entries: list[Entry], filename: str) -> None:
    """
    Write to filename the 'Entry' objects from entries

    Args:
        entries (List[Entry]): A list of 'Entry' objects 
        filename (str): Name of the file to write to 
    
    Return:
        None
    """
    if not entries:
        return None

    with open(filename, 'w') as f:
        for entry in entries:
            f.write(f"{entry.source} {",".join(entry.targets)}\n")

def remove_source_matching_regex(entries: list[Entry], regexes: list[str]) \
                                 -> tuple[list[Entry], list[Entry]]:
    """
    Filter out any 'Entry' object's source that matches the regex

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        regexes (list[str]): A list of regexes 

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with 
        sources that doesn't match the regexes, while the second list 
        contains those that do

    """
    if not regexes:
        return (entries, None)
    # 0 for source, 1 for tagets

    valid_entries = []
    invalid_entries = []
    
    compiled_regexes = [re.compile(rf"{regex}") for regex in regexes]

    for entry in entries:
        matched = False
        if any(regex.search(entry.source) for regex in compiled_regexes):
            invalid_entries.append(entry)
            matched = True
        if not matched:
            valid_entries.append(entry)            
    return (valid_entries, invalid_entries)

def remove_target_matching_regex(entries: list[Entry], regexes: list[str]) \
                                 -> tuple[list[Entry], list[Entry]]:
    """
    Filter out any 'Entry' object's targets that matches the regex

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        regexes (list[str]): A list of regexes 

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects with 
        targets that doesn't match the regexes, while the second list 
        contains those that do

    """
    if not regexes:
        return (entries, None)

    valid_entries = []
    invalid_entries = []
    
    compiled_regexes = [re.compile(rf"{regex}") for regex in regexes]
    for entry in entries:
        for address in entry.targets:
            matched = False
            if any(regex.search(address) for regex in compiled_regexes):
                invalid_entries.append(entry)
                matched = True
                break
        if not matched:
            valid_entries.append(entry)
    return (valid_entries, invalid_entries)

def remove_known_bad_entries(entries: list[Entry],
                             entries_to_remove: dict[str, list[str]]) \
                             -> tuple[list[Entry], list[Entry]]:
    """
    Filter out any 'Entry' objects that exist in entries_to_remove. 
    Uses set arithmetic. ONLY the targets listed in entries_to_remove are
    removed.
    Example:
    Entry(a, [b,c], 'somefile])
    entries_to_remove = {a: [b]}
    The res is: Entry(a, [c]) 

    IF entries_to_remove = {a: [b,c]}, then the entire Entry is removed. 

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        entries_to_remove (dict[str, list[str]): A dictionary that has 
        source as the key and a list of targets as value. 

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects that aren't
        listed in entries_to_remove, while the second list  contains 
        those that do
    """
    if not entries_to_remove:
        return entries

    valid_entries = []

    for entry in entries:
        if entry.source in entries_to_remove:
            a = set(entries_to_remove[entry.source])
            b = set(entry.targets)
            diff = b - a
            if diff:
                entry.targets = list(diff)
                entry.targets.sort()
                valid_entries.append(entry)
        else:
            valid_entries.append(entry)
    
    return valid_entries

def modify_misformatted_addresses(entries: list[Entry], 
                                  misformatted_addresses: dict[str, str]) \
                                  -> list[Entry]:
    """
    Modify the addresses in the 'Entry' object if they exist in 
    misformatted_addresses 

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        misformatted_addresses (dict[str, str): A dictionary that has 
        the misformatted address as the key and the correct address as the 
        value

    Returns:
        list[Entry]: A list of 'Entry' objects with corrected addresses 
    """
    if not misformatted_addresses:
        return entries

    for entry in entries:
        entry.source = misformatted_addresses.get(entry.source, entry.source)

        tmp_targets = []
        for target in entry.targets:
            tmp_targets.append(misformatted_addresses.get(target, target))
        entry.targets = tmp_targets

    return entries

def add_additional_entries(entries: list[Entry], 
                           additional_entries: dict[str, list[str]]) \
                           -> list[Entry]:
    """
    Add additional 'Entry' objects to entries. If an 'Entry' object with the
    same source already exist, then the new targets will be appended to the 
    existing targets in the original 'Entry' object. If not, a new 
    'Entry' object will be created and appended to entries. 

    Args:
        entries (list[Entry]): A list of 'Entry' objects
        additional_entries (dict[str, str): A dictionary that has 
        the source as the key and a list of targets as the 
        value

    Returns:
        list[Entry]: A list of 'Entry' objects with additional entries. 
    """
    if not additional_entries:
        return entries

    # Create an adjency list
    source_to_targets = dict()

    for entry in entries:
        source_to_targets[entry.source] = entry.targets

    for source, targets in additional_entries.items():
        if source in source_to_targets:
            print(f"WARNING: appending {targets} to an existing entry:" + 
                  f"{source} {source_to_targets[source]}")
            source_to_targets[source].extend(targets)
        else:
            entries.append(Entry(source, targets, 'additional_entries'))
    return entries

def find_ncsa_domain_targets(entries: list[Entry]) \
                             -> tuple[list[Entry], list[Entry]]:
    """
    Filter out any 'Entry' object that has "@ncsa.illinois.edu" in their
    list of targets

    Args:
        entries (list[Entry]): A list of 'Entry' objects

    Returns:
        tuple[list[Entry], list[Entry]]: A tuple containing two lists of 
        `Entry` objects. The first list includes `Entry` objects that does not
        contain "@ncsa.illinois.edu" in their targets, while the second list 
        contains those that do 
    """
    valid_entries = []
    invalid_entries = []

    for entry in entries:
        if any("@ncsa.illinois.edu" in target for target in entry.targets):
            invalid_entries.append(entry)
        else:
            valid_entries.append(entry)
    return (valid_entries, invalid_entries)

def write_to_csv(filename: str, entries: list[Entry]) -> None: 
    """
    Write out the sources and targets from entries to filename in csv format

    filename (str): The name of the file 
    entries (list[Entry]): A list of 'Entry' objects 

    Returns:
        None
    """
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Source", "Targets"])
        for entry in entries:
            comma_seperated_targets = ",".join(entry.targets)
            writer.writerow([f"{entry.source}", f"{comma_seperated_targets}"])

def generate_output(input_file: list[str]) -> None:
    """
    Reads in the entries from the list of file in input_file and compile 
    a csv file

    Args:
        input_file (list[str]): A list of input files 

    Returns:
        None
    """
    
    # A list of Entry
    entries = []
    for file in input_file:
        parseable, unparseable = parse_file(file)
        entries.extend(parseable)

    # Obtain values from the config.yaml
    domain_mapping = data.get('domain_mapping', None)
    misformatted_addresses = data.get('misformatted_addresses', None)
    entries_to_remove = data.get('entries_to_remove', None)
    source_regex = data.get('source_regex_to_remove', None)
    target_regex = data.get('target_regex_to_remove', None)
    additional_entries = data.get('additional_entries', None)
    special_addresses = data.get('special_addresses', None)

    # MODIFY AND REMOVE KNOWN BAD ENTRIES
    entries = check_and_replace_domain(entries, domain_mapping)
    entries = modify_misformatted_addresses(entries, misformatted_addresses)
    entries = remove_known_bad_entries(entries, entries_to_remove)
    entries, source_regexed_entries = remove_source_matching_regex(entries, source_regex)
    entries, target_regexed_entries = remove_target_matching_regex(entries, target_regex)

    # ADD ADDITIONAL ENTRIES
    entries = add_additional_entries(entries, additional_entries)
    
    # FILTER ENTRIES
    entries, duplicates = remove_duplicates(entries)
    entries, non_ncsa = remove_non_ncsa_source_domains(entries)
    entries, special_addresses = remove_special_addresses(entries, special_addresses)
    entries, misformatted_addresses = remove_misformatted_addresses(entries)
    entries, invalid_addresses = remove_invalid_addresses(entries)
    entries = resolve_symlinks(entries)  
    entries, ncsa_domain_targets = find_ncsa_domain_targets(entries)

    # PRINT VALID AND INVALID ENTRIES TO FILES
    subdir = './invalids'
    print_list_entries(duplicates, f"{subdir}/duplicates.txt")
    print_list_entries(non_ncsa, f"{subdir}/non_ncsa_domains.txt")
    print_list_entries(special_addresses, f"{subdir}/special_addresses.txt")
    print_list_entries(misformatted_addresses, f"{subdir}/misformatted_addresses.txt")
    print_list_entries(invalid_addresses, f"{subdir}/invalid_addresses.txt")
    print_list_entries(source_regexed_entries, f"{subdir}/source_regexed.txt")
    print_list_entries(target_regexed_entries, f"{subdir}/target_regexed.txt")
    print_list_entries(ncsa_domain_targets, f"{subdir}/ncsa_domain_targets.txt")
    
    write_to_csv('output.csv', entries)

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

    generate_output(args.input)
    
if __name__ == '__main__':

    # GLOBAL VARIABLES
    with open('config.yaml', 'r') as file:
        data = yaml.safe_load(file)
        
    # LOGGING 
    logging.basicConfig(level=logging.WARNING,
                        format='%(levelname)s:%(message)s',
                        handlers=[
                            logging.StreamHandler()
                        ])
    logger = logging.getLogger(__name__)    
    main()
   
