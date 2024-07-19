import argparse
import sys

def parse_input_file(filename):
    """
    Parses the input file of key value pairs
    
    Args:
        filename (str): the input file
        
    Returns:
        dict: contains the source as the key and list of targets as value
    """
    entries = {}
    with open(filename, 'r') as f:
        for line in f:
            newLine = line.strip()
            newLine = newLine.replace('\t', ' ')
            
            colon_index = newLine.find(':')
            space_index = newLine.find(' ')

            if colon_index == -1:
                entry = newLine.split(' ')
            elif space_index == -1:
                entry = newLine.split(':')
            elif colon_index < space_index:
                entry = newLine.split(':')
            else:
                # colon_index >= space_index:
                entry = newLine.split(' ')

            username = entry[0].strip()
            
            entries[username] = []
            for email in entry[len(entry) - 1].split(','):
                entries[username].append(email.strip())
    return entries

def write_to_file(filename, entries):
    """
    Writes the entries into an LDIF file
    
    Args:
        filename (str): the output file
        entries (dict): contains the source as the key and list of targets as value
        
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

def process_args():
    parser = argparse.ArgumentParser(
        prog = 'LDIF generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description = 'Generate LDIF file from on input file')
    
    parser.add_argument("-i", "--input",  nargs='+', type=str, help="Source file to be parsed")
    parser.add_argument("-o", "--output", type=str, help="Filename to output LDIF content")       
    return parser.parse_args()

def main():
    args = process_args()
    if args.input == None or args.output == None:
        print('Error: run python3 generate.py -h for help')
        sys.exit(1)
    print(f"input: {args.input}")
    print(f"output: {args.output}")
    
    entries = {}
    for file in args.input:
        entries.update(parse_input_file(file))
    write_to_file(args.output, entries)

if __name__ == '__main__':
    main()

