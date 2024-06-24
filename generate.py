import argparse

def parse_input_file(filename):
    entries = {}
    with open(filename, 'r') as f:
        for line in f:
            entry = line.split(' ')
            username = entry[0]
        
            if '@' in username: continue
            
            entries[username] = []
            for email in entry[1].split(','):
                entries[username].append(email.strip())
    
    return entries

def write_to_file(filename, entries):

    with open(filename, 'w') as f:
        for username in entries:
            f.write(f"dn: {username}@ncsa.illinois.edu\n")
            f.write(f"uid: {username}@ncsa.illinois.edu\n")
            f.write(f"mail: {username}@ncsa.illinois.edu\n")
            
            fowarding = entries[username]
            if len(fowarding) == 1:
                f.write(f"profileType: 0\n")
                f.write(f"mailRoutingAddress: {fowarding[0]}\n")
            else:
                f.write(f"profileType: 1\n")
                for email in fowarding:
                    f.write(f"listMember: {email}\n")
                
            f.write("\n")

# @TODO write a help function 
def process_args():
    parser = argparse.ArgumentParser(
        prog = 'LDIF generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description = 'Generate LDIF file from on input file')
    
    parser.add_argument("input", type=str, help="Source file to be parsed")
    parser.add_argument("output", type=str, help="Filename to output LDIF content")       
    return parser.parse_args()

def main():
    args = process_args()

    entries = parse_input_file(args.input)
    write_to_file(args.output, entries)

if __name__ == '__main__':
    main()
