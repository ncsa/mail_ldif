import ldap3
import time 
import logging

file_path = "output.ldif"
def write_to_file(ldif_entries):

    # dn, uid, mail, mailRoutingAddress, profileType
    # entry = [uid, mail, memberOf, domain]
    try:        
        with open(file_path, 'w') as file:
            for entry in ldif_entries:     
                file.write(f"dn: {entry[1]}\n")
                file.write(f"uid: {entry[1]}\n")
                file.write(f"mail: {entry[1]}\n")
                file.write(f"mailRoutingAddress: {entry[0]}@{entry[3]}\n")
                file.write(f"profileType: 0\n")
                for group in entry[2]:
                    file.write(f"memberOf: {group}\n")
                file.write("\n")
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")
    except IOError as e:
        print(f"An error occurred: {str(e)}")
    
def get_email_list_from_ldap(group_name):
    """
    Retrieves the email list of the members in group_name using ldap server
    
    Args:
        group_name (str): The name of the specified group
    
    Returns:
        A list of emails from the specified group_name using ldap server
    """

    entries = []
    ldap_server = "ldaps://ldap1.ncsa.illinois.edu"  # Replace with your LDAP server
    
    ldap_user = None
    ldap_password = None

    
    search_base = 'dc=ncsa,dc=illinois,dc=edu'
    
    domain = ""
    subdomains = search_base.split(',')
    for index, subdomain in enumerate(subdomains):
        if (index == 0):
            domain = subdomain.split('=')[1]
        else:
            domain = domain + "." + subdomain.split('=')[1]

    # The subtree attributes indicatest that we want to search the entire tree starting from the search
    search_scope = ldap3.SUBTREE
    attributes = ldap3.ALL_ATTRIBUTES

    group_list = [
        group_name
    ]

    with ldap3.Connection(ldap_server, ldap_user, ldap_password) as conn:
        if not conn.bind():
            raise Exception("Error: Could not bind to LDAP server")
        else:
            for group_name in group_list:
                search_filter = f"(cn={group_name})"
                #print("search_filter: " + search_filter)
                result = conn.search(search_base, search_filter, search_scope, attributes=attributes)
                if not result:
                    raise KeyError(f"Error: Could not find group {group_name}")
                else:
                    members = [ m.split(',')[0].split('=')[1] for m in conn.entries[0].uniqueMember ]
            
            print(f"{len(members)} user entries in get_email_list_from_ldap")
            for member in members:    
                result = conn.search(search_base, f"(uid={member})", search_scope, attributes=attributes)
                if not result:
                    # if a member is not found, then just move onto the next member
                    logger.warning(f"Could not find member with uid {member}")
                    #raise KeyError(f"Error: Could not find member with uid {member}")
                else:
                    uid = conn.entries[0].uid
                    try:
                        mail = conn.entries[0].mail
                    except:
                        # If a primary email isn't set, then there's no point in adding the user entry to the LDIF
                        logger.warning(f"Primary email doesn't exist in entry with uid {member}")
                        continue
                    try:
                        memberOf = conn.entries[0].memberOf
                    except:
                        memberOf = []

                    #write_to_file(uid, mail, memberOf, domain)
                    entry = [uid, mail, memberOf, domain]
                    entries.append(entry)
    return entries

def get_user_entries_from_ldap(group_name):
    entries = []
    ldap_server = "ldaps://ldap1.ncsa.illinois.edu"  # Replace with your LDAP server
    
    ldap_user = None
    ldap_password = None

    search_base = 'dc=ncsa,dc=illinois,dc=edu'
    
    domain = ""
    subdomains = search_base.split(',')
    for index, subdomain in enumerate(subdomains):
        if (index == 0):
            domain = subdomain.split('=')[1]
        else:
            domain = domain + "." + subdomain.split('=')[1]

    # The subtree attributes indicatest that we want to search the entire tree starting from the search
    search_scope = ldap3.SUBTREE
    attributes = ldap3.ALL_ATTRIBUTES

    group_list = [
        group_name
    ]

    with ldap3.Connection(ldap_server, ldap_user, ldap_password) as conn:
        if not conn.bind():
            raise Exception("Error: Could not bind to LDAP server")
        
        for group_name in group_list:
            ldap_filter = f'(&(objectClass=person)(memberOf={group_name}))'
            search_filter = f"(cn={group_name})"
            #print("search_filter: " + search_filter)
            result = conn.search(search_base, ldap_filter, search_scope, attributes=attributes)
            if not result:
                raise KeyError(f"Error: Could not find group {group_name}")
            
            print(f"There are {len(conn.entries)} in get_user_entries_from_ldap")
            for entry in conn.entries:
                #Retrieve and print user attributes
                uid = entry.uid
                
                try:
                    mail = entry.mail
                except:
                    # If a primary email isn't set, then there's no point in adding the user entry to the LDIF
                    logger.warning(f"Primary email doesn't exist in entry with uid {uid}")
                    continue
                try:
                    memberOf = entry.memberOf
                except:
                    memberOf = []
                
                entries.append([uid, mail, memberOf, domain])
    return entries
def main():
    start_time = time.time()
    group_name = 'all_ncsa_employe'
    ldif_entries = get_user_entries_from_ldap(f"cn={group_name},ou=Groups,dc=ncsa,dc=illinois,dc=edu")
    #ldif_entries = get_email_list_from_ldap('all_ncsa_employe') # org_ici
    write_to_file(ldif_entries)
    end_time = time.time()
    elapsed_time = end_time - start_time
    # Print the elapsed time in seconds
    print(f"Elapsed time: {elapsed_time:.2f} seconds")



if __name__ == '__main__':
    formater = logging.Formatter('%(name)s:%(asctime)s:%(filename)s:%(levelname)s:%(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler("error.txt", "a")
    fileHandler.setLevel(logging.WARNING)
    fileHandler.setFormatter(formater)

    logger.addHandler(fileHandler)

    main()



