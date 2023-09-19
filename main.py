import ldap3
# TODO: what should I do about the memberOf? should it just be the output of cnn.entries[0].memberOf from the members loop?
# TODO: join together the search base into one path and pass it to write_to_file
file_path = "output.ldif"
def write_to_file(uid, mail, domain):

    # dn, uid, mail, mailRoutingAddress, profileType

    try:
        with open(file_path, 'a') as file:
            file.write(f"dn: {mail}\n")
            file.write(f"uid: {mail}\n")
            file.write(f"mail: {mail}\n")
            file.write(f"mailRoutingAddress: {uid}@{domain}\n")
            file.write(f"profileType: 0\n")
            #file.write(f"memberOf: \n")
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
                
            # print(members)
            emails = []
            for member in members:    
                result = conn.search(search_base, f"(uid={member})", search_scope, attributes=attributes)
                if not result:
                    raise KeyError(f"Error: Could not find member with uid {member}")
                else:
                    #uid, mail
                    uid = conn.entries[0].uid
                    mail = conn.entries[0].mail
                    write_to_file(uid, mail, domain)
        
with open(file_path, 'w') as file:
    pass  # This block is empty, and the file is closed automatically
mail_list = get_email_list_from_ldap('org_ici')
