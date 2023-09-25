# mail_ldif

Generate an LDIF file containing 6key-value pairs per user entry: 
```
dn: jDoe1@illinois.edu                 
uid: jDoe1@illinois.edu  
mail: jDoe1@illinois.edu       
mailRoutingAddress: jDoe1@ncsa.illinois.edu
profileType: 0
memberOf: group1
memberOf: group2
```

- **dn** is the distinguish name that uniquely identifies the entry. Recommend using target email

- **uid** is the unique identifier for a user.  Recommend using dn value

- **mail** is the primary email listed on the LDAP user query (target email)

- **mailRoutingAddress** is the email address that is being rerouted from.

- **profileType** identifies the type of entry, and 0 is the default for user entry

- **memberOf** is a list of groups that the member is apart of. 