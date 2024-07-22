# mail_ldif
- Generates an LDIF file given a list of input file(s) in key value pair format. 


## Commands 
```
python3 generate.py -o output.ldif -i file1.txt file2.txt ... 
python3 generate.py -d -i file1.txt file2.txt ... 
```

## Options
```
-o: Outputs the LDIF into a file.
-d: Outputs the LDIF to the console. One line per entry.
-i: A list of input file(s)
```
## Sample input file

```
key1 value1
key2 value2
key3 value3
```