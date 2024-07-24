Offline Binary Ninja plugin to search for Shellcode API Hashes using databases built with/for the Mandiant FLARE shellcode_hash_search project: https://github.com/mandiant/flare-ida/blob/master/python/flare/shellcode_hash_search.py  

To install, copy the python file into your Binary Ninja plugin folder. (https://docs.binary.ninja/guide/plugins.html)  

Run via the Plugins menu bar.  

Known limitations:  
 - Does not implement GUI for algorithm selection (All algorithms in database will be run)  
 - Does not search through none code data (Only looks for arguments in instructions)  
