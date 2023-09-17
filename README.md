# file_protection
Utility to protect selected files from editing, reading, or deleting<br>Usage:
```
init            Create a configuration file and set a password
add             Add a regexp template to the config file
passwd          Change password
on              Turn on security measures
off             Turn off security measures
--help,-h       Print help
Example:
./file_protection add "test[0-9].txt"   The program would protect test0.txt, test1.txt, test2.txt, ...
```
