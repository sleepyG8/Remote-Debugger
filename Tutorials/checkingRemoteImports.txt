Checking Remote Imports
========================

There is two ways to check for imported modules
in this debugger. Either through the IAT or
through the Loaded module list from the PEB
aka the LDR.

 ++++++++++
+ !Imports +
 ++++++++++

!imports - Dumps the imported functions

This gets all of the loaded DLLs and also gets
the imported functions from those DLLs 

Tip: This must be ran to properly map function 
names in the !dump command.

 ++++++++++
+   !dll   +
 ++++++++++

!dll - Dumps all loaded modules / DLLs

This command retrieves all the loaded DLLs in the
process. It uses a custom structure "Dlls" to store
all of the current modules at the time of connection.



