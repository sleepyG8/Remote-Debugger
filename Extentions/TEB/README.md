This is a sample source file for one of the extentions.

Compile:
```bash
cl /LD teb.c
```

This creates a DLL that the debugger can then use with
the !teb command, allowing the dumping of the TEB (Thread
Enviorment Block).

I made this as a two for one feature. To get a proper TEB
walker implemented into my debugger, and also to show 
everyone how to structure your extentions for Glyph.

Feel free to use this in your own projects if you wish,
the exported function takes in a process handle and a 
thread handle to then dump the TEB info, including but
not limited to the PEB address.

Once this is compiled and you have a DLL named teb.dll,
go ahead and add it to your debuggers root directory and
run the !teb command. Easy.
