
Starting up the Glyph
======================

There are a couple of differnt ways to start up
the debugger.

+ START 
+ ATTACH
+ BREAKPOINT

======================

START

./Glyph <PATH> start

```bash
./Glyph C:\\Windows\\System32\\notepad.exe start
```

So START means we are starting up a fresh process
and attaching the debugger right away. This is the 
most basic attachment method and is useful only 
when the process isnt already running.

TIP: Some Read operations require a ATTACH so I will
go over starting the process then attaching the debugger.
Im not sure why, but ATTACH allows deeper debugging in 
some situations. 

======================

ATTACH

./Glyph -c <Process/Name> 

```bash
./Glyph -c Notepad.exe
```

ATTACH connects the debugger to a already running.

Both of these connection methods do exactly the same thing,
but attaching to a already running process tends to allow 
fluid read and write OPs.

If you hit any error 5 codes or issues use ATTACH

personally I use this mode all the time for everything.

======================

BREAKPOINT

-b 

```bash
./Glyph -c Notepad.exe -b
```

And supply a function name to break at.

So a couple things about breakpoints.

Since I dont use any debug APIs breakpoints have to be handled
very carefully. Carefully, meaning setting up a breakpoint 
handler before doing actually setting the break.

The reason behind this is because normally when people use the 
debug APIs it will automatically register in the remote process
and it will also allow for fluid breakpoints without interrupting
execution. But, because of the way I wrote my debugger, this is
where setting up a breakpoint handler come in.

I provided some DLLs for introspection, one of those being Sly.dll.

Sly is a helper DLL that assist in fluid breakpoint setting, just
like you would in WinDbg / x64. Sly also uses VEH to "break" on 
functions and also set up a breakpoint handler for future breaks.



