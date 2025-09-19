===== Debugger Usage =====

-- Registers & Breakpoints --

`!reg` – Print process registers  
`!getreg` – Print registers at current memory location  
`!break` – Set a breakpoint and read registers  
`!synbreak` – Break at a debug symbol *(not stable yet)*  

-- Memory & Data Inspection --

`!dump` – Dump a raw address *(retry if ERROR_ACCESS_DENIED)*  
`!mbi` – Get MBI info *(only for unprotected processes)*  
`!bit` – Display Bitfield data  
`!var` – Display section data  
`!veh` – VEH Info  
`!imports` – Get Remote Imports  

-- Process & System Info --

`!proc` – Display all running processes  
`!cpu` – Display CPU data per processor  
`!attr` – Retrieve object attributes  
`!peb` – Display PEB details  
`!params` – Show process parameters *(debug status & path)*  
`!gsi` – Get system info  
`!cfg` – Check for CFG  
`!sig` – Get signature  
`!pwr` – Check CPU GHz  
`!handles` – Dump Handles  

-- General Commands --

`clear` – Clear the console screen  
`exit` – Terminate debugging session  
`kill` – Close the debugged process  
`help` – Display additional commands  
`!ext` – Load extension (DLL)  
`docs` – Go to documentation online  

==============================

If you hit any permission issues, or an image base of 000000 just exit and re connect with the -c command.

-- Extentions --

Extentions are just Dlls can be loaded into a remote process to do things that cannot be done outside of the remote process.
For example, I provided a heap dumper and also a full function tracer named Sly.dll. If you inject these Dlls into a remote process, either by the full version of this debugger or creating your own injection module, they will provide a more in depth view of a process. These are only really needed for specific use cases like function tracing and heap dumping, but in order for my debugger to stay stealthy, I most definitely cannot use debug apis because whats the fun in that? 

Feel free to make your own extentions, either for injection, or for just system introspection with the !ext flag in my debugger.

The full version of this debugger comes with a -i flag to inject all that is needed is the path to the Dll.

Theres much more to come!

If you are interested in testing the full version, reach out on Discord in my server.


                                   

                                
