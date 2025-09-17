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


                                   

                                
