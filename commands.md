# Debugger Command Reference

## Registers & Breakpoints
- `!reg` - Print process registers
- `!getreg` - Print registers at current memory location
- `!break` - Set a breakpoint and read registers
- `!synbreak` - Set breakpoint at debug symbol (experimental not ready)
- `!dump` - Dump a raw address (sometimes error 5, run another instance and boom)

## Process & System Info
- `!proc` - Display all running processes
- `!cpu` - Get CPU data for each processor
- `!attr` - Retrieve object attributes
- `!peb` - Display PEB details
- `!params` - Show process parameters (debug status & path)

## Memory & Data Analysis
- `!mbi` - Get MBI info (only works for unprotected process)
- `!bit` - Display Bitfield data
- `!cpu` - Get system processor info
- `!var` - Get section data

## General Commands
- `clear` - Clear the console screen
- `exit` - Terminate debugging session
- `help` - Display additional commands
- `kill` - Close Process 


                                   

                                
