# Remote-Debugger
A advanced debugger I wrote capable of debugging processes, this is a work in progress and will be updated frequently for more features

The stealth file contains my new POC using fibers to bypass windows protections

peb.exe is the compiled binary but as always I recomend you build from source .c

this is a windows debugger, as of now it pulls all information from the peb, register context, loaded modules, and the addresses of important structures like the ldr and image base address

this debugger hides itself from the system by using certain low level techniques like modifying dr1-dr6 but leaving dr7 for future hardware breakpoints

in the near future there will be custom breakpoints, reading registers, teb(easier than peb), much more...

this is going to be an ongoing project to feel free to try it out, add to it, break it, let me know if I can improve somewhere

I am most proud of my peb implementation as it is undocumented by microsoft and a lot of reading and old examples from 10+ years ago to build this

that being said this is original and I look forward to building this into the next windbg

if you need help with commands run help 

Facts:

(any examples I found were from 2015 and 2008 and written in c++ so I wrote this in C for speed and windows nt apis are written in C so lets keep it native) and windows internals

(checks for debugging with the PEB)

(stealthy hides debug registers)

(capable of pulling register addresses for further examining)

(built from scratch)

Sleepy :)

To do: 

+make into terminal commands/loop(done) done but needs made better

+add custom breakpoints add addresses to go deeper(easy)

+better logo (last)

+more optimization its already fast but ill add a seperate thread from the while loop to execute commands like !break, !clear, !atrributes, !peb, !teb, !access (done)

+A kernel driver in the future to access kernel structures

+IAT inspection

+add my clipboard feature
