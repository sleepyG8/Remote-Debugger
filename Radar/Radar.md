Radar is a Dll that can be Injected into a remote process to
pull executable code out of memory.

Once injected it will attach a console and begin searching for
executable code regions in memory.

Radar.dll - Searches for code starting near the base address.
This finds the .text section because the .text is the very 
first section after the base address.

RadarHeap.dll - Searches the heap range for exectuable code 
using the same algorithm.

Dont worry this finds exectuable code, not sections and does 
not rely on and headers at all. It walks raw memory and finds
the code through assembly heuristics. This not only finds code
but function boundaries as well.

I also added a disasm feature so it will walk function by 
function, pulling the bytes and disassembling them. Just 
press enter to continue the dump.

Since this doesnt rely on PE foramt at all, you can use this
to pull any exectuable code. This is expecially useful when
trying to find payloads in memory. 

Forget dumping the whole heap... This walks the heap range 
and checks for code period, no BS. 

Same with the base address range. It will walk the common
image base address range and search for code. It does find 
an MZ header. But you can use this as more of a sanity 
check if your reversing some weird code.

Use Glyph's !var command to dump all sections and confirm
your walker is working correctly. Easiest way to find out 
if its working is compare the .text addresses.

the first section is 99.9 percent of the time loaded at 
exactly 0x1000 after the base address in memory. Dont
worry, this does not rely on that at all. It searches 
for actual code and the .text just so happens to be the
very first code after the base address.



