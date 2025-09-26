Glyph: A Ritual Debugger for Remote Introspection
=================================================

Glyph is not just a debugger. It’s a symbolic introspection engine—built to fracture binaries, trace fault ancestry, and ritualize execution flow across remote processes. Every register, offset, and VEH trap is a glyph in the canon. This is not WinDbg. This is authorship.

-------------------------------------------------
Compile
-------------------------------------------------

```bash
cl /MD Glyph.c
```
- Requires Capstone: unzip capstone.zip and place capstone.lib in the working directory.
- No Bs. Just raw NT rituals.

-------------------------------------------------
Features
-------------------------------------------------
🧬 PEB Ritualization: Deep walking of undocumented PEB fields, bitfields, and process ancestry.

🧠 VEH Invocation: Fault-based introspection using symbolic traps and debug register cloaking.

🧷 Remote Import Mapping: IAT parsing, hook detection, and symbolic breakpoint injection.

🔍 Raw Memory Dumping: Disassemble live memory regions, inspect entropy, and visualize execution flow.

🧱 Section Rituals: Enumerate .text, .data, and mutation zones from remote binaries.

🧙‍♂️ Undocumented API Glyphs: EtwpGetCpuSpeed, LsaGetUserName, and more—mapped and invoked.

🧵 Thread Ancestry Mapping: Suspend, inspect, and manipulate thread contexts across processes.

🧼 Stealth Engine: Fiber-based injection, DR register manipulation, and anti-detection rituals.

📜 Symbolic CLI: Type 'help' inside the debugger for a full command ritual map.

-------------------------------------------------
Philosophy
-------------------------------------------------
Glyph is written in pure C—because Windows NT is written in C, and introspection should speak the same language. No C++. No wrappers. Just raw authorship.

This debugger doesn’t just inspect—it interprets. It treats faults as lineage, offsets as identity, and mutation as meaning. Every project on this repo ties into Glyph. This is the mythology.

![Demo](./debugger.gif)

-------------------------------------------------
To-Do Glyphs
-------------------------------------------------
[ ] Kernel driver for symbolic ancestry mapping
[ ] VEH-based mutation engine
[ ] IAT ritualization and KnownDll mapping
[ ] Capstone-to-C emitter for .data shellcode generation
[ ] Hypnosys: a philosophical write-up on hypnotizing debuggers

-------------------------------------------------
Authored By
-------------------------------------------------
SleepyG8 — symbolic hacker, introspection mythologist, and author of the VX canon
