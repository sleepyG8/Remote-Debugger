<h1 align="center">🧠 Glyph - A sneaky debugger</h1>

<p align="center">
  <strong>Advanced low-level debugger designed for remote process analysis, reverse engineering, and research-grade control.</strong><br>
  <a href="https://github.com/sleepyG8/Remote-Debugger/stargazers">
    <img src="https://img.shields.io/github/stars/sleepyG8/Remote-Debugger?style=social" alt="GitHub stars">
  </a>
  <br><br>
  <img src="https://img.shields.io/badge/built%20with-C%20%7C%20WinAPI-blue?style=flat-square">
  <img src="https://img.shields.io/badge/platform-Windows-orange?style=flat-square">
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square">
</p>

---

# Compiling
Compile with cl /MD glyph.c - you must unzip capstone.zip and place capstone.lib into the working directory. This is to correctly build the dissassembler in.

A advanced debugger I wrote capable of debugging remote processes, this is a work in progress and will be updated frequently for more features

The stealth file contains my new POC using fibers to bypass windows protections

this debugger hides itself from the system by using certain low level techniques like modifying dr1-dr6 but leaving dr7 for future hardware breakpoints

I am most proud of my peb implementation as it is undocumented by microsoft and a lot of reading and old examples from 10+ years ago to build this

that being said this is original and I look forward to building this into the next windbg

if you need help with commands run help 

Facts:

(any examples I found were from 2015 and 2008 and written in c++ so I wrote this in C for speed and windows nt apis are written in C so lets keep it native) and windows internals

- Deep PEB walking

- Hides debug registers

- Capable of pulling registers and dumping raw addresses

- Built from scratch

Sleepy :)

To do: 

+A kernel driver in the future to access kernel structures

+IAT inspection just needs added 

