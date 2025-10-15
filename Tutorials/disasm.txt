
SPOTTING A MALICOUS FUNCTION:
=============================

Glyph.exe -c <ProcName>

!imports - Load IAT

!var - Get .text address

!dump / start clip - Disasm the .text address

```bash
0x7ff662e61000: mov     qword ptr [rsp + 8], rcx
0x7ff662e61005: sub     rsp, 0x58
0x7ff662e61009: mov     dword ptr [rsp + 0x20], 0x40
0x7ff662e61011: mov     r9d, 0x3000
0x7ff662e61017: mov     r8d, 0x2000
0x7ff662e6101d: xor     edx, edx
0x7ff662e6101f: mov     rcx, qword ptr [rsp + 0x60]
VirtualAllocEx -> 0x7ffa0f4d34e0:       call    qword ptr [rip + 0x15ffe]
0x7ff662e61024: call    qword ptr [rip + 0x15ffe]
0x7ff662e6102a: mov     qword ptr [rsp + 0x40], rax
0x7ff662e6102f: cmp     qword ptr [rsp + 0x40], 0
0x7ff662e61035: jne     0x7ff662e61055
GetLastError -> 0x7ffa0f4a8640: call    qword ptr [rip + 0x15fc3]
0x7ff662e61037: call    qword ptr [rip + 0x15fc3]
0x7ff662e6103d: mov     edx, eax
0x7ff662e6103f: lea     rcx, [rip + 0x225c2]
0x7ff662e61046: call    0x7ff662e61380
0x7ff662e6104b: mov     eax, 1
0x7ff662e61050: jmp     0x7ff662e6112b
0x7ff662e61055: mov     eax, dword ptr [rip + 0x225a5]
0x7ff662e6105b: mov     qword ptr [rsp + 0x20], 0
0x7ff662e61064: mov     r9d, eax
0x7ff662e61067: lea     r8, [rip + 0x20f92]
0x7ff662e6106e: mov     rdx, qword ptr [rsp + 0x40]
0x7ff662e61073: mov     rcx, qword ptr [rsp + 0x60]
WriteProcessMemory -> 0x7ffa0f4d0b60:   call    qword ptr [rip + 0x15fb2]
0x7ff662e61078: call    qword ptr [rip + 0x15fb2]
0x7ff662e6107e: test    eax, eax
0x7ff662e61080: jne     0x7ff662e610a0
GetLastError -> 0x7ffa0f4a8640: call    qword ptr [rip + 0x15f78]
0x7ff662e61082: call    qword ptr [rip + 0x15f78]
0x7ff662e61088: mov     edx, eax
0x7ff662e6108a: lea     rcx, [rip + 0x22597]
0x7ff662e61091: call    0x7ff662e61380
0x7ff662e61096: mov     eax, 1
0x7ff662e6109b: jmp     0x7ff662e6112b
0x7ff662e610a0: mov     eax, dword ptr [rip + 0x2255e]
0x7ff662e610a6: mov     rcx, qword ptr [rsp + 0x40]
0x7ff662e610ab: add     rcx, rax
0x7ff662e610ae: mov     rax, rcx
0x7ff662e610b1: mov     qword ptr [rsp + 0x30], 0
0x7ff662e610ba: mov     dword ptr [rsp + 0x28], 0
0x7ff662e610c2: mov     qword ptr [rsp + 0x20], 0
0x7ff662e610cb: mov     r9, rax
0x7ff662e610ce: xor     r8d, r8d
0x7ff662e610d1: xor     edx, edx
0x7ff662e610d3: mov     rcx, qword ptr [rsp + 0x60]
CreateRemoteThread -> 0x7ffa0f4d2e10:   call    qword ptr [rip + 0x15f32]
0x7ff662e610d8: call    qword ptr [rip + 0x15f32]
```
