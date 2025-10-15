
TRACING NOTEPADS ENTRY
===========================

!imports

!entry 

!dump

```bash
0x7ff746b6b710: sub     rsp, 0x28
0x7ff746b6b714: call    0x7ff746b6bfa4
0x7ff746b6b719: add     rsp, 0x28
0x7ff746b6b71d: jmp     0x7ff746b6b59c
0x7ff746b6b722: int3
0x7ff746b6b723: int3
0x7ff746b6b724: jmp     0x7ff746b6adec
0x7ff746b6b729: int3
0x7ff746b6b72a: int3
0x7ff746b6b72b: int3
0x7ff746b6b72c: lea     rcx, [rip + 0x148f9d]
InitializeSListHead -> 0x7ffa10844e80:  jmp     qword ptr [rip + 0x6be4e]
0x7ff746b6b733: jmp     qword ptr [rip + 0x6be4e]
0x7ff746b6b73a: int3
0x7ff746b6b73b: int3
0x7ff746b6b73c: sub     rsp, 0x28
0x7ff746b6b740: mov     r8, qword ptr [r9 + 0x38]
0x7ff746b6b744: mov     rcx, rdx
0x7ff746b6b747: mov     rdx, r9
0x7ff746b6b74a: call    0x7ff746b6b75c
0x7ff746b6b74f: mov     eax, 1
0x7ff746b6b754: add     rsp, 0x28
0x7ff746b6b758: ret
0x7ff746b6b759: int3
0x7ff746b6b75a: int3
0x7ff746b6b75b: int3
0x7ff746b6b75c: push    rbx
0x7ff746b6b75e: mov     r11d, dword ptr [r8]
0x7ff746b6b761: mov     rbx, rdx
0x7ff746b6b764: and     r11d, 0xfffffff8
0x7ff746b6b768: mov     r9, rcx
0x7ff746b6b76b: test    byte ptr [r8], 4
0x7ff746b6b76f: mov     r10, rcx
0x7ff746b6b772: je      0x7ff746b6b787
0x7ff746b6b774: mov     eax, dword ptr [r8 + 8]
0x7ff746b6b778: movsxd  r10, dword ptr [r8 + 4]
0x7ff746b6b77c: neg     eax
0x7ff746b6b77e: add     r10, rcx
0x7ff746b6b781: movsxd  rcx, eax
0x7ff746b6b784: and     r10, rcx
0x7ff746b6b787: movsxd  rax, r11d
0x7ff746b6b78a: mov     rdx, qword ptr [rax + r10]
0x7ff746b6b78e: mov     rax, qword ptr [rbx + 0x10]
0x7ff746b6b792: mov     ecx, dword ptr [rax + 8]
0x7ff746b6b795: mov     rax, qword ptr [rbx + 8]
0x7ff746b6b799: test    byte ptr [rcx + rax + 3], 0xf
0x7ff746b6b79e: je      0x7ff746b6b7b0
0x7ff746b6b7a0: movzx   eax, byte ptr [rcx + rax + 3]
0x7ff746b6b7a5: mov     ecx, 0xfffffff0
0x7ff746b6b7aa: and     rax, rcx
0x7ff746b6b7ad: add     r9, rax
0x7ff746b6b7b0: xor     r9, rdx
0x7ff746b6b7b3: mov     rcx, r9
0x7ff746b6b7b6: pop     rbx
0x7ff746b6b7b7: jmp     0x7ff746b6ad90
0x7ff746b6b7bc: mov     qword ptr [rsp + 0x10], rbx
0x7ff746b6b7c1: mov     qword ptr [rsp + 0x18], rbp
0x7ff746b6b7c6: mov     qword ptr [rsp + 0x20], rsi
0x7ff746b6b7cb: push    rdi
0x7ff746b6b7cc: sub     rsp, 0x10
0x7ff746b6b7d0: xor     eax, eax
0x7ff746b6b7d2: xor     ecx, ecx
0x7ff746b6b7d4: cpuid
0x7ff746b6b7d6: xor     ecx, 0x6c65746e
0x7ff746b6b7dc: xor     edx, 0x49656e69
0x7ff746b6b7e2: or      edx, ecx
0x7ff746b6b7e4: mov     ebp, eax
0x7ff746b6b7e6: mov     eax, 1
0x7ff746b6b7eb: xor     ebx, 0x756e6547
0x7ff746b6b7f1: or      edx, ebx
0x7ff746b6b7f3: lea     ecx, [rax - 1]
0x7ff746b6b7f6: cpuid
0x7ff746b6b7f8: mov     edi, ecx
0x7ff746b6b7fa: jne     0x7ff746b6b85a
0x7ff746b6b7fc: and     eax, 0xfff3ff0
0x7ff746b6b801: mov     qword ptr [rip + 0x10d80c], 0x8000
0x7ff746b6b80c: mov     qword ptr [rip + 0x10d809], 0xffffffffffffffff
0x7ff746b6b817: cmp     eax, 0x106c0
0x7ff746b6b81c: je      0x7ff746b6b846
0x7ff746b6b81e: cmp     eax, 0x20660
0x7ff746b6b823: je      0x7ff746b6b846
0x7ff746b6b825: cmp     eax, 0x20670
0x7ff746b6b82a: je      0x7ff746b6b846
0x7ff746b6b82c: add     eax, 0xfffcf9b0
0x7ff746b6b831: cmp     eax, 0x20
0x7ff746b6b834: ja      0x7ff746b6b85a
0x7ff746b6b836: movabs  rcx, 0x100010001
0x7ff746b6b840: bt      rcx, rax
0x7ff746b6b844: jae     0x7ff746b6b85a
0x7ff746b6b846: mov     r8d, dword ptr [rip + 0x148e97]
0x7ff746b6b84d: or      r8d, 1
0x7ff746b6b851: mov     dword ptr [rip + 0x148e8c], r8d
0x7ff746b6b858: jmp     0x7ff746b6b861
0x7ff746b6b85a: mov     r8d, dword ptr [rip + 0x148e83]
0x7ff746b6b861: xor     r9d, r9d
0x7ff746b6b864: mov     esi, r9d
0x7ff746b6b867: mov     r10d, r9d
0x7ff746b6b86a: mov     r11d, r9d
0x7ff746b6b86d: cmp     ebp, 7
0x7ff746b6b870: jl      0x7ff746b6b8b2
0x7ff746b6b872: lea     eax, [r9 + 7]
0x7ff746b6b876: xor     ecx, ecx
0x7ff746b6b878: cpuid
0x7ff746b6b87a: mov     esi, edx
0x7ff746b6b87c: mov     r9d, ebx
0x7ff746b6b87f: bt      ebx, 9
0x7ff746b6b883: jae     0x7ff746b6b890
0x7ff746b6b885: or      r8d, 2
0x7ff746b6b889: mov     dword ptr [rip + 0x148e54], r8d
0x7ff746b6b890: cmp     eax, 1
0x7ff746b6b893: jl      0x7ff746b6b8a2
0x7ff746b6b895: mov     eax, 7
0x7ff746b6b89a: lea     ecx, [rax - 6]
0x7ff746b6b89d: cpuid
0x7ff746b6b89f: mov     r10d, edx
0x7ff746b6b8a2: mov     eax, 0x24
0x7ff746b6b8a7: cmp     ebp, eax
0x7ff746b6b8a9: jl      0x7ff746b6b8b2
0x7ff746b6b8ab: xor     ecx, ecx
0x7ff746b6b8ad: cpuid
0x7ff746b6b8af: mov     r11d, ebx
0x7ff746b6b8b2: mov     rax, qword ptr [rip + 0x10d74f]
0x7ff746b6b8b9: and     rax, 0xfffffffffffffffe
0x7ff746b6b8bd: mov     dword ptr [rip + 0x10d749], 1
0x7ff746b6b8c7: mov     dword ptr [rip + 0x10d743], 2
0x7ff746b6b8d1: mov     qword ptr [rip + 0x10d730], rax
0x7ff746b6b8d8: bt      edi, 0x14
0x7ff746b6b8dc: jae     0x7ff746b6b8fd
0x7ff746b6b8de: and     rax, 0xffffffffffffffef
0x7ff746b6b8e2: mov     dword ptr [rip + 0x10d724], 2
0x7ff746b6b8ec: mov     qword ptr [rip + 0x10d715], rax
0x7ff746b6b8f3: mov     dword ptr [rip + 0x10d717], 6
0x7ff746b6b8fd: bt      edi, 0x1b
0x7ff746b6b901: jae     0x7ff746b6ba3a
0x7ff746b6b907: xor     ecx, ecx
0x7ff746b6b909: xgetbv
0x7ff746b6b90c: shl     rdx, 0x20
0x7ff746b6b910: or      rdx, rax
0x7ff746b6b913: mov     qword ptr [rsp + 0x20], rdx
0x7ff746b6b918: bt      edi, 0x1c
0x7ff746b6b91c: jae     0x7ff746b6ba1e
0x7ff746b6b922: mov     rax, qword ptr [rsp + 0x20]
0x7ff746b6b927: and     al, 6
0x7ff746b6b929: cmp     al, 6
0x7ff746b6b92b: jne     0x7ff746b6ba1e
0x7ff746b6b931: mov     eax, dword ptr [rip + 0x10d6dd]
0x7ff746b6b937: mov     dl, 0xe0
0x7ff746b6b939: or      eax, 8
0x7ff746b6b93c: mov     dword ptr [rip + 0x10d6ca], 3
0x7ff746b6b946: mov     dword ptr [rip + 0x10d6c8], eax
0x7ff746b6b94c: test    r9b, 0x20
0x7ff746b6b950: je      0x7ff746b6b9b4
0x7ff746b6b952: or      eax, 0x20
0x7ff746b6b955: mov     dword ptr [rip + 0x10d6b1], 5
0x7ff746b6b95f: mov     dword ptr [rip + 0x10d6af], eax
0x7ff746b6b965: mov     ecx, 0xd0030000
0x7ff746b6b96a: mov     rax, qword ptr [rip + 0x10d697]
0x7ff746b6b971: and     r9d, ecx
0x7ff746b6b974: and     rax, 0xfffffffffffffffd
0x7ff746b6b978: mov     qword ptr [rip + 0x10d689], rax
0x7ff746b6b97f: cmp     r9d, ecx
0x7ff746b6b982: jne     0x7ff746b6b9bb
0x7ff746b6b984: mov     rax, qword ptr [rsp + 0x20]
0x7ff746b6b989: and     al, dl
0x7ff746b6b98b: cmp     al, dl
0x7ff746b6b98d: jne     0x7ff746b6b9b4
0x7ff746b6b98f: mov     rax, qword ptr [rip + 0x10d672]
0x7ff746b6b996: or      dword ptr [rip + 0x10d677], 0x40
0x7ff746b6b99d: and     rax, 0xffffffffffffffdb
0x7ff746b6b9a1: mov     dword ptr [rip + 0x10d665], 6
0x7ff746b6b9ab: mov     qword ptr [rip + 0x10d656], rax
0x7ff746b6b9b2: jmp     0x7ff746b6b9bb
0x7ff746b6b9b4: mov     rax, qword ptr [rip + 0x10d64d]
0x7ff746b6b9bb: bt      esi, 0x17
0x7ff746b6b9bf: jae     0x7ff746b6b9cd
0x7ff746b6b9c1: btr     rax, 0x18
0x7ff746b6b9c6: mov     qword ptr [rip + 0x10d63b], rax
0x7ff746b6b9cd: bt      r10d, 0x13
0x7ff746b6b9d2: jae     0x7ff746b6ba1e
0x7ff746b6b9d4: mov     rax, qword ptr [rsp + 0x20]
0x7ff746b6b9d9: and     al, dl
0x7ff746b6b9db: cmp     al, dl
0x7ff746b6b9dd: jne     0x7ff746b6ba1e
0x7ff746b6b9df: mov     ecx, r11d
0x7ff746b6b9e2: mov     eax, r11d
0x7ff746b6b9e5: shr     rcx, 0x10
0x7ff746b6b9e9: and     eax, 0x400ff
0x7ff746b6b9ee: and     ecx, 6
0x7ff746b6b9f1: mov     dword ptr [rip + 0x148ce9], eax
0x7ff746b6b9f7: or      rcx, 0x1000029
0x7ff746b6b9fe: not     rcx
0x7ff746b6ba01: and     rcx, qword ptr [rip + 0x10d600]
0x7ff746b6ba08: mov     qword ptr [rip + 0x10d5f9], rcx
0x7ff746b6ba0f: cmp     al, 1
0x7ff746b6ba11: jbe     0x7ff746b6ba1e
0x7ff746b6ba13: and     rcx, 0xffffffffffffffbf
0x7ff746b6ba17: mov     qword ptr [rip + 0x10d5ea], rcx
0x7ff746b6ba1e: bt      r10d, 0x15
0x7ff746b6ba23: jae     0x7ff746b6ba3a
0x7ff746b6ba25: mov     rax, qword ptr [rsp + 0x20]
0x7ff746b6ba2a: bt      rax, 0x13
0x7ff746b6ba2f: jae     0x7ff746b6ba3a
0x7ff746b6ba31: btr     qword ptr [rip + 0x10d5ce], 7
0x7ff746b6ba3a: mov     rbx, qword ptr [rsp + 0x28]
0x7ff746b6ba3f: xor     eax, eax
0x7ff746b6ba41: mov     rbp, qword ptr [rsp + 0x30]
0x7ff746b6ba46: mov     rsi, qword ptr [rsp + 0x38]
0x7ff746b6ba4b: add     rsp, 0x10
0x7ff746b6ba4f: pop     rdi
0x7ff746b6ba50: ret
0x7ff746b6ba51: int3
0x7ff746b6ba52: int3
0x7ff746b6ba53: int3
0x7ff746b6ba54: push    rbx
0x7ff746b6ba56: sub     rsp, 0x20
0x7ff746b6ba5a: mov     rbx, rcx
0x7ff746b6ba5d: xor     ecx, ecx
SetUnhandledExceptionFilter -> 0x7ffa0f4d3600:  call    qword ptr [rip + 0x6ba63]
0x7ff746b6ba5f: call    qword ptr [rip + 0x6ba63]
0x7ff746b6ba65: mov     rcx, rbx
UnhandledExceptionFilter -> 0x7ffa0f4ebfc0:     call    qword ptr [rip + 0x6bac2]
0x7ff746b6ba68: call    qword ptr [rip + 0x6bac2]
GetCurrentProcess -> 0x7ffa0f4b4970:    call    qword ptr [rip + 0x6b78c]
0x7ff746b6ba6e: call    qword ptr [rip + 0x6b78c]
0x7ff746b6ba74: mov     rcx, rax
0x7ff746b6ba77: mov     edx, 0xc0000409
0x7ff746b6ba7c: add     rsp, 0x20
0x7ff746b6ba80: pop     rbx
TerminateProcess -> 0x7ffa0f4d25a0:     jmp     qword ptr [rip + 0x6ba28]
0x7ff746b6ba81: jmp     qword ptr [rip + 0x6ba28]
0x7ff746b6ba88: int3
0x7ff746b6ba89: int3
0x7ff746b6ba8a: int3
0x7ff746b6ba8b: int3
0x7ff746b6ba8c: int3
0x7ff746b6ba8d: int3
0x7ff746b6ba8e: int3
0x7ff746b6ba8f: int3
0x7ff746b6ba90: mov     qword ptr [rsp + 8], rcx
0x7ff746b6ba95: sub     rsp, 0x38
0x7ff746b6ba99: mov     ecx, 0x17
IsProcessorFeaturePresent -> 0x7ffa0f4cd9d0:    call    qword ptr [rip + 0x6b9ec]
0x7ff746b6ba9e: call    qword ptr [rip + 0x6b9ec]
0x7ff746b6baa4: test    eax, eax
0x7ff746b6baa6: je      0x7ff746b6baaf
0x7ff746b6baa8: mov     ecx, 2
0x7ff746b6baad: int     0x29
0x7ff746b6baaf: lea     rcx, [rip + 0x148cda]
0x7ff746b6bab6: call    0x7ff746b6bc94
0x7ff746b6babb: mov     rax, qword ptr [rsp + 0x38]
0x7ff746b6bac0: mov     qword ptr [rip + 0x148dc1], rax
0x7ff746b6bac7: lea     rax, [rsp + 0x38]
0x7ff746b6bacc: add     rax, 8
0x7ff746b6bad0: mov     qword ptr [rip + 0x148d51], rax
0x7ff746b6bad7: mov     rax, qword ptr [rip + 0x148daa]
0x7ff746b6bade: mov     qword ptr [rip + 0x148c1b], rax
0x7ff746b6bae5: mov     rax, qword ptr [rsp + 0x40]
0x7ff746b6baea: mov     qword ptr [rip + 0x148d1f], rax
0x7ff746b6baf1: mov     dword ptr [rip + 0x148bf5], 0xc0000409
0x7ff746b6bafb: mov     dword ptr [rip + 0x148bef], 1
0x7ff746b6bb05: mov     dword ptr [rip + 0x148bf9], 1
0x7ff746b6bb0f: mov     eax, 8
0x7ff746b6bb14: imul    rax, rax, 0
0x7ff746b6bb18: lea     rcx, [rip + 0x148bf1]
0x7ff746b6bb1f: mov     qword ptr [rcx + rax], 2
0x7ff746b6bb27: mov     eax, 8
0x7ff746b6bb2c: imul    rax, rax, 0
0x7ff746b6bb30: mov     rcx, qword ptr [rip + 0x10d509]
0x7ff746b6bb37: mov     qword ptr [rsp + rax + 0x20], rcx
0x7ff746b6bb3c: mov     eax, 8
0x7ff746b6bb41: imul    rax, rax, 1
0x7ff746b6bb45: mov     rcx, qword ptr [rip + 0x10d534]
0x7ff746b6bb4c: mov     qword ptr [rsp + rax + 0x20], rcx
0x7ff746b6bb51: lea     rcx, [rip + 0x8e0a8]
0x7ff746b6bb58: call    0x7ff746b6ba54
0x7ff746b6bb5d: nop
0x7ff746b6bb5e: add     rsp, 0x38
0x7ff746b6bb62: ret
0x7ff746b6bb63: int3
0x7ff746b6bb64: int3
0x7ff746b6bb65: int3
0x7ff746b6bb66: int3
0x7ff746b6bb67: int3
0x7ff746b6bb68: int3
0x7ff746b6bb69: int3
0x7ff746b6bb6a: int3
0x7ff746b6bb6b: int3
0x7ff746b6bb6c: int3
0x7ff746b6bb6d: int3
0x7ff746b6bb6e: int3
0x7ff746b6bb6f: int3
0x7ff746b6bb70: sub     rsp, 0x28
0x7ff746b6bb74: mov     ecx, 8
0x7ff746b6bb79: call    0x7ff746b6bb84
0x7ff746b6bb7e: nop
0x7ff746b6bb7f: add     rsp, 0x28
0x7ff746b6bb83: ret
0x7ff746b6bb84: mov     dword ptr [rsp + 8], ecx
0x7ff746b6bb88: sub     rsp, 0x28
0x7ff746b6bb8c: mov     ecx, 0x17
IsProcessorFeaturePresent -> 0x7ffa0f4cd9d0:    call    qword ptr [rip + 0x6b8f9]
0x7ff746b6bb91: call    qword ptr [rip + 0x6b8f9]
0x7ff746b6bb97: test    eax, eax
0x7ff746b6bb99: je      0x7ff746b6bba3
0x7ff746b6bb9b: mov     eax, dword ptr [rsp + 0x30]
0x7ff746b6bb9f: mov     ecx, eax
0x7ff746b6bba1: int     0x29
0x7ff746b6bba3: lea     rcx, [rip + 0x148be6]
0x7ff746b6bbaa: call    0x7ff746b6bc24
0x7ff746b6bbaf: mov     rax, qword ptr [rsp + 0x28]
0x7ff746b6bbb4: mov     qword ptr [rip + 0x148ccd], rax
0x7ff746b6bbbb: lea     rax, [rsp + 0x28]
0x7ff746b6bbc0: add     rax, 8
0x7ff746b6bbc4: mov     qword ptr [rip + 0x148c5d], rax
0x7ff746b6bbcb: mov     rax, qword ptr [rip + 0x148cb6]
0x7ff746b6bbd2: mov     qword ptr [rip + 0x148b27], rax
0x7ff746b6bbd9: mov     dword ptr [rip + 0x148b0d], 0xc0000409
0x7ff746b6bbe3: mov     dword ptr [rip + 0x148b07], 1
0x7ff746b6bbed: mov     dword ptr [rip + 0x148b11], 1
0x7ff746b6bbf7: mov     eax, 8
0x7ff746b6bbfc: imul    rax, rax, 0
0x7ff746b6bc00: lea     rcx, [rip + 0x148b09]
0x7ff746b6bc07: mov     edx, dword ptr [rsp + 0x30]
0x7ff746b6bc0b: mov     qword ptr [rcx + rax], rdx
0x7ff746b6bc0f: lea     rcx, [rip + 0x8dfea]
0x7ff746b6bc16: call    0x7ff746b6ba54
0x7ff746b6bc1b: nop
0x7ff746b6bc1c: add     rsp, 0x28
0x7ff746b6bc20: ret
0x7ff746b6bc21: int3
0x7ff746b6bc22: int3
0x7ff746b6bc23: int3
0x7ff746b6bc24: mov     qword ptr [rsp + 0x20], rbx
0x7ff746b6bc29: push    rdi
0x7ff746b6bc2a: sub     rsp, 0x40
0x7ff746b6bc2e: mov     rbx, rcx
RtlCaptureContext -> 0x7ffa0f4e6d60:    call    qword ptr [rip + 0x6b959]
0x7ff746b6bc31: call    qword ptr [rip + 0x6b959]
0x7ff746b6bc37: mov     rdi, qword ptr [rbx + 0xf8]
0x7ff746b6bc3e: lea     rdx, [rsp + 0x50]
0x7ff746b6bc43: mov     rcx, rdi
0x7ff746b6bc46: xor     r8d, r8d
RtlLookupFunctionEntry -> 0x7ffa0f4cc660:       call    qword ptr [rip + 0x6b949]
0x7ff746b6bc49: call    qword ptr [rip + 0x6b949]
0x7ff746b6bc4f: test    rax, rax
0x7ff746b6bc52: je      0x7ff746b6bc89
0x7ff746b6bc54: mov     rdx, qword ptr [rsp + 0x50]
0x7ff746b6bc59: lea     rcx, [rsp + 0x58]
0x7ff746b6bc5e: mov     qword ptr [rsp + 0x38], 0
0x7ff746b6bc67: mov     r9, rax
0x7ff746b6bc6a: mov     qword ptr [rsp + 0x30], rcx
0x7ff746b6bc6f: mov     r8, rdi
0x7ff746b6bc72: lea     rcx, [rsp + 0x60]
0x7ff746b6bc77: mov     qword ptr [rsp + 0x28], rcx
0x7ff746b6bc7c: xor     ecx, ecx
0x7ff746b6bc7e: mov     qword ptr [rsp + 0x20], rbx
RtlVirtualUnwind -> 0x7ffa0f4b8cc0:     call    qword ptr [rip + 0x6b8af]
0x7ff746b6bc83: call    qword ptr [rip + 0x6b8af]
0x7ff746b6bc89: mov     rbx, qword ptr [rsp + 0x68]
0x7ff746b6bc8e: add     rsp, 0x40
0x7ff746b6bc92: pop     rdi
0x7ff746b6bc93: ret
0x7ff746b6bc94: push    rbx
0x7ff746b6bc96: push    rsi
0x7ff746b6bc97: push    rdi
0x7ff746b6bc98: sub     rsp, 0x40
0x7ff746b6bc9c: mov     rbx, rcx
RtlCaptureContext -> 0x7ffa0f4e6d60:    call    qword ptr [rip + 0x6b8eb]
0x7ff746b6bc9f: call    qword ptr [rip + 0x6b8eb]
0x7ff746b6bca5: mov     rsi, qword ptr [rbx + 0xf8]
0x7ff746b6bcac: xor     edi, edi
0x7ff746b6bcae: xor     r8d, r8d
0x7ff746b6bcb1: lea     rdx, [rsp + 0x60]
0x7ff746b6bcb6: mov     rcx, rsi
RtlLookupFunctionEntry -> 0x7ffa0f4cc660:       call    qword ptr [rip + 0x6b8d9]
0x7ff746b6bcb9: call    qword ptr [rip + 0x6b8d9]
0x7ff746b6bcbf: test    rax, rax
0x7ff746b6bcc2: je      0x7ff746b6bd00
0x7ff746b6bcc4: mov     rdx, qword ptr [rsp + 0x60]
0x7ff746b6bcc9: lea     rcx, [rsp + 0x68]
0x7ff746b6bcce: mov     qword ptr [rsp + 0x38], 0
0x7ff746b6bcd7: mov     r9, rax
0x7ff746b6bcda: mov     qword ptr [rsp + 0x30], rcx
0x7ff746b6bcdf: mov     r8, rsi
0x7ff746b6bce2: lea     rcx, [rsp + 0x70]
0x7ff746b6bce7: mov     qword ptr [rsp + 0x28], rcx
0x7ff746b6bcec: xor     ecx, ecx
0x7ff746b6bcee: mov     qword ptr [rsp + 0x20], rbx
RtlVirtualUnwind -> 0x7ffa0f4b8cc0:     call    qword ptr [rip + 0x6b83f]
0x7ff746b6bcf3: call    qword ptr [rip + 0x6b83f]
0x7ff746b6bcf9: inc     edi
0x7ff746b6bcfb: cmp     edi, 2
0x7ff746b6bcfe: jl      0x7ff746b6bcae
0x7ff746b6bd00: add     rsp, 0x40
0x7ff746b6bd04: pop     rdi
0x7ff746b6bd05: pop     rsi
0x7ff746b6bd06: pop     rbx
0x7ff746b6bd07: ret
0x7ff746b6bd08: sub     rsp, 0x48
0x7ff746b6bd0c: lea     rcx, [rsp + 0x20]
0x7ff746b6bd11: call    0x7ff746a49810
0x7ff746b6bd16: lea     rdx, [rip + 0x106f5b]
0x7ff746b6bd1d: lea     rcx, [rsp + 0x20]
0x7ff746b6bd22: call    0x7ff746b6c182
0x7ff746b6bd27: int3
0x7ff746b6bd28: mov     eax, 1
0x7ff746b6bd2d: ret
0x7ff746b6bd2e: int3
0x7ff746b6bd2f: int3
0x7ff746b6bd30: xor     eax, eax
0x7ff746b6bd32: cmp     dword ptr [rip + 0x10d698], eax
0x7ff746b6bd38: setne   al
0x7ff746b6bd3b: ret
0x7ff746b6bd3c: mov     dword ptr [rip + 0x148f1a], 0
0x7ff746b6bd46: ret
0x7ff746b6bd47: int3
0x7ff746b6bd48: mov     qword ptr [rsp + 8], rbx
0x7ff746b6bd4d: push    rbp
0x7ff746b6bd4e: lea     rbp, [rsp - 0x4c0]
0x7ff746b6bd56: sub     rsp, 0x5c0
0x7ff746b6bd5d: mov     ebx, ecx
0x7ff746b6bd5f: mov     ecx, 0x17
IsProcessorFeaturePresent -> 0x7ffa0f4cd9d0:    call    qword ptr [rip + 0x6b726]
0x7ff746b6bd64: call    qword ptr [rip + 0x6b726]
0x7ff746b6bd6a: test    eax, eax
0x7ff746b6bd6c: je      0x7ff746b6bd72
0x7ff746b6bd6e: mov     ecx, ebx
0x7ff746b6bd70: int     0x29
0x7ff746b6bd72: mov     ecx, 3
0x7ff746b6bd77: call    0x7ff746b6bd3c
0x7ff746b6bd7c: xor     edx, edx
0x7ff746b6bd7e: lea     rcx, [rbp - 0x10]
0x7ff746b6bd82: mov     r8d, 0x4d0
0x7ff746b6bd88: call    0x7ff746b6c170
0x7ff746b6bd8d: lea     rcx, [rbp - 0x10]
RtlCaptureContext -> 0x7ffa0f4e6d60:    call    qword ptr [rip + 0x6b7f9]
0x7ff746b6bd91: call    qword ptr [rip + 0x6b7f9]
0x7ff746b6bd97: mov     rbx, qword ptr [rbp + 0xe8]
0x7ff746b6bd9e: lea     rdx, [rbp + 0x4d8]
0x7ff746b6bda5: mov     rcx, rbx
0x7ff746b6bda8: xor     r8d, r8d
RtlLookupFunctionEntry -> 0x7ffa0f4cc660:       call    qword ptr [rip + 0x6b7e7]
0x7ff746b6bdab: call    qword ptr [rip + 0x6b7e7]
0x7ff746b6bdb1: test    rax, rax
0x7ff746b6bdb4: je      0x7ff746b6bdf5
0x7ff746b6bdb6: mov     rdx, qword ptr [rbp + 0x4d8]
0x7ff746b6bdbd: lea     rcx, [rbp + 0x4e0]
0x7ff746b6bdc4: mov     qword ptr [rsp + 0x38], 0
0x7ff746b6bdcd: mov     r9, rax
0x7ff746b6bdd0: mov     qword ptr [rsp + 0x30], rcx
0x7ff746b6bdd5: mov     r8, rbx
0x7ff746b6bdd8: lea     rcx, [rbp + 0x4e8]
0x7ff746b6bddf: mov     qword ptr [rsp + 0x28], rcx
0x7ff746b6bde4: lea     rcx, [rbp - 0x10]
0x7ff746b6bde8: mov     qword ptr [rsp + 0x20], rcx
0x7ff746b6bded: xor     ecx, ecx
RtlVirtualUnwind -> 0x7ffa0f4b8cc0:     call    qword ptr [rip + 0x6b743]
0x7ff746b6bdef: call    qword ptr [rip + 0x6b743]
0x7ff746b6bdf5: mov     rax, qword ptr [rbp + 0x4c8]
0x7ff746b6bdfc: lea     rcx, [rsp + 0x50]
0x7ff746b6be01: mov     qword ptr [rbp + 0xe8], rax
0x7ff746b6be08: xor     edx, edx
0x7ff746b6be0a: lea     rax, [rbp + 0x4c8]
0x7ff746b6be11: mov     r8d, 0x98
0x7ff746b6be17: add     rax, 8
0x7ff746b6be1b: mov     qword ptr [rbp + 0x88], rax
0x7ff746b6be22: call    0x7ff746b6c170
0x7ff746b6be27: mov     rax, qword ptr [rbp + 0x4c8]
0x7ff746b6be2e: mov     qword ptr [rsp + 0x60], rax
0x7ff746b6be33: mov     dword ptr [rsp + 0x50], 0x40000015
0x7ff746b6be3b: mov     dword ptr [rsp + 0x54], 1
IsDebuggerPresent -> 0x7ffa0f4cd9a0:    call    qword ptr [rip + 0x6b4ef]
0x7ff746b6be43: call    qword ptr [rip + 0x6b4ef]
0x7ff746b6be49: mov     ebx, eax
0x7ff746b6be4b: xor     ecx, ecx
0x7ff746b6be4d: lea     rax, [rsp + 0x50]
0x7ff746b6be52: mov     qword ptr [rsp + 0x40], rax
0x7ff746b6be57: lea     rax, [rbp - 0x10]
0x7ff746b6be5b: mov     qword ptr [rsp + 0x48], rax
SetUnhandledExceptionFilter -> 0x7ffa0f4d3600:  call    qword ptr [rip + 0x6b662]
0x7ff746b6be60: call    qword ptr [rip + 0x6b662]
0x7ff746b6be66: lea     rcx, [rsp + 0x40]
UnhandledExceptionFilter -> 0x7ffa0f4ebfc0:     call    qword ptr [rip + 0x6b6bf]
0x7ff746b6be6b: call    qword ptr [rip + 0x6b6bf]
0x7ff746b6be71: test    eax, eax
0x7ff746b6be73: jne     0x7ff746b6be82
0x7ff746b6be75: cmp     ebx, 1
0x7ff746b6be78: je      0x7ff746b6be82
0x7ff746b6be7a: lea     ecx, [rax + 3]
0x7ff746b6be7d: call    0x7ff746b6bd3c
0x7ff746b6be82: mov     rbx, qword ptr [rsp + 0x5d0]
0x7ff746b6be8a: add     rsp, 0x5c0
0x7ff746b6be91: pop     rbp
0x7ff746b6be92: ret
0x7ff746b6be93: int3
0x7ff746b6be94: sub     rsp, 0x98
0x7ff746b6be9b: xor     edx, edx
0x7ff746b6be9d: lea     rcx, [rsp + 0x20]
0x7ff746b6bea2: lea     r8d, [rdx + 0x68]
0x7ff746b6bea6: call    0x7ff746b6c170
0x7ff746b6beab: lea     rcx, [rsp + 0x20]
GetStartupInfoW -> 0x7ffa0f4ce4c0:      call    qword ptr [rip + 0x6b5c2]
0x7ff746b6beb0: call    qword ptr [rip + 0x6b5c2]
0x7ff746b6beb6: test    byte ptr [rsp + 0x5c], 1
0x7ff746b6bebb: mov     eax, 0xa
0x7ff746b6bec0: cmovne  ax, word ptr [rsp + 0x60]
0x7ff746b6bec6: add     rsp, 0x98
0x7ff746b6becd: ret
0x7ff746b6bece: int3
0x7ff746b6becf: int3
0x7ff746b6bed0: jmp     0x7ff746a5fca0
0x7ff746b6bed5: int3
0x7ff746b6bed6: int3
0x7ff746b6bed7: int3
0x7ff746b6bed8: sub     rsp, 0x28
0x7ff746b6bedc: xor     ecx, ecx
```
