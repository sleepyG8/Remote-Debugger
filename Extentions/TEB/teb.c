#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct _MYPEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
        union {
        BYTE BitField;
        struct {
            BYTE ImageUsesLargePages : 1;
            BYTE IsProtectedProcess : 1;
            BYTE IsImageDynamicallyRelocated : 1;
            BYTE SkipPatchingUser32Forwarders : 1;
            BYTE IsPackagedProcess : 1;
            BYTE IsAppContainer : 1;
            BYTE IsProtectedProcessLight : 1;
            BYTE IsLongPathAwareProcess : 1;
        };
    };
    union {
    ULONG CrossProcessFlags;
    struct {
        ULONG ProcessInJob : 1;
        ULONG ProcessInitializing : 1;
        ULONG ProcessUsingVEH : 1;
        ULONG ProcessUsingVCH : 1;
        ULONG ProcessUsingFTH : 1;
        ULONG ReservedBits0 : 27;
    };
};
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} MYPEB;

MYPEB pbi;

#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _GDI_TEB_BATCH {
    ULONG Offset;                     // Current offset into the buffer
    ULONG_PTR HDC;                    // Handle to the device context
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE]; // Batched GDI commands
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    struct _TEB_ACTIVE_FRAME_CONTEXT *Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct MY_NT_TIB {
    PVOID ExceptionList;        // 0x00
    PVOID StackBase;            // 0x08
    PVOID StackLimit;           // 0x10
    PVOID SubSystemTib;         // 0x18
    PVOID FiberData;            // 0x20  (a.k.a. Version on some docs)
    PVOID ArbitraryUserPointer; // 0x28
    struct _NT_TIB *Self;       // 0x30  <-- must point to TEB base
} MYNT_TIB, *MYPNT_TIB;

typedef struct _MYTEB {
    MYNT_TIB NtTib;                                // Thread Information Block
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    LPVOID ProcessEnvironmentBlock;
} MYTEB, *MYPTEB;

void PrintCommonTEB(MYTEB teb, void* base) {
    printf("TEB base:                  0x%p\n", base);
    printf("  NtTib.Self:              0x%p\n", teb.NtTib.Self);
    printf("  StackBase:               0x%p\n", teb.NtTib.StackBase);
    printf("  StackLimit:              0x%p\n", teb.NtTib.StackLimit);
    printf("  ClientId.Process:        0x%p\n", teb.ClientId.UniqueProcess);
    printf("  ClientId.Thread:         0x%p\n", teb.ClientId.UniqueThread);
    printf("  peb:                     0x%p\n", teb.ProcessEnvironmentBlock);
}

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress; // the goods
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);


__declspec(dllexport) int __stdcall getTEB(HANDLE hProcess, HANDLE thread)  {

    NtQueryInformationThread_t qit = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

   // MYTEB* teb = (MYTEB*)__readgsqword(0x30);

   THREAD_BASIC_INFORMATION tbi;
   
   NTSTATUS status = qit(thread, 0, &tbi, sizeof(tbi), NULL);

   if (!NT_SUCCESS(status)) {
    printf("Status: %lu\n", status);
   };

   MYTEB teb;
   if (!ReadProcessMemory(hProcess, (LPCVOID)tbi.TebBaseAddress, &teb, sizeof(teb), NULL)) {
    printf("Error reading memory %lu\n", GetLastError());
   }


   
   PrintCommonTEB(teb, tbi.TebBaseAddress);

   return 0;
}
