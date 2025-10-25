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
    ULONG Offset;                    
    ULONG_PTR HDC;                    
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
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


typedef struct _MYTEB {
    NT_TIB NtTib;                                
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    MYPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    ULONG CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    LONG ExceptionCode;
    PVOID ActivationContextStackPointer;
    BYTE SpareBytes1[36];
    ULONG TxFsContext;
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID TlsExpansionSlots;
    PVOID ReservedForOle;
    ULONG ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    PVOID CurrentTransactionHandle;
    TEB_ACTIVE_FRAME *ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    USHORT CrossTebFlags;
    USHORT SameTebFlags;
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
} MYTEB, *MYPTEB;

void PrintCommonTEB(MYTEB teb) {
    printf("TEB base:                  0x%p\n", teb);
    printf("  NtTib.Self:              0x%p\n", teb.NtTib.Self);
    printf("  StackBase:               0x%p\n", teb.NtTib.StackBase);
    printf("  StackLimit:              0x%p\n", teb.NtTib.StackLimit);
    printf("  ClientId.Process:        0x%p\n", teb.ClientId.UniqueProcess);
    printf("  ClientId.Thread:         0x%p\n", teb.ClientId.UniqueThread);
    printf("  LastErrorValue:          0x%08X\n", teb.LastErrorValue);
    printf("  TLS Pointer:             0x%p\n", teb.ThreadLocalStoragePointer);
    printf("  TlsSlots[0]:             0x%p\n", teb.TlsSlots[0]);
    printf("  TlsSlots[1]:             0x%p\n", teb.TlsSlots[1]);
    printf("  TlsExpansionSlots:       0x%p\n", teb.TlsExpansionSlots);
    printf("  PEB:                     0x%p\n", teb.ProcessEnvironmentBlock);
    printf("  GdiTebBatch.HDC:         0x%p\n", teb.GdiTebBatch.HDC);
    printf("  GdiTebBatch.Offset:      %lu\n", teb.GdiTebBatch.Offset);
    printf("  ActiveFrame:             0x%p\n", teb.ActiveFrame);
    printf("  FlsData:                 0x%p\n", teb.FlsData);
    printf("  IsImpersonating:         %lu\n", teb.IsImpersonating);
    printf("  StaticUnicodeString:     %ws\n", teb.StaticUnicodeString.Buffer);
}

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress; // ← This is what you want
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

   THREAD_BASIC_INFORMATION tbi;
   
   NTSTATUS status = qit(thread, 0, &tbi, sizeof(tbi), NULL);

   if (!NT_SUCCESS(status)) {
    printf("Status: %lu\n", status);
   };

   MYTEB teb;
   if (!ReadProcessMemory(hProcess, (LPCVOID)tbi.TebBaseAddress, &teb, sizeof(teb), NULL)) {
    printf("Error reading memory %lu\n", GetLastError());
   }

   PrintCommonTEB(teb);

   return 0;
}
