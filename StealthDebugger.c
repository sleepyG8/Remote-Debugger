#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <securitybaseapi.h>
#include <sddl.h> 
#include <AclAPI.h>
#include <dbghelp.h>
//add terminate

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

CONTEXT context;

struct mystructs {

PPEB pebaddr;
PRTL_USER_PROCESS_PARAMETERS params;
BYTE BeingDebugged;
PVOID Base;

}peb;

struct myparams {

WCHAR *fullPath;

}myparams;

typedef NTSTATUS (NTAPI* pNtTerminateProcess)(HANDLE, NTSTATUS);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

/*BOOL readRdxReg(HANDLE hProcess, CONTEXT context) {

SIZE_T bytesRead;
BYTE *buffer = (BYTE*)malloc(256 * sizeof(BYTE));

// Assume hProcess is already opened and accessible
if (ReadProcessMemory(hProcess, (LPCVOID)context.Rdx, &buffer, sizeof(buffer), &bytesRead)) {
    printf("Data at RCX: ");
    for (size_t i = 0; i < bytesRead; i++) {
        printf("%02X ", buffer[i]); // Prints byte values
    }
    printf("\n");
} else {
    printf("Failed to read memory at RCX. Error: %lu\n", GetLastError());
    return FALSE;
}

return TRUE;
}
*/

WCHAR imagePath[MAX_PATH] = {0};


BOOL logo() {
    
    //aunt ansi came to town
        printf("\x1B[2J");
    
        printf("\x1B[2;20H");
        printf("\x1B[37;44m");
        printf("Debugger By Sleepy:\n                            v0.0.1\n");
    
        
    
    
        printf("\x1B[4;1H");
        //char *buff = "+";
        for (int i = 0; i < 100; i++) {
            printf("+");
        }
        
        
        printf("\x1B[6;10Hprocesses:\n\n");
        printf("\x1B[0m");
        
        return 0;
    }

BOOL readRawAddr(HANDLE hProcess, LPVOID base, SIZE_T bytesToRead) {

    BYTE *buff = (BYTE*)malloc(bytesToRead);
    if (!buff) {
        printf("Memory allocation failed!\n");
        return FALSE;
    }

    DWORD bytesRead = 0;
    // Read memory
    if (ReadProcessMemory(hProcess, base, buff, bytesToRead, &bytesRead)) {
        printf("\x1b[92m[!]\x1b[0m Read Memory - Base: %p\n", base);
    } else {
        printf("\x1b[92m[!]\x1b[0m Read partial memory - Region base: %p\n", base);
    }
    // Print 100 raw memory bytes
    printf("\x1b[92m[+]\x1b[0m Chars:\n");
    for (SIZE_T i = 0; i < 100; i++) {
        if (isprint(buff[i])) {  // Very useful to print only valid chars
        printf("%c ", buff[i]);;
    }
}
    printf("\n");

    printf("\x1b[92m[+]\x1b[0m Raw: \n");
    for (SIZE_T i = 0; i < 100; i++) {
    printf("%02X ", buff[i]);        
    }
    
    printf("\n");

    free(buff); // Free allocated memory
    return TRUE;
}

BOOL getThreads(DWORD *threadId) {
    HANDLE hThread;

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread.\n");
        return TRUE;
    }

    SuspendThread(hThread);

    context.ContextFlags = CONTEXT_FULL | CONTEXT_AMD64;
    //setting conetext can help avoid detection
    if (GetThreadContext(hThread, &context)) {
        context.Dr6 = 0;
        context.Dr0 = 0xDEADBEEF;
        context.Dr1 = 1;
        context.Dr2 = 0xDEADBEEF;
        context.Dr3 = 0xDEADBEEF;
        SetThreadContext(hThread, &context);

        printf("\n\033[35m+-----------Registers-----------+\033[0m\n");
        printf("RIP: 0x%016llX\n", context.Rip);
        printf("RAX: 0x%016llX\n", context.Rax);
        printf("RBX: 0x%016llX\n", context.Rbx);
        printf("RCX: 0x%016llX\n", context.Rcx);
        printf("RDX: 0x%016llX\n", context.Rdx);

    } else {
        printf("Error: Unable to get thread context. %lu\n", GetLastError());
        return FALSE;
    }

    ResumeThread(hThread);

    CloseHandle(hThread);

    return TRUE;
}

//defined my own PEB to get BITFIELD and other structures in the future
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

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;


typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // Padding or additional fields could follow if needed
} MY_LDR_DATA_TABLE_ENTRY;



MYPEB pbi;
WCHAR dllName[MAX_PATH] = {0};


BOOL GetPEBFromAnotherProcess(HANDLE hProcess, PROCESS_INFORMATION *thread, DWORD id) {
    SuspendThread(thread);
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return FALSE;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("Failed to get NtQueryInformationProcess\n");
        return FALSE;
    }

    
    PROCESS_BASIC_INFORMATION proc = {0};
    ULONG returnlen;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc, sizeof(PROCESS_BASIC_INFORMATION), &returnlen);
    if (status != 0) {
        printf("NtQueryInformationProcess failed (Status 0x%08X)\n", status);
        return FALSE;
    }
    //\033[35mDebugging %s:\033[0m
    printf("\n\033[35m+-----------Startup-Info-----------+\033[0m\n");
    
   // printf("PEB Address of the target process: %s\n", proc.PebBaseAddress);
    printf("\x1b[92m[+]\x1b[0m Peb address: 0x%llX", proc.PebBaseAddress);
    peb.pebaddr = proc.PebBaseAddress;
   
   
   
   //printf("Peb struct address: %p", peb.pebaddr);

    MY_PEB_LDR_DATA ldrData;
    if (ReadProcessMemory(hProcess, proc.PebBaseAddress, &pbi, sizeof(pbi), NULL)) {
        printf("\n\x1b[92m[+]\x1b[0m process ID: %lu\n", (unsigned long)proc.UniqueProcessId);
    } else {
        printf("Failed to read PEB from the target process (Error %lu)\n", GetLastError());
        return FALSE;
    }
   // printf("Parameters: %i\n", pbi.ProcessParameters->CommandLine.Length); this is only for terminal apps
   // printf("Is Protected Process?: %lu\n", pbi.IsProtectedProcess);
    printf("\x1b[92m[+]\x1b[0m IsBeingDebugged: %i\n", pbi.BeingDebugged);

    peb.BeingDebugged = pbi.BeingDebugged; //neat
    peb.params = pbi.ProcessParameters; //storing address

    //remember even if its a Buffer in memory you have to read it to a WCHAR for storing like shown this is key
    RTL_USER_PROCESS_PARAMETERS parameters;
    struct myparams myparams;
    
    myparams.fullPath = (WCHAR*)malloc(1068 * sizeof(WCHAR));

    if (!ReadProcessMemory(hProcess, pbi.ProcessParameters, &parameters, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        printf("error reading params\n");
    } else {
       // WCHAR imagePath[MAX_PATH] = {0};
        if (!ReadProcessMemory(hProcess, parameters.ImagePathName.Buffer, imagePath, parameters.ImagePathName.Length, NULL)) {
            printf("Error reading ImagePathName buffer\n");
        } else {
            wprintf(L"\x1b[92m[+]\x1b[0m Full Path: %ls\n", imagePath);
            myparams.fullPath = _wcsdup(imagePath);
           // free(myparams.fullPath);
        }
    }

    WCHAR cmd[MAX_PATH] = {0};
    if (!ReadProcessMemory(hProcess, parameters.CommandLine.Buffer, &cmd, parameters.CommandLine.Length, NULL)) {
        printf("error reading command line arguments\n");
        return FALSE;
    }

    wprintf(L"\x1b[92m[+]\x1b[0m Command Line: %ls\n", cmd);
    
    size_t bytesread;

    // wow this fixed a lot, the list wasnt populated
    WaitForInputIdle(hProcess, 500);

    if (!ReadProcessMemory(hProcess, (LPCVOID)pbi.Ldr , &ldrData, sizeof(ldrData), &bytesread)) {
            printf("error getting ldr, retry...\n");
            return FALSE;
    }
    
        printf("\x1b[92m[+]\x1b[0m LDR Address: 0x%llX\n", ldrData);

        printf("\n\033[35m+-----------Modules-----------+\033[0m\n");
     LIST_ENTRY* head = &ldrData.InLoadOrderModuleList;
     LIST_ENTRY* currentEntry = head->Flink;
    
    while (currentEntry != head) {
        DWORD bytes;
        MY_LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        if (!ReadProcessMemory(hProcess, currentEntry, &ldrEntry, sizeof(MY_LDR_DATA_TABLE_ENTRY), &bytes)) {
            printf("\x1b[92m[!]\x1b[0m Done\n");
            return FALSE;
        }

        WCHAR name[MAX_PATH] = {0};
        if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &name, ldrEntry.FullDllName.Length, NULL)) {
            printf("\x1b[92m[!]\x1b[0m Done\n");
            return FALSE;
        }

        // Setting Global struct
        peb.Base = ldrEntry.DllBase;

        wprintf(L"\x1b[92m[+]\x1b[0m Module: %s\n", name);
        printf("\x1b[92m[+]\x1b[0m Base Address: 0x%llX\n", ldrEntry.DllBase);
        printf("+++++++++++++++++++++++++++++++++\n");
        
        currentEntry = ldrEntry.InLoadOrderLinks.Flink;
       
    }
        return TRUE;
    
    }

BOOL GetSecurityDescriptor(HANDLE hObject) {
    HMODULE hAdvapi32 = LoadLibrary("Advapi32.dll");
if (!hAdvapi32) {
    printf("Failed to load Advapi32.dll!\n");
    return FALSE;
}

typedef BOOL (WINAPI *pIsValidSecurityDescriptor)(PSECURITY_DESCRIPTOR);
pIsValidSecurityDescriptor IsValidSD = (pIsValidSecurityDescriptor)GetProcAddress(hAdvapi32, "IsValidSecurityDescriptor");

if (!IsValidSD) {
    printf("Failed to retrieve IsValidSecurityDescriptor function!\n");
    FreeLibrary(hAdvapi32);
    return FALSE;
}

    typedef NTSTATUS (NTAPI *pZwQuerySecurityObject)(
        HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG
    );

    //setting dll manually
    HMODULE hNtDll = LoadLibrary("ntdll.dll");
    pZwQuerySecurityObject ZwQuerySecurityObject = (pZwQuerySecurityObject)GetProcAddress(hNtDll, "ZwQuerySecurityObject");




ULONG sdSize = 0;
//this also sets the size for the psd alloc
NTSTATUS status = ZwQuerySecurityObject(hObject, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, sdSize, &sdSize);

PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)malloc(sdSize);
if (!pSD) {
    printf("Memory allocation failed!\n");
    return FALSE;
}

status = ZwQuerySecurityObject(hObject, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, pSD, sdSize, &sdSize);

if (!IsValidSD(pSD)) {
    printf("Invalid security descriptor!\n");
    return FALSE;
}

if (status == STATUS_SUCCESS) {
    printf("\x1b[92m[!]\x1b[0m retrieved the security descriptor!\n");
} else {
    printf("error\n");
    return FALSE;
}

PSID ownerSID = NULL;
PSID oGroup;
PACL dasl;
BOOL ownerDefaulted;
BOOL ownerDefaultedGroup;
BOOL ownerDefaultedDasl;
BOOL daslPresent;
//getting owner
if (!GetSecurityDescriptorOwner(pSD, &ownerSID, &ownerDefaulted)) {
    printf("error getting owner SID\n");
    return FALSE;
}
// getting group
if (!GetSecurityDescriptorGroup(pSD, &oGroup, &ownerDefaultedGroup)){
    printf("error getting Object group\n");
    return FALSE;
}
//getting dacl
if (!GetSecurityDescriptorDacl(pSD, &daslPresent, &dasl, &ownerDefaultedDasl)) {
    printf("error getting DACL\n");
    return FALSE;
} else {
    if (daslPresent == FALSE) {
        printf("No group permissions set\n");
    }
}

LPSTR daclOut;
if (ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &daclOut, NULL)) {
    printf("\x1b[92m[+]\x1b[0m DACL: %s\n", daclOut);
}

//ConvertStringSecurityDescriptorToSecurityDescriptor found this use later to set a descriptor?

LPSTR sidstring;
if (ConvertSidToStringSid(ownerSID, &sidstring)) {
    printf("\x1b[92m[+]\x1b[0m SID: %s\n", sidstring);
} else {
    printf("error geeting SID\n");
    return FALSE;
}
//SE_OBJECT_TYPE sObj;
//SECURITY_INFORMATION sInfo;
//if (GetSecurityInfo(hObject, sObj, sInfo, &ownerSID, &oGroup,  ))


char name[256];
char domain[256];
DWORD nameLen = sizeof(name);
DWORD domainLen = sizeof(domain);
SID_NAME_USE sidType;

PSID psdString = NULL;
ConvertStringSidToSidA(sidstring, &psdString);
if (!LookupAccountSidA(NULL, psdString, name, &nameLen, domain, &domainLen, &sidType)) {
    printf("Error looking up SID name and domain %lu\n", GetLastError());
}

printf("\x1b[92m[+]\x1b[0m NT %s\\%s\\\n", name, domain);

return TRUE;
FreeLibrary(hAdvapi32);
FreeLibrary(hNtDll);
}

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

BOOL listProcesses() {
          HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return FALSE;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQueryInformationProcess\n");
        return FALSE;
    }

    PULONG returnLen;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return FALSE;
    }

        SYSTEM_PROCESS_INFORMATION* info = malloc(returnLen);
        if (!info) {
            printf("failed to allocate memory\n");
        }

        status = NtQuerySystemInformation(SystemProcessInformation, info, returnLen, &returnLen);
            if (status != STATUS_SUCCESS) {
        printf("Error 2 0x%X", status);
        return FALSE;
    } 
int procCount = 0;
while(info) {
    wprintf(L"\x1b[92m[+]\x1b[0m Image Name: %ls\n", info->ImageName.Buffer ? info->ImageName.Buffer : L"NULL, no image name\n");
    printf("Number of Threads (process): %lu\n", info->NumberOfThreads);
    //printf("Next Entry offest: %lu\n", info->NextEntryOffset);
    printf("Handle count: %lu\n", info->HandleCount);
   // printf("Memory Usage: %llu\n", info->VirtualSize);
    printf("Process ID: %i\n", (int)info->UniqueProcessId);
    printf("+++++++++++++++++++++++++++++++++++++++++++\n");
    procCount++;
    if (info->NextEntryOffset == 0) break;
    info = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)info + info->NextEntryOffset); //loop through using next next entry offset
}
   
    printf("\x1b[92m[+]\x1b[0m # of processes: %i\n", procCount);

    return TRUE;
}

BOOL Getcpuinfo() {

          HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return FALSE;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQueryInformationProcess\n");
        return FALSE;
    }

       ULONG returnLen;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, NULL, 0, &returnLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return FALSE;
    }

    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *spi = (SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION*)malloc(returnLen);

       status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, spi, returnLen, &returnLen);
    if (NT_SUCCESS(status)) {
       printf("Loaded processor information:\n");
    } else {
        return FALSE;
    }

        int numProcessors = returnLen / sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
    for (int i = 0; i < numProcessors; i++) {
        printf("CPU %d - Idle time: %lli\n", i, spi[i].IdleTime.QuadPart);
        printf("CPU %d - Kernel time: %lli\n", i, spi[i].KernelTime.QuadPart);
        printf("CPU %d - User time: %lli\n", i, spi[i].UserTime.QuadPart);
        printf("----------------------------------\n");
    }

    free(spi);

    return TRUE;

}

#pragma comment(lib, "dbghelp.lib")

//setting a breakpoint using the symbol file (I am working on adding normal breaks at addresses next)
BOOL setBreakpointatSymbol(HANDLE hProcess, const char* symbol, char* module) {
    if (!symbol) return FALSE;


    
    SymInitialize(hProcess, NULL, TRUE);

    DWORD64 baseAddr = SymLoadModuleEx(hProcess, NULL, symbol, NULL, 0, 0, NULL, 0);
if (!baseAddr) {
    printf("Failed to load module %s, error: %lu\n", symbol, GetLastError());
    return FALSE;
}

    //printf("data :%s\n", symbol);
    SYMBOL_INFO *Symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    ZeroMemory(Symbol, sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    Symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    Symbol->MaxNameLen = MAX_SYM_NAME;

    if (SymFromName(hProcess, symbol, Symbol)) {
        printf("Got symbol\n");
    } else {
        printf("no symbol file %lu\n", GetLastError());
        free(Symbol);
        return FALSE;
    }

    DWORD oldProtect;
    if (!VirtualProtect(Symbol->Address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to modify memory protection.\n");
        free(Symbol);
        return FALSE;
    }

    *(BYTE*)Symbol->Address = 0xCC;  // INT3 Breakpoint

    VirtualProtect(Symbol->Address, 1, oldProtect, &oldProtect);
    free(Symbol);
    return TRUE;
}

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

       typedef NTSTATUS (NTAPI *pNtQueryVirtualMemory)(
    HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T
);

//gets mbi info which is useful for checking protections on a mem region
//also, I built this for me to test regions while building this debugger
BOOL getMBI(HANDLE hProcess, LPVOID addr) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD oldProtect;
   
 
MEMORY_INFORMATION_CLASS infoClass = MemoryBasicInformation;

pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(
    GetModuleHandle("ntdll.dll"), "NtQueryVirtualMemory"
);
    
  NTSTATUS status = NtQueryVirtualMemory(hProcess, addr, infoClass, &mbi, sizeof(mbi), NULL);
if (!NT_SUCCESS(status)) {
    printf("Error with Virtual Memory: %lu\n", GetLastError());
}

    printf("\x1b[92m[+]\x1b[0m Base address: 0x%p\n", mbi.BaseAddress);
    printf("\x1b[92m[+]\x1b[0m Protections: %lu\n", mbi.Protect);
    printf("\x1b[92m[+]\x1b[0m State: %lu\n", mbi.State);
    printf("\x1b[92m[+]\x1b[0m Partition ID: %lu\n", mbi.PartitionId);
    printf("\x1b[92m[+]\x1b[0m Type: %lu\n", mbi.Type);
    printf("\x1b[92m[+]\x1b[0m Protect alloc: %lu\n", mbi.AllocationProtect);

    return TRUE;

}



BOOL breakpoint(DWORD threadId, PVOID address, HANDLE hProcess) {
    CONTEXT contextBreak;
    HANDLE hThread;
 
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread.\n");
        return TRUE;
    }

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");

    typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PULONG, ULONG, PULONG
    );

    pNtProtectVirtualMemory NtProtectVirtualMemory = 
    (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

//attempt to bypass error 5 damn it doesnt work yet!
ULONG size = 0x1000;
ULONG oldProtect;
NTSTATUS status = NtProtectVirtualMemory(hProcess, &address, &size, PAGE_EXECUTE_READWRITE, &oldProtect);

if (status == STATUS_ACCESS_VIOLATION) {
    printf ("error, cannot change memory protections\n");
}
//printf("status: %lu\n", status);

   if (SuspendThread(hThread) == -1) {
    printf("failed to suspend %lu\n", GetLastError());
    return FALSE;
   }
    
   // Helps with getting context maybe? idk you can remove probably
    Sleep(1000);

    //checking if thread is still active
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 259) {
        printf("259 - still running\n");
    } else {
    printf("exit code: %lu\n", exitCode);
    }

    contextBreak.ContextFlags = CONTEXT_FULL | CONTEXT_AMD64;
    //setting conetext can help avoid detection
    if (GetThreadContext(hThread, &contextBreak)) {
        contextBreak.Dr1 = address;
        contextBreak.Dr7 |= (1 << 2);  // Enable DR1
        contextBreak.Dr7 |= (3 << 20); // Break on execution
        contextBreak.Dr7 |= (0 << 22); // 1-byte breakpoint
        SetThreadContext(hThread, &contextBreak);

        printf("RIP: 0x%016llX\n", contextBreak.Rip);
        printf("RAX: 0x%016llX\n", contextBreak.Rax);
        printf("RBX: 0x%016llX\n", contextBreak.Rbx);
        printf("RCX: 0x%016llX\n", contextBreak.Rcx);
        printf("RDX: 0x%016llX\n", contextBreak.Rdx);

    } else {
        printf("Error: Unable to get thread context. %lu\n", GetLastError());
        return FALSE;
    }

    ResumeThread(hThread);

    CloseHandle(hThread);

    return TRUE;
}

BOOL getVariables(DWORD procId) {

HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
if (!hProcess) {
    printf("error opening process %lu\n", GetLastError());
    return FALSE;
}

printf("base: %p\n", peb.Base);
//reading dos header
IMAGE_DOS_HEADER dh;

if (!ReadProcessMemory(hProcess, peb.Base, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
    printf("error reading memory of process ID\n");
   return FALSE;
}

//checks for a valid PE file
if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3 %lu\n", GetLastError());
    return FALSE;
} else {
    printf("\x1b[92m[+]\x1b[0m Valid PE file: YES-%x\n", dh.e_magic);
}

//getting nt headers
IMAGE_NT_HEADERS nt;
if (!ReadProcessMemory(hProcess, (BYTE*)peb.Base + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return FALSE;
}

//getting offset and starting a for loop to get all sections
DWORD sectionOffset = dh.e_lfanew + sizeof(IMAGE_NT_HEADERS);
IMAGE_SECTION_HEADER section;

//good touch
printf("\x1b[92m[!]\x1b[0m Scanning");
 for (int i=0; i < 3; i++) {
     printf(".");
     Sleep(500);
    }
    printf("\n");

//looping through
for (int i=0; i < nt.FileHeader.NumberOfSections; i++) {

    
if (!ReadProcessMemory(hProcess, (BYTE*)peb.Base + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)), &section, sizeof(IMAGE_SECTION_HEADER), NULL)) {
    printf("Error reading section memory %lu", GetLastError());
    }

    printf("\x1b[92m[+]\x1b[0m %s\n", (char*)section.Name);

    printf("\x1b[92m[+]\x1b[0m Section: %s | Address: 0x%X | Size: %d\n", section.Name, section.VirtualAddress, section.SizeOfRawData);

    char buffer[1025];
    if (!ReadProcessMemory(hProcess, (BYTE*)peb.Base + section.VirtualAddress, &buffer, sizeof(buffer), NULL)) {
        printf("Error reading data %lu\n", GetLastError());
    } else {
            for (int i = 0; i < sizeof(buffer); i++) {
            if (isprint(buffer[i])) {  // Very useful to print only valid chars
        printf("%c ", buffer[i]);
    }
    }
    printf("\n");
    printf("++++++++++++++++++++++++++++++++++\n");
    }
    
}
return TRUE;
}

BOOL Extensions(char* dllName) {
HANDLE hMod = LoadLibraryA(dllName);
if (!hMod) return FALSE;
printf("Extension loaded...\n");

return TRUE;
} 

BOOL WINAPI debug(LPCVOID param) {

    char *arg = (char*)param;
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    logo();
    char *process = arg;
    //"C:\\Windows\\System32\\notepad.exe"
    if (CreateProcess(
            process,
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi)) {
        printf("\x1b[92m[+]\x1b[0m \033[35mDebugging %s:\033[0m\n", arg);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (!hProcess) {
            printf("Problem starting the debugger\n");
        } else {
            DWORD *threadId = pi.dwThreadId;
            if (threadId == NULL) {
                printf("Error getting the thread ID...\n");
                return FALSE;
            } 
       
            getThreads(threadId);

            GetPEBFromAnotherProcess(hProcess, pi.dwThreadId, pi.dwProcessId);
            printf("thread address/ID: %p\n", &threadId);
                    while (1) {                           
                            
                            char buff[50];
                            printf("\033[35mDebug>>\033[0m");
                                            
                            fgets(buff, 49, stdin);
                            size_t sizeBuff = sizeof(buff);
                            buff[strcspn(buff, "\n")] = '\0';
                            
                            if (buff != NULL) {
            
                            //buff[sizeBuff + 1] = '\0';
                            
                            if (strcmp(buff, "!reg") == 0) {
                               printf("Process ID: %lu\n", pi.dwProcessId);
                               printf("Thread ID: %lu\n", pi.dwThreadId);
                               printf("RIP: 0x%016llX\n", context.Rip);
                               printf("RAX: 0x%016llX\n", context.Rax);
                               printf("RBX: 0x%016llX\n", context.Rbx);
                               printf("RCX: 0x%016llX\n", context.Rcx);
                               printf("RDX: 0x%016llX\n", context.Rdx);
                            }
                            
                           else if (strcmp(buff, "!attr") == 0) {
                                           //geting object info
                            typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        
                            HMODULE hNtDll = LoadLibrary("ntdll.dll");
                            pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
    
                            PUBLIC_OBJECT_BASIC_INFORMATION objInfo;
    
                            // HANDLE hObject = GetCurrentProcess();
                            ULONG size;
                            NTSTATUS status = NtQueryObject(hProcess, ObjectBasicInformation, &objInfo, sizeof(objInfo), &size);
        
                            if (!GetSecurityDescriptor(hProcess)) {
                                  printf("error\n");
                                }
                                printf("\x1b[92m[+]\x1b[0m Object Attributes: %i\n", objInfo.Attributes); 
                                printf("\x1b[92m[+]\x1b[0m Granted Access: %08X\n", objInfo.GrantedAccess);
                                printf("\x1b[92m[+]\x1b[0m Handle count: %lu\n", objInfo.HandleCount); 
                                FreeLibrary(hNtDll);     
                                } 

                                else if (strcmp(buff,"!peb") == 0) {
                                    printf("\x1b[92m[+]\x1b[0m peb already retrieved\n");
                                    printf("\x1b[92m[+]\x1b[0m Peb address: 0x%p\n", peb.pebaddr);
                                     

                                }

                                else if (strcmp(buff, "exit") == 0) {
                                        pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtTerminateProcess");
                                       if (!NtTerminateProcess) return FALSE;
                                       NTSTATUS status = NtTerminateProcess(NULL, 0);
                                       if (NT_SUCCESS(status)) {
                                        printf("See ya!\n", pi.dwProcessId);
                                        printf("\a");
                                       } else {
                                        printf("NTSTATUS: 0x%08X - Error killing\n", status);
                                       }   
                                       //Second call? Try it with 1 it doesnt work, this just works
                                       NtTerminateProcess(NULL, 0);
                                       
                                }

                                else if (strcmp(buff, "!params") == 0) {
                                   
                                    if (peb.BeingDebugged == 0) {
                                        printf("debugged?: No\n");
                                    }
                                    printf("\x1b[92m[+]\x1b[0m Peb address: 0x%p\n", peb.pebaddr);

                                    wprintf(L"\x1b[92m[+]\x1b[0m Path: %ls\n", imagePath);


                                }

                                else if (strcmp(buff, "clear") == 0) {
                                    printf("\x1B[2J");                             
                                   }

                                else if (strcmp(buff, "help") == 0) {
                                    printf("\n===== Debugger Usage =====\n");
                                    printf("-- Registers & Breakpoints --\n");
                                    printf("!reg      - Print process registers\n");
                                    printf("!getreg   - Print registers at current memory location\n");
                                    printf("!break    - Set a breakpoint and read registers\n");
                                    printf("!synbreak - Break at a debug symbol (not stable yet)\n");

                                    printf("\n-- Memory & Data Inspection --\n");
                                    printf("!dump     - Dump a raw address (retry if ERROR_ACCESS_DENIED)\n");
                                    printf("!mbi      - Get MBI info (only for unprotected processes)\n");
                                    printf("!bit      - Display Bitfield data\n");
                                    printf("!var      - Display section data\n");
                                    printf("!veh      - VEH Info\n");

                                    printf("\n-- Process & System Info --\n");
                                    printf("!proc     - Display all running processes\n");
                                    printf("!cpu      - Display CPU data per processor\n");
                                    printf("!attr     - Retrieve object attributes\n");
                                    printf("!peb      - Display PEB details\n");
                                    printf("!params   - Show process parameters (debug status & path)\n");

                                    printf("\n-- General Commands --\n");
                                    printf("clear     - Clear the console screen\n");
                                    printf("exit      - Terminate debugging session\n");
                                    printf("kill      - Close the debugged process\n");
                                    printf("help      - Display additional commands\n");
                                    printf("!ext      - Load extension (DLL)\n");

                                    printf("==============================\n");

                                }

                                else if (strcmp(buff, "!proc") == 0) {
                                    printf("\x1b[92m[+]\x1b[0m Listing system wide process information:\n");
                                    listProcesses();
                                }

                                // bit stuff
                                else if (strcmp(buff, "!bit") == 0) {
                                        printf("\x1b[92m[+]\x1b[0m Is Protected Process?: %lu\n", pbi.IsProtectedProcess);
                                        printf("\x1b[92m[+]\x1b[0m Is PPL?: %lu\n", pbi.IsProtectedProcessLight);
                                        printf("\x1b[92m[+]\x1b[0m Uses Large Pages?: %lu\n", pbi.ImageUsesLargePages);
                                        printf("\x1b[92m[+]\x1b[0m IsImageDynamicallyRelocated?: %lu\n", pbi.IsImageDynamicallyRelocated);

                                } 
                                
                                // Check for VEH in remote process
                                else if (strcmp(buff, "!veh") == 0) {
                                    printf("\x1b[92m[+]\x1b[0m VEH: %lu\n", (DWORD)pbi.ProcessUsingVEH);
                                }

                                else if (strcmp(buff,"!symbreak") == 0) {
                                    char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    printf("\x1b[92m[-]\x1b[0m Which symbol to break at?\n");
                                    if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    }
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';
                                    // pdb break
                                    if (!setBreakpointatSymbol(hProcess, breakBuffer, arg)) {
                                        printf("Cannot set breakpoint must be from a .pdb file\n");
                                    }
                                
                                }

                                else if (strcmp(buff, "!mbi") == 0) {
                                    LPVOID *breakBuffer = (LPVOID*)malloc(100 * sizeof(LPVOID));
                                    
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }

                                    printf("\x1b[92m[-]\x1b[0m Which addr to get?\n");

                                    if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    }

                                   // getMBI, region checker
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';
                                    if (!getMBI(hProcess, breakBuffer)) {
                                        printf("error");
                                    }
                                }

                                   else if (strcmp(buff, "!break") == 0) {
                                    char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    
                                    printf("\x1b[92m[-]\x1b[0m Which address to break at?\n");
                                   
                                    if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    return FALSE;
                                    }

                                    // Break
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';
                                    if (!breakpoint( pi.dwThreadId , breakBuffer, hProcess)) {
                                        printf("failed to set breakpoint, protected memory region.\n");
                                    }

                                }

                                 else if (strcmp(buff, "!getreg") == 0) {
                                            if (!getThreads(threadId)) {
                                            printf("error getting threads\n");
                                            }
                                    }

                                    else if (strcmp(buff, "!cpu") == 0) {
                                        if (!Getcpuinfo()) {
                                            printf("error %lu", GetLastError());
                                        }
                                    }

                                    else if (strcmp(buff, "!dump") == 0) {
                                        char breakBuffer[100] = {0};
                                        if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                        }

                                        printf("Which addr to get?\n");

                                        if (!fgets(breakBuffer, 99, stdin)) {
                                         printf("buffer to large\n");
                                        }

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        // Had to add for correct formating
                                        ULONGLONG addr = 0;
                                        if (sscanf(breakBuffer, "%llx", &addr) != 1 || addr == 0) {
                                        printf("Error: invalid address '%s'\n", breakBuffer);
                                        return FALSE;
                                        }

                                        // Read Raw function 
                                        if (!readRawAddr(hProcess, (LPVOID)addr, 50)) {
                                        printf("Error invalid address\n");
                                        }
                                    }

                                    else if (strcmp(buff, "!var") == 0) {
                                        if (!getVariables(pi.dwProcessId)) {
                                            printf("Error enumerating sections\n");
                                            }
                                    }

                                    else if (strcmp(buff, "kill") == 0) {
                                       pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtTerminateProcess");
                                       if (!NtTerminateProcess) return FALSE;
                                       NTSTATUS status = NtTerminateProcess(hProcess, 0);
                                       if (NT_SUCCESS(status)) {
                                        printf("Process[%lu] killed\n", pi.dwProcessId);
                                       } else {
                                        printf("NTSTATUS: 0x%08X - Error killing\n", status);
                                       }   
                                    }

                                    else if (strcmp(buff, "!ext") == 0) {

                                    char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    
                                    printf("\x1b[92m[-]\x1b[0m Which Extension to Load? (Path to dll)\n");
                                   
                                    if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    return FALSE;
                                    }

                                    // Break
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                    if (!Extensions(breakBuffer)) {
                                        printf("Error loading extension\n");
                                    }

                                    }

                                     } else {
                                         printf("run -help- to see the help menu.\n");
                                        }
                            }                  
                        }                                            
                    }
    WaitForInputIdle(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int main(int argc, char* argv[]) {
    LPVOID fiberMain = ConvertThreadToFiber(NULL); 
    LPVOID debugFiber = CreateFiber(0, debug, argv[1]);

    if (debugFiber) {
        while (1) {
        SwitchToFiber(debugFiber);
        DeleteFiber(debugFiber); 
        } // Launch debugger inside fiber
          // Cleanup

}
return 0;
}
