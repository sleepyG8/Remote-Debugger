#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <securitybaseapi.h>
#include <sddl.h> 
#include <AclAPI.h>
#include <dbghelp.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

CONTEXT context;

struct mystructs {

PPEB pebaddr;
PRTL_USER_PROCESS_PARAMETERS params;
BYTE BeingDebugged;

}peb;

struct myparams {

WCHAR *fullPath;

}myparams;

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

BOOL readRawAddr(HANDLE hProcess, LPVOID base) {
 
    MEMORY_BASIC_INFORMATION mbi = {0};
if (VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi)) == 0) {
    printf("VirtualQueryEx failed: %lu\n", GetLastError());
    return FALSE;
}

printf("Size: %lu\n", mbi.RegionSize);
printf("Region base: %p\n", mbi.BaseAddress);
printf("Base: %p\n", base);

    //SIZE_T bytesToRead = min(256, mbi.RegionSize - ((SIZE_T)base - (SIZE_T)mbi.BaseAddress));
    SIZE_T bytesToRead = 200;

        BYTE *buff = (BYTE*)malloc(bytesToRead);
    if (!buff) {
        printf("Memory allocation failed!\n");
        return FALSE;
    }

    DWORD bytesRead = 0;
    // Read memory
    if (ReadProcessMemory(hProcess, base, buff, bytesToRead, &bytesRead)) {
        printf("Read full Memory region\n");
    } else {
        printf("Read partial memory\n");
    }
    // Print 100 raw memory bytes
    for (SIZE_T i = 0; i < 100; i++) {
        if (isprint(buff[i])) {  // Very useful to print only valid chars
        printf("%c ", buff[i]);;
    }
}
    printf("\n");

    printf("Raw: \n");
    for (SIZE_T i = 0; i < 100; i++) {
    printf("%02X ", buff[i]);        
    }
    free(buff); // Free allocated memory
    return TRUE;
}

BOOL getThreads(DWORD *threadId) {
    HANDLE hThread;
    //HMODULE hModule = GetModuleHandle("notepad.exe"); // Or LoadLibrary() if it's a DLL
//LPVOID targetAddr = GetProcAddress(hModule, "TargetFunction");

    //DWORD threadId = 5652; // Replace with the actual thread ID

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


        printf("RAX: %016llX\n", context.Rax);
        printf("RBX: %016llX\n", context.Rbx);
        printf("RCX: %016llX\n", context.Rcx);
        printf("RDX: %016llX\n", context.Rdx);

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
WCHAR dllName[MAX_PATH] = {0};

BOOL GetPEBFromAnotherProcess(HANDLE hProcess, PROCESS_INFORMATION *thread) {
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
    
   // printf("PEB Address of the target process: %s\n", proc.PebBaseAddress);
    printf("Peb address: %p", proc.PebBaseAddress);
    peb.pebaddr = proc.PebBaseAddress;
   
   
   
   //printf("Peb struct address: %p", peb.pebaddr);

    PEB_LDR_DATA ldrData;
    if (ReadProcessMemory(hProcess, proc.PebBaseAddress, &pbi, sizeof(pbi), NULL)) {
        printf("\nprocess ID: %lu\n", (unsigned long)proc.UniqueProcessId);
    } else {
        printf("Failed to read PEB from the target process (Error %lu)\n", GetLastError());
        return FALSE;
    }
   // printf("Parameters: %i\n", pbi.ProcessParameters->CommandLine.Length); this is only for terminal apps
   // printf("Is Protected Process?: %lu\n", pbi.IsProtectedProcess);
    printf("\x1B[31m+isBeingDebugged: %i\n\x1B[0m", pbi.BeingDebugged);

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
            wprintf(L"Path: %ls\n", imagePath);
            myparams.fullPath = _wcsdup(imagePath);
           // free(myparams.fullPath);
        }
    }

    WCHAR cmd[MAX_PATH] = {0};
    if (!ReadProcessMemory(hProcess, parameters.CommandLine.Buffer, &cmd, parameters.CommandLine.Length, NULL)) {
        printf("error reading command line arguments\n");
        return FALSE;
    }

    wprintf(L"Command line: %ls\n", cmd);
    
    size_t bytesread;

    //printf("%p", peb.LoaderData->Length);
    printf("Ldr address: %p\n", pbi.Ldr);
    if (!ReadProcessMemory(hProcess, (LPCVOID)pbi.Ldr , &ldrData, sizeof(ldrData), &bytesread)) {
            printf("error getting ldr, retry...\n");
            return FALSE;
           // return 1;
    }
    //PPEB pebbers = (PPEB)pbi.PebBaseAddress;
    // PPEB 
   // printf("DLLs: %p", ldrData.InLoadOrderModuleList);
    //PMY_LDR_DATA_TABLE_ENTRY ldr = (PMY_LDR_DATA_TABLE_ENTRY)peb.LoaderData;

    //printf("LI: %p", ldrData.InMemoryOrderModuleList.Flink);
    
    LIST_ENTRY *currentEntry = (LIST_ENTRY*)ldrData.InMemoryOrderModuleList.Flink;
    LIST_ENTRY *pLdrCurrentNode = ldrData.InMemoryOrderModuleList.Flink; 
    
   
        DWORD bytes;
        LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        if (!ReadProcessMemory(hProcess, pLdrCurrentNode, &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), &bytes)) {
            printf("Error reading memory %lu\n", GetLastError());
            return FALSE;
        }

        if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &dllName, ldrEntry.FullDllName.Length, NULL)) {
            printf("Error reading dll name\n");
            return 1;
        }

        //printf("Bytes %lu\n", bytes);

        wprintf(L"Module: %p\n", dllName);

    
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
    printf("retrieved the security descriptor!\n");
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
    } else {
        printf("DACL found!\n");
    }
}

LPSTR daclOut;
if (ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &daclOut, NULL)) {
    printf("DACL: %s\n", daclOut);
}

//ConvertStringSecurityDescriptorToSecurityDescriptor found this use later to set a descriptor?

LPSTR sidstring;
if (ConvertSidToStringSid(ownerSID, &sidstring)) {
    printf("SID: %s\n", sidstring);
} else {
    printf("error geeting SID\n");
    return FALSE;
}
//SE_OBJECT_TYPE sObj;
//SECURITY_INFORMATION sInfo;
//if (GetSecurityInfo(hObject, sObj, sInfo, &ownerSID, &oGroup,  ))

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
    wprintf(L"Image Name: %ls\n", info->ImageName.Buffer ? info->ImageName.Buffer : L"NULL, no image name\n");
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
   
    printf("# of processes: %i\n", procCount);

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
    printf("Protected Region (works for unprotected proc): %lu\n", GetLastError());
}

    printf("Base address: %p\n", mbi.BaseAddress);
    printf("Protections: %lu\n", mbi.Protect);
    printf("State: %lu\n", mbi.State);
    printf("Partition ID: %lu\n", mbi.PartitionId);
    printf("Type: %lu\n", mbi.Type);
    printf("Protect alloc: %lu\n", mbi.AllocationProtect);

    return TRUE;

}



BOOL breakpoint(DWORD threadId, PVOID address, HANDLE hProcess) {
    CONTEXT contextBreak;
        HANDLE hThread;
    //HMODULE hModule = GetModuleHandle("notepad.exe"); // Or LoadLibrary() if it's a DLL
//LPVOID targetAddr = GetProcAddress(hModule, "TargetFunction");

    //DWORD threadId = 5652; // Replace with the actual thread ID

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

        printf("RIP: %016llX\n", contextBreak.Rip);
        printf("RAX: %016llX\n", contextBreak.Rax);
        printf("RBX: %016llX\n", contextBreak.Rbx);
        printf("RCX: %016llX\n", contextBreak.Rcx);
        printf("RDX: %016llX\n", contextBreak.Rdx);

    } else {
        printf("Error: Unable to get thread context. %lu\n", GetLastError());
        return FALSE;
    }

    ResumeThread(hThread);

    CloseHandle(hThread);

    return TRUE;
}

BOOL getVariables(DWORD procId) {

BYTE *baseAddress = (BYTE*)malloc(100 * sizeof(BYTE));

HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
if (!hProcess) {
    printf("error opening process %lu\n", GetLastError());
    return FALSE;
}

//getting base address
HMODULE hMods[1024];
DWORD cbNeeded;
if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
    baseAddress = (BYTE*)hMods[0]; 
} else {
    printf("error enumerating base address\n");
    return FALSE;
}

//reading dos header
IMAGE_DOS_HEADER dh;

if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
    printf("error reading memory of process ID\n");
   return FALSE;
}

//checks for a valid PE file
if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3 %lu\n", GetLastError());
    return FALSE;
} else {
    printf("Valdid PE file: YES-%x\n", dh.e_magic);
}

//getting nt headers
IMAGE_NT_HEADERS nt;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return FALSE;
}

//getting offset and starting a for loop to get all sections
DWORD sectionOffset = dh.e_lfanew + sizeof(IMAGE_NT_HEADERS);
IMAGE_SECTION_HEADER section;

//good touch
printf("Scanning");
 for (int i=0; i < 3; i++) {
     printf(".");
     Sleep(500);
    }
    printf("\n");

//looping through
for (int i=0; i < nt.FileHeader.NumberOfSections; i++) {

    
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)), &section, sizeof(IMAGE_SECTION_HEADER), NULL)) {
    printf("Error reading section memory %lu", GetLastError());
    }

printf("+ %s\n", (char*)section.Name);

    printf("Section: %s | Address: 0x%X | Size: %d\n", section.Name, section.VirtualAddress, section.SizeOfRawData);

    char buffer[1025];
    if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + section.VirtualAddress, &buffer, sizeof(buffer), NULL)) {
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
        printf("\033[35mDebugging %s:\033[0m\n", arg);

        

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

            GetPEBFromAnotherProcess(hProcess, pi.dwThreadId);
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
                               printf("RIP: %016llX\n", context.Rip);
                               printf("RAX: %016llX\n", context.Rax);
                               printf("RBX: %016llX\n", context.Rbx);
                               printf("RCX: %016llX\n", context.Rcx);
                               printf("RDX: %016llX\n", context.Rdx);
                            }
                            
                           else if (strcmp(buff, "!attr") == 0) {
                                           //geting object info
                                typedef NTSTATUS (NTAPI *pNtQueryObject)(
                             HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG
                                                     );
        
                             HMODULE hNtDll = LoadLibrary("ntdll.dll");
                    pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
    
                           PUBLIC_OBJECT_BASIC_INFORMATION objInfo;
    
                              // HANDLE hObject = GetCurrentProcess();
                                  ULONG size;
                 NTSTATUS status = NtQueryObject(hProcess, ObjectBasicInformation, &objInfo, sizeof(objInfo), &size);
        
                                   if (!GetSecurityDescriptor(hProcess)) {
                                              printf("error\n");
                                   }
                                                             
    
    
                                     printf("Object Attributes: %i\n", objInfo.Attributes); 
                                     printf("Granted Access: %08X\n", objInfo.GrantedAccess);
                                     printf("Handle count: %lu\n", objInfo.HandleCount); 
                                     FreeLibrary(hNtDll);
                                     
                                } 

                                else if (strcmp(buff,"!peb") == 0) {
                                    printf("peb already retrieved\n");
                                    printf("Peb address: %p\n", peb.pebaddr);
                                     

                                }

                                else if (strcmp(buff, "exit") == 0) {
                                    printf("Goodbye!\n");
                                    printf("ctrl-c to exit\n");
                                    CloseHandle(hProcess);
                                    break;
                                }

                                else if (strcmp(buff, "!params") == 0) {
                                   
                                    if (peb.BeingDebugged == 0) {
                                        printf("debugged?: No\n");
                                    }
                                    printf("Peb address: %p\n", peb.pebaddr);

                                    wprintf(L"Path: %ls\n", imagePath);


                                }

                                else if (strcmp(buff, "clear") == 0) {
                                    printf("\x1B[2J");                             
                                   }

                                else if (strcmp(buff, "help") == 0) {
                                    printf("\n===== Debugger Usage =====\n");
                                    printf("!reg     - Print process registers\n");
                                    printf("!attr    - Retrieve object attributes\n");
                                    printf("!peb     - Display PEB details\n");
                                    printf("!params  - Show process parameters (debug status & path)\n");
                                    printf("!proc    - Display all running processes on the system\n");
                                    printf("!bit     - Display Bitfield data\n");
                                    printf("!mbi     - get mbi info (only works for unprotected process)\n");
                                    printf("!synbreak - break at a debug symbol (not stable yet)\n");
                                    printf("!break   - Set a break and read registers\n");
                                    printf("!getreg - print registers wherever in memory currently\n");
                                    printf("clear    - Clear the console screen\n");
                                    printf("exit     - Terminate debugging session\n");
                                    printf("help     - Display additional commands\n");
                                    printf("==========================\n");

                                }

                                    else if (strcmp(buff, "!proc") == 0) {
                                    printf("Listing system wide process information:\n");
                                    listProcesses();
                                }

                                else if (strcmp(buff, "!bit") == 0) {
                                        printf("Is Protected Process?: %lu\n", pbi.IsProtectedProcess);
                                        printf("Light Protected?: %lu\n", pbi.IsProtectedProcessLight);
                                        printf("Uses Large Pages?: %lu\n", pbi.ImageUsesLargePages);
                                        printf("IsImageDynamicallyRelocated?: %lu\n", pbi.IsImageDynamicallyRelocated);

                                } 

                                else if (strcmp(buff,"!symbreak") == 0) {
                                    char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    printf("Which symbol to break at?\n");
                                   if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                   }
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';
                                  // printf("testing\n");
                                    if (!setBreakpointatSymbol(hProcess, breakBuffer, arg)) {
                                        printf("Cannot set breakpoint must be from a .pdb file\n");
                                    }
                                
                                }

                                else if (strcmp(buff, "!mbi") == 0) {
                                            LPVOID *breakBuffer = (LPVOID*)malloc(100 * sizeof(LPVOID));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    printf("Which addr to get?\n");
                                   if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                   }
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
                                    printf("Which address to break at?\n");
                                   if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    return FALSE;
                                   }
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
                                    LPVOID *breakBuffer = (LPVOID*)malloc(100 * sizeof(LPVOID));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    printf("Which addr to get?\n");
                                   if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                   }
                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                    if (!readRawAddr(hProcess, breakBuffer)) {
                                        printf("Error invalid address\n");
                                    }
                                    }

                                    else if (strcmp(buff, "!var") == 0) {
                                        if (!getVariables(pi.dwProcessId)) {
                                            printf("Error enumerating sections\n");
                                        }
                                    }

                            } else {
                                printf("run -help- to see the help menu.\n");
                            }

                        }
                               
                                        
                    }                            
                    //finally calling peb function
                               
                        //Get OBJ attributes mostly 0 but kernel uses this
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
