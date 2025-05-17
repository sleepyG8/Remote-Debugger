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
        printf("Error: Unable to get thread context.\n");
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

    LIST_ENTRY currentEntry = ldrData.InMemoryOrderModuleList;
    do {
        
        LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        if (!ReadProcessMemory(hProcess, ldrData.InMemoryOrderModuleList.Flink, &ldrEntry, sizeof(ldrEntry), NULL)) {
            printf("Failed to read LDR_DATA_TABLE_ENTRY (Error %lu)\n", GetLastError());
            return FALSE;
            break;
        }

        wprintf(L"Next Entry: %p\n", ldrEntry.InMemoryOrderLinks.Flink);

        
      /*  MEMORY_BASIC_INFORMATION mbi = {0};
        if (mbi.State != MEM_COMMIT) {
            printf("Memory not committed, skipping!\n");
            return FALSE;
        }
if (ldrEntry.DllBase > 0 && VirtualQueryEx(hProcess, ldrEntry.DllBase, &mbi, sizeof(mbi))) {
    printf("Image Base Address: %p\n", mbi.AllocationBase);
} else {
    printf("error %lu", GetLastError());
}*/


        // Print DLL details
        WCHAR dllName[MAX_PATH];
        wprintf(L"Length DLL fullname: %p\n", ldrEntry.FullDllName.Buffer);
        if ( ldrEntry.FullDllName.Length > 0 &&
            ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &dllName, ldrEntry.FullDllName.Length, NULL)) {
            dllName[ldrEntry.FullDllName.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate the string
            wprintf(L"Module: %ls\n", dllName);
        } else {
            printf("Must be admin to pull modules!\n");
            return FALSE;
            
        }

        

        currentEntry = *ldrEntry.InMemoryOrderLinks.Flink;

    } while (currentEntry.Flink != &ldrData.InMemoryOrderModuleList);
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

while(info) {
    wprintf(L"Image Name: %ls\n", info->ImageName.Buffer ? info->ImageName.Buffer : L"NULL, no image name\n");
    printf("Number of Threads (process): %lu\n", info->NumberOfThreads);
    printf("Next Entry offest: %lu\n", info->NextEntryOffset);
    printf("Handle count: %lu\n", info->HandleCount);
    printf("Memory Usage: %llu\n", info->VirtualSize);
    printf("+++++++++++++++++++++++++++++++++++++++++++\n");
    if (info->NextEntryOffset == 0) break;
    info = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)info + info->NextEntryOffset); //loop through using next next entry offset
}
   
    // printf("Process ID: %i", (int)info->UniqueProcessId);

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

BOOL getMBI(HANDLE hProcess, LPVOID addr) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD oldProtect;
   
 
MEMORY_INFORMATION_CLASS infoClass = MemoryBasicInformation;

pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(
    GetModuleHandle("ntdll.dll"), "NtQueryVirtualMemory"
);
    
  NTSTATUS status = NtQueryVirtualMemory(hProcess, addr, infoClass, &mbi, sizeof(mbi), NULL);
if (status != STATUS_SUCCESS) {
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
        printf("Debugging %s:\n", arg);

        

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
                        printf("Debug>>");
            
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
                                    printf("!mbi     - get mbi info (only works for unprotected process)");
                                    printf("!synbreak - break at a debug symbol (not stable yet)");
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
