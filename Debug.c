#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "User32.lib")

CONTEXT context;

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
    
    //DWORD threadId = 5652; // Replace with the actual thread ID

    // Get a handle to the thread
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread.\n");
        return TRUE;
    }

    // Suspend the thread to safely retrieve its context
    SuspendThread(hThread);

    // Initialize the context structure and set ContextFlags to get full context
    context.ContextFlags = CONTEXT_FULL | CONTEXT_AMD64;

    // Retrieve the thread context
    if (GetThreadContext(hThread, &context)) {
        // Print general-purpose registers
        context.Dr6 = 0;
        context.Dr0 = 0xDEADBEEF;
        context.Dr1 = 0xDEADBEEF;
        context.Dr2 = 0xDEADBEEF;
        context.Dr3 = 0xDEADBEEF;

        printf("RAX: %016llX\n", context.Rax);
        printf("RBX: %016llX\n", context.Rbx);
        printf("RCX: %016llX\n", context.Rcx);
        printf("RDX: %016llX\n", context.Rdx);

        // Print more registers as needed...
    } else {
        printf("Error: Unable to get thread context.\n");
        return FALSE;
    }

    // Resume the thread
    ResumeThread(hThread);

    // Close the handle to the thread
    CloseHandle(hThread);

    return TRUE;
}

BOOL GetPEBFromAnotherProcess(HANDLE hProcess) {
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

    PEB pbi;
    PROCESS_BASIC_INFORMATION proc = {0};
    ULONG returnlen;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc, sizeof(PROCESS_BASIC_INFORMATION), &returnlen);
    if (status != 0) {
        printf("NtQueryInformationProcess failed (Status 0x%08X)\n", status);
        return FALSE;
    }
    
   // printf("PEB Address of the target process: %s\n", proc.PebBaseAddress);
    printf("Peb address: %p", proc.PebBaseAddress);
    
    PEB_LDR_DATA ldrData;
    if (ReadProcessMemory(hProcess, proc.PebBaseAddress, &pbi, sizeof(pbi), NULL)) {
        printf("\nImage Base Address of the target process: %p\n", proc.PebBaseAddress);
    } else {
        printf("Failed to read PEB from the target process (Error %lu)\n", GetLastError());
        return FALSE;
    }

    printf("\x1B[31m+isBeingDebugged: %i\n\x1B[0m", pbi.BeingDebugged);

    size_t bytesread;
    //printf("%p", peb.LoaderData->Length);
    printf("Ldr address: %p\n", pbi.Ldr);
    if (!ReadProcessMemory(hProcess, (LPCVOID)pbi.Ldr , &ldrData, sizeof(ldrData), &bytesread)) {
            printf("error\n");
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
        if (!ReadProcessMemory(hProcess, currentEntry.Flink, &ldrEntry, sizeof(ldrEntry), NULL)) {
            printf("Failed to read LDR_DATA_TABLE_ENTRY (Error %lu)\n", GetLastError());
            return FALSE;
            break;
        }
        


        // Print DLL details
        WCHAR dllName[MAX_PATH];
        wprintf(L"Length DLL fullname: %p\n", ldrEntry.FullDllName.Buffer);
        if (ldrEntry.FullDllName.Length > 0 &&
            ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &dllName, ldrEntry.FullDllName.Length, NULL)) {
            dllName[ldrEntry.FullDllName.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate the string
            wprintf(L"Module: %ls\n", dllName);
        } else {
            printf("Must be admin to pull modules!");
            return FALSE;
            
        }

        

        currentEntry = *ldrEntry.InMemoryOrderLinks.Flink;

    } while (currentEntry.Flink != &ldrData.InMemoryOrderModuleList);
    return TRUE;
}   

int main(int argc, char* argv[]) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (argc < 1) {
        printf("Usage: ./peb <path to file>");
    } 
    logo();
    char *process = argv[1];
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
        printf("Debugging %s:\n", argv[1]);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
                if (!hProcess) {
                    printf("Problem starting the debugger\n");
                } else {
                    DWORD *threadId = pi.dwThreadId;
                    if (threadId == NULL) {
                        printf("Error getting the thread ID...\n");
                        return 1;
                    } 
                    printf("thread address/ID: %p\n", &threadId);
                    if (!getThreads(threadId)) {
                        printf("Error reading thread context\n");
                    }
                    
                }

            /* while () {
                char* buffer = (char*)malloc(50 * sizeof(char));
                printf("Debugger>>");
                fgets(buffer, 49, stdin);

                if (strcmp(buffer, "get rdx")) {
                    readRdxReg(hProcess, context);
                }

                if (strcmp(buffer, "exit")) {
                    printf("Goodbye!");
                    return 1;
                }
            }
        */
        WaitForInputIdle(pi.hProcess, INFINITE);
        GetPEBFromAnotherProcess(hProcess); 

        CloseHandle(hProcess);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("Failed to open %s. Error: %lu\n", argv[1], GetLastError());
    }

    return 0;
}

