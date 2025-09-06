#include <Windows.h>

#pragma comment(lib, "Psapi.lib")

BOOL getVariables(DWORD procId) {

BYTE *baseAddress = (BYTE*)malloc(100 * sizeof(BYTE));

HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
if (!hProcess) {
    printf("error opening process\n");
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

for (int i=0; i < nt.FileHeader.NumberOfSections; i++) {
    
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)), &section, sizeof(IMAGE_SECTION_HEADER), NULL)) {
    printf("Error reading section memory %lu", GetLastError());
    }

// This gets the .data and pulls the buffer using a loop
if (strcmp((char *)section.Name, ".data") == 0 || strcmp((char *)section.Name, ".bss") == 0) {

    printf("Scanning");
    for (int i=0; i < 3; i++) {
        printf(".");
        Sleep(500);
    }
    printf("\n");

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
    }

    }
    
}
fclose(hProcess);
return TRUE;
}

int main(int argc, char* argv[]) {

if (argc < 2) {
    printf("Usage: %s <procID>\n", argv[0]);
    return 1;
}

//converting char to DWORD (32 bit)
DWORD procId = (DWORD)atoi(argv[1]);
if (!getVariables(procId)) {
    printf("Something went horribly wrong abort\n");
}


}
