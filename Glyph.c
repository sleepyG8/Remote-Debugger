#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <securitybaseapi.h>
#include <sddl.h> 
#include <AclAPI.h>
#include <dbghelp.h>
#include "capstone/capstone.h"
//add terminate

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "capstone.lib")

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

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,       // Workstation
    NtProductLanManNt,        // Server
    NtProductServer           // Domain Controller
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

#define PROCESSOR_FEATURE_MAX 64

typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    KSYSTEM_TIME InterruptTime;
    KSYSTEM_TIME SystemTime;
    KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunlevel;
    LONG TimeZoneBiasStamp;
    ULONG NtBuildNumber;
    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG Reserved1;
    ULONG Reserved3;
    ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG BootId;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT CyclesPerYield;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        };
    };
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;
    ULONG SystemCall;
    ULONG Reserved2;
    ULONGLONG FullNumberOfPhysicalPages;
    ULONGLONG SystemCallPad[1];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64 TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        };
    };
    ULONG Cookie;
    ULONG CookiePad[1];
    LONGLONG ConsoleSessionForegroundProcessId;
    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;
    ULONG EnclaveFeatureMask[4];
    ULONG TelemetryCoverageRound;
    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;
    ULONGLONG Reserved4;
    ULONGLONG InterruptTimeBias;
    ULONGLONG QpcBias;
    ULONG ActiveProcessorCount;
    UCHAR ActiveGroupCount;
    UCHAR Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION XState;
    KSYSTEM_TIME FeatureConfigurationChangeStamp;
    ULONG Spare;
    ULONG64 UserPointerAuthMask;
    XSTATE_CONFIGURATION XStateArm64;
    ULONG Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

// KUSER_SHARED_DATA has a fixed address
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

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

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *pNtQueryVirtualMemory)(
    HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T
);

typedef struct _WIN_CERTIFICATE
{
    DWORD       dwLength;
    WORD        wRevision;
    WORD        wCertificateType;   // WIN_CERT_TYPE_xxx
    BYTE        bCertificate[ANYSIZE_ARRAY];

} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

// storing all imports and its address into a struct
typedef struct {
    char name[150];
    FARPROC address;
} Imports;

typedef struct {
    wchar_t modName[256];
    FARPROC modAddress;
} Dlls;

Imports* imports = NULL;
size_t countImport = 0;

int Score; // Globally Function tracking
BOOL MalCheck(char* funcName) {

if (strcmp(funcName, "VirtualAlloc") == 0) {
Score += 30;
}

else if (strcmp(funcName, "WriteProcessMemory") == 0) {
Score += 30;
}

if (strcmp(funcName, "VirtualAllocEx") == 0) {
Score += 30;
}

else if (strcmp(funcName, "CreateRemoteThread") == 0) {
Score += 50;
}

else if (strcmp(funcName, "CreateRemoteThreadEx") == 0) {
Score += 50;
}

return TRUE;
}


// checking for + and reading until and checking in between from capstone op_str
DWORD64 extract_offset_from_operand(const char* op_str) {

    const char* plus = strstr(op_str, "+");
    if (!plus) return 0;

    const char* end = strchr(plus, ']');
    if (!end) return 0;

    char temp[32] = {0};
    strncpy(temp, plus + 1, end - plus - 1);

    return strtoull(temp, NULL, 0);
    }


BYTE* makeMem(int size) {

    BYTE* remoteMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    return remoteMem;
}

int allocStdin(BYTE* remoteMem, int startingOffset, FILE* data) {

    // Cannot overun because 100 input can never overrun the 200 safety gap
    if (startingOffset + 200 >= 0x2000) {
        printf("Buffer is getting full, free is coming soon, restart the app...\n");
    }

    int i = 0;
    int ch;

    while ((ch = fgetc(data)) != EOF && ch != '\n' && i < 100) {
        // Safety check
        if ((startingOffset + i) < 0x2000) {
        remoteMem[startingOffset + i] = (BYTE)ch;
        }
        i++;
    }

    int sizeOfData = i;

    // storing offset of data
    uintptr_t offset = (uintptr_t)remoteMem[startingOffset + i];

    for (int j = 0; j < 100; j++) {
    remoteMem[startingOffset + sizeOfData + j] = 0x00;
    }

    //printf("Offset: %llx\n", startingOffset + sizeOfData);

    return startingOffset + sizeOfData + 100;

}

BYTE* readAlloc(BYTE* remoteMem, int startingOffset) {

    BYTE* temp = malloc(100);
    int i;
    for (i=0; i < 100; i++) {

        if (remoteMem[startingOffset + i] == 0x00) break;

        temp[i] = remoteMem[startingOffset + i];

        //printf("%02X ", temp[i]);

    }

    temp[i] = 0x00;

    return temp;


}

// Capstone disasm
BOOL disasm(HANDLE hProcess, uint8_t *code, int size, uint64_t address) {
    csh handle;
    cs_insn *insn;
    size_t count;

    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return -1;
    }

    // Disassemble
    count = cs_disasm(handle, code, size, address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {

                //int didntPrintf = 0;
                for (int k=0; k < countImport; k++) {

                //printf("%s - %s\n", insn[i].op_str, addrStr);

                if (strstr(insn[i].op_str, "[rip +") != NULL) {


                    uint64_t rip = insn[i].address + insn[i].size;

                    DWORD64 offset = extract_offset_from_operand(insn[i].op_str);

                    //printf("offset %lu\n", offset);

                    uint64_t finalAddress = rip + offset;
                            
                    uint64_t finalComputedAddress = 0;
                    if (!ReadProcessMemory(hProcess, finalAddress, &finalComputedAddress, 8, NULL)) {
                        printf("Error reading %lu\n", GetLastError());
                    }
                    
                   // if (didntPrintf == 0 && finalComputedAddress != 0) {
                     //   printf("\x1b[32mFunction Address:\x1b[0m %llX\n", finalComputedAddress);
                       // didntPrintf = 1;
                    //}

                   // uint64_t addrStr[32];
                   //sprintf(addrStr, "0x%"PRIx64, (uint64_t)imports[k].address);

                    //printf("Final: %llX - %llX\n", finalAddress, (uint64_t)imports[k].address);

                    if (finalComputedAddress == (uint64_t)(uintptr_t)imports[k].address) {
                    
                        printf("\x1b[32m%s ->\x1b[0m 0x%"PRIx64":\t%s\t%s\n", imports[k].name, (uint64_t)imports[k].address, insn[i].mnemonic, insn[i].op_str);
                    
                        // Checking function names and giving a global Score
                        MalCheck(imports[k].name);

                        if (Score > 60) {
                            printf("Malicous File found!");
                            getchar();
                        }

                        continue;
                }
            }

                if (strncmp(insn[i].op_str, "0x", 2) == 0) {

                DWORD64 final = strtoull(insn[i].op_str, NULL, 0);

                //printf("Final: %llX - %llX\n", final, (uint64_t)imports[k].address);


                if (final == (uint64_t)(uintptr_t)imports[k].address) {
                    puts("Import Found\n");
                    printf("\x1b[32m%s ->\x1b[0m 0x%"PRIx64":\t%s\t%s\n", 
                    imports[k].name,
                    (uint64_t)imports[k].address,  
                    insn[i].mnemonic, 
                    insn[i].op_str);
                    continue;
                }

            }

            }

            printf("0x%"PRIx64":\t%s\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str, insn[i].bytes);

            if (i == count) {
                printf("[END]");
            }
        }

        cs_free(insn, count);
    } else {
        printf("Failed to disassemble\n");
    }

    cs_close(&handle);
    return 0;
}

BOOL getSystemInfo() {
    KUSER_SHARED_DATA* sharedData = (KUSER_SHARED_DATA*)(0x7FFE0000);
    KSYSTEM_TIME systemTime = sharedData->SystemTime;
   
    printf("TickCountLowDeprecated: %lu\n", sharedData->TickCountLowDeprecated);
    printf("TickCountMultiplier: %lu\n", sharedData->TickCountMultiplier);
    printf("SystemTime.LowPart: %lu\n", sharedData->SystemTime.LowPart);
    printf("NtSystemRoot: %ws\n", sharedData->NtSystemRoot);
    printf("NtBuildNumber: %lu\n", sharedData->NtBuildNumber);
    printf("NtProductType: %d\n", sharedData->NtProductType);
    printf("ProductTypeIsValid: %d\n", sharedData->ProductTypeIsValid);
    printf("NtMajorVersion: %lu\n", sharedData->NtMajorVersion);
    printf("NtMinorVersion: %lu\n", sharedData->NtMinorVersion);
    printf("SuiteMask: %lu\n", sharedData->SuiteMask);
    printf("KdDebuggerEnabled: %d\n", sharedData->KdDebuggerEnabled);
    printf("ActiveConsoleId: %lu\n", sharedData->ActiveConsoleId);
    printf("SafeBootMode: %d\n", sharedData->SafeBootMode);
    printf("ConsoleSessionForegroundProcessId: %lld\n", sharedData->ConsoleSessionForegroundProcessId);
    printf("QpcFrequency: %lld\n", sharedData->QpcFrequency);
    printf("SystemCall: %lu\n", sharedData->SystemCall);
    printf("Cookie: %lu\n", sharedData->Cookie);
    printf("TimeUpdateLock: %llu\n", sharedData->TimeUpdateLock);
    printf("QpcBias: %llu\n", sharedData->QpcBias);
    printf("ActiveProcessorCount: %lu\n", sharedData->ActiveProcessorCount);
    printf("UserPointerAuthMask: %llu\n", sharedData->UserPointerAuthMask);
    printf("Boot ID: %lu\n", sharedData->BootId);

    return 0;
}

IMAGE_THUNK_DATA thunkData;

// Helper Remote to get VA
UINT RvaToFileOffset(HANDLE hProcess, BYTE* baseAddress, UINT rva) {
    IMAGE_DOS_HEADER dh;
    if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
        printf("Error reading DOS header\n");
        return -1;
    }

    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, baseAddress + dh.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
        printf("Error reading NT headers\n");
        return -1;
    }

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!sections) {
        printf("Memory allocation failed\n");
        return -1;
    }

    DWORD sectionOffset = dh.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

    if (!ReadProcessMemory(hProcess, baseAddress + sectionOffset, sections,
                           sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections, NULL)) {
        printf("Error reading section headers\n");
        free(sections);
        return -1;
    }

    
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section = sections[i];
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            free(sections);
            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }

    free(sections);
    return -1; 
}

//Helper to get VA
BYTE* VAFromRVA(DWORD rva, PIMAGE_NT_HEADERS nt, BYTE* base) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    //printf("hello\n");
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD sectionVA = section->VirtualAddress;
        DWORD sectionSize = section->Misc.VirtualSize;
           // printf("hello2\n");

        if (rva >= sectionVA && rva < (sectionVA + sectionSize)) {
            return base + section->PointerToRawData + (rva - sectionVA);
        }
    }

    return NULL;
}


size_t capacity = 0;
// making Dynamic struct for imports
void addImport(char* funcName, FARPROC addr) {
    if (countImport >= capacity) {
        capacity = (capacity == 0) ? 4 : capacity * 2;
        imports = realloc(imports, capacity * sizeof(Imports));
        if (!imports) {
            printf("Memory allocation failed\n");
            exit(1);
        }
    }

    strncpy(imports[countImport].name, funcName, sizeof(imports[countImport].name) - 1);
       
    //printf("func: %s\n", imports[countImport].name);

    imports[countImport].address = addr;
    countImport++;
}

size_t modCapacity = 0;
Dlls* modules;
size_t countModules = 0;
// making Dynamic struct for Modules
void addModule(wchar_t* funcName, FARPROC addr) {

    if (!funcName) return;

    if (countModules >= modCapacity) {
        modCapacity = (modCapacity == 0) ? 4 : modCapacity * 2;
        modules = realloc(modules, modCapacity * sizeof(Dlls));
        if (!modules) {
            printf("Memory allocation failed\n");
            exit(1);
        }
    }

    // copying funcName buffer into the global modules struct, see line 327
    wcscpy_s(modules[countModules].modName, 256, funcName);

    // Setting address
    modules[countModules].modAddress = addr;

    countModules++;
}

BOOL listModules() {
    for (int i=0; i < countModules; i++) {

        if (i == 0) {
            wprintf(L"\x1b[92m[+]\x1b[0m Base Address: %s\n", modules[i].modName);
        } else {
            wprintf(L"\x1b[92m[+]\x1b[0m Module %lu: %s\n", i, modules[i].modName);
            printf("\x1b[92m[+]\x1b[0m Address: 0x%llX\n", modules[i].modAddress);
        }

        if (i == countModules) {
            puts("[END]");
        }

        printf("+++++++++++++++++++++++++++++++++\n");

    }
    return TRUE;
}

int breakpointSet = 0;
// Reading Imported Apis
int getRemoteImports(HANDLE hProcess, char* breakFunction, BOOL entry) {

printf("+++++++++++++++++++++++++++++++++++++++++++\n");

if (breakpointSet == 0) {
printf("Remote Imports:\n");
printf("Base: %p\n", (void*)peb.Base);
}


//getting base address
BYTE* baseAddress = peb.Base;

if (peb.Base == 0) return 1;

//reading dos header
IMAGE_DOS_HEADER dh;

if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
    printf("error reading memory of process ID\n");
   return 1;
}

//checks for a valid PE file
if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3 %lu\n", GetLastError());
    return 1;
} else {
    printf("Valdid PE file: YES-%x\n", dh.e_magic);
}


//getting nt headers
#ifdef _WIN64
IMAGE_NT_HEADERS64 nt;
#else
IMAGE_NT_HEADERS32 nt;
#endif

if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return 1;
}

//optional headers
IMAGE_OPTIONAL_HEADER oh;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader), 
                       &oh, sizeof(IMAGE_OPTIONAL_HEADER), NULL)) {
    printf("Error reading Optional Header\n");
    return 1;
}

if (entry == 1) {
uintptr_t entry = (uintptr_t)baseAddress + oh.AddressOfEntryPoint;
printf("Entry: %p\n", (void*)entry);
return 0;
}


//some dlls like ntdll dont have imports
if (oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
    printf("Does not have any imports.\n");
    return 1;
} 


// This pain in the ass loop
// I had to do this to loop through properly
BYTE* importDescAddr = (BYTE*)baseAddress + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

while (importDescAddr != 0) {

// reading (BYTE*)baseAddress + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress from remote process
IMAGE_IMPORT_DESCRIPTOR id;
if (!ReadProcessMemory(hProcess, importDescAddr, &id, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL)) {
    printf("error reading the import descriptor\n");
    return 1;
}


//Check
if (id.Name == 0) break;

// Getting import name from id using id.Name
char* importName[256];
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + id.Name, 
                       importName, sizeof(importName), NULL)) {
    return 1;
}

if (breakpointSet == 0) {
printf("%s\n", (char*)importName);
}

//if (strcmp(importName, "OLEAUT32.dll") == 0) break;

// use these for looping
uintptr_t origThunkAddr = (uintptr_t)baseAddress + id.OriginalFirstThunk;
uintptr_t thunkAddr     = (uintptr_t)baseAddress + id.FirstThunk;

//////////////////////////////////////////
// these are only for the first read
IMAGE_THUNK_DATA origThunk = {0};
IMAGE_THUNK_DATA thunkData = {0};

if (!ReadProcessMemory(hProcess, (LPVOID)((BYTE*)origThunkAddr), &origThunk, sizeof(IMAGE_THUNK_DATA), NULL)) {
    printf("error %lu\n", GetLastError());
    return 1;
}

if (!ReadProcessMemory(hProcess, (LPVOID)((BYTE*)thunkAddr), &thunkData, sizeof(IMAGE_THUNK_DATA), NULL)) {
    printf("error 2 %lu\n", GetLastError());
    return 1;
}
///////////////////////////////////////////

while (TRUE) {
        
        // read orig and thunk addr in the loop again to stop infinite loop
        if (!ReadProcessMemory(hProcess, (LPCVOID)origThunkAddr, &origThunk, sizeof(origThunk), NULL) || !ReadProcessMemory(hProcess, (LPCVOID)thunkAddr, &thunkData, sizeof(thunkData), NULL)) {
            printf("error reading thunk\n");
            break;
            }

        if (origThunk.u1.AddressOfData == 0) break;

        IMAGE_IMPORT_BY_NAME importByName;

        if (!ReadProcessMemory(hProcess, (LPCVOID)((BYTE*)baseAddress + origThunk.u1.AddressOfData), &importByName, sizeof(IMAGE_IMPORT_BY_NAME), NULL)) {
            printf("error 3 %lu\n", GetLastError());
            }

        if (importByName.Name != NULL) {
        FARPROC funcAddr = (FARPROC)thunkData.u1.Function;
        

        // read into larger buffer
        BYTE importBuffer[256] = {0};  // Enough to hold most function names
        if (!ReadProcessMemory(hProcess, (LPCVOID)((BYTE*)baseAddress + origThunk.u1.AddressOfData), &importBuffer, sizeof(importBuffer), NULL)) {
        printf("error 4 %lu\n", GetLastError());
        }

        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)importBuffer;

        if (breakpointSet == 0)  {
        printf("+ %s\n", importByName->Name);
        printf("Function Address: 0x%p\n", funcAddr);
        }

        addImport(importByName->Name, funcAddr);
        
        BYTE hookedBytes[5];
        ReadProcessMemory(hProcess, funcAddr, &hookedBytes, sizeof(hookedBytes), NULL);

        if (hookedBytes[0] == 0xE9) {
            printf("\033[31m[!]\033[0m [Hook detected! at ");
            printf("%s ", importByName->Name);
            printf("Function Address: 0x%p]\n", funcAddr);
        }


        BYTE patch[10];
        memset(patch, 0xCC, sizeof(patch));

        if (breakFunction != NULL && strcmp(importByName->Name, breakFunction) == 0) {
            if (!WriteProcessMemory(hProcess, funcAddr, &patch, sizeof(patch), NULL)) {
                printf("error\n");
                return 0;
            } else {
                printf("\n++++++++++++++++\033[31mBreakPoints\033[0m++++++++++++++++\n");

                printf("\033[31mWrote a breakpoint at 0x%llX on function [%s]\033[0m\n", funcAddr, importByName->Name);
                return 0;
            }
        }

        }
        
        origThunkAddr += sizeof(IMAGE_THUNK_DATA);
        thunkAddr     += sizeof(IMAGE_THUNK_DATA);
            
        }
    
if (breakpointSet == 0) {
printf("+++++++++++++++++++++++++++++++++++++++++++\n");
}

// Move forward 1 ID just like my ID++
importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
}
}

BOOL logo() {
    
    //aunt ansi came to town
        printf("\x1B[2J");
    
        printf("\x1B[2;20H");
        printf("\x1B[37;44m");
        printf("Debugger By Sleepy:\n                            v1.1.1\n");
    
        printf("\x1B[4;1H");

        for (int i = 0; i < 100; i++) {
            printf("+");
        }
        
        puts("\n");
        printf("\x1B[0m");
        
        return 0;
    }

// Reading Raw address and parsing the data
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
    for (SIZE_T i = 0; i < bytesRead; i++) {
        if (isprint(buff[i])) {  // Very useful to print only valid chars
        printf("%c ", buff[i]);;
        //if ((i +1) % 12 == 0) printf("\n");
    }
}
    printf("\n");

    printf("\x1b[92m[+]\x1b[0m Raw: \n");
    for (SIZE_T i = 0; i < bytesRead; i++) {
    printf("%02X ", buff[i]);   
    if ((i +1) % 12 == 0) printf("\n");     
    }
    
    printf("\n");

    typedef BOOL (WINAPI* pCheckEntropy)(char* buff, size_t size);

    //Entropy Check
    HANDLE hEdll = LoadLibrary("entropyCheck.dll");
    if (hEdll) {

    pCheckEntropy CE = (pCheckEntropy)GetProcAddress(hEdll, "CheckEntropy");
    if (!CE) return 1;
    puts("\nEntropy Checker Extention:\n-------------------------------");

    CE(buff, bytesRead);

    }
    
    // capstone
    puts("\n------\x1b[92m[+]Dissassembly:\x1b[0m------");

    disasm(hProcess, buff, bytesToRead, base);
    //free(buff); // Free allocated memory
    return TRUE;
}

// Getting Context of the desired thread ID
BOOL getThreads(DWORD *threadId) {
    HANDLE hThread;

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread. %lu\n", GetLastError());
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
        printf("RSI: 0x%016llX\n", context.Rsi);
        printf("RDI: 0x%016llX\n", context.Rdi);
        printf("RSP: 0x%016llX\n", context.Rsp);
        printf("RBP: 0x%016llX\n", context.Rbp);
        printf("R8 : 0x%016llX\n", context.R8);
        printf("R9 : 0x%016llX\n", context.R9);
        printf("R10: 0x%016llX\n", context.R10);
        printf("R11: 0x%016llX\n", context.R11);
        printf("R12: 0x%016llX\n", context.R12);
        printf("R13: 0x%016llX\n", context.R13);
        printf("R14: 0x%016llX\n", context.R14);
        printf("R15: 0x%016llX\n", context.R15);

        printf("EFlags: 0x%08X\n", context.EFlags);

        printf("CS: 0x%04X\n", context.SegCs);
        printf("DS: 0x%04X\n", context.SegDs);
        printf("ES: 0x%04X\n", context.SegEs);
        printf("FS: 0x%04X\n", context.SegFs);
        printf("GS: 0x%04X\n", context.SegGs);
        printf("SS: 0x%04X\n", context.SegSs);

    } else {
        printf("Error: Unable to get thread context. %lu\n", GetLastError());
        return FALSE;
    }

    ResumeThread(hThread);

    CloseHandle(hThread);

    return TRUE;
}

PVOID ntdllBase;
MYPEB pbi;
WCHAR dllName[MAX_PATH] = {0};
// Peb :)
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
            //wprintf(L"%ws\n", myparams.fullPath);
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

       // printf("\n\033[35m+-----------Modules-----------+\033[0m\n");
     LIST_ENTRY* head = &ldrData.InLoadOrderModuleList;
     LIST_ENTRY* currentEntry = head->Flink;
    
    while (currentEntry != head) {
        DWORD bytes;
        MY_LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        if (!ReadProcessMemory(hProcess, currentEntry, &ldrEntry, sizeof(MY_LDR_DATA_TABLE_ENTRY), &bytes)) {
            //printf("\x1b[92m[!]\x1b[0m Done\n");
            return FALSE;
        }

        WCHAR name[MAX_PATH] = {0};
        if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &name, ldrEntry.FullDllName.Length, NULL)) {
            //printf("\x1b[92m[!]\x1b[0m Done\n");
            return FALSE;
        }

        // Setting Global struct
        if (wcscmp(myparams.fullPath, name) == 0) {
        //wprintf(L"%ws - %ws\n", myparams.fullPath, name);
        //puts("hello");
        peb.Base = ldrEntry.DllBase;
        }

        if (wcscmp(L"C:\\Windows\\SYSTEM32\\ntdll.dll", name) == 0) {
            ntdllBase = ldrEntry.DllBase;
        }

        // Patching Infinite loop bug on some Windows versions
        if (ldrEntry.DllBase == 0x0) break;

        //wprintf(L"\x1b[92m[+]\x1b[0m Module: %s\n", name);
        //printf("\x1b[92m[+]\x1b[0m Base Address: 0x%llX\n", ldrEntry.DllBase);

        // Adding to a struct
        addModule(name, ldrEntry.DllBase);
        
        currentEntry = ldrEntry.InLoadOrderLinks.Flink;
       
    }
        return TRUE;
    
    }

// Getting the security descriptor of a provided handle
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
// Listing all processes
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

    ULONG returnLen;
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


    ULONG threadCount = info->NumberOfThreads;

    // info + 1 walks from process struct to thread struct
    PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)(info + 1);

    for (int i=0; i < info->NumberOfThreads; i++) {
        printf("Thread # %lu - ", threads[i].ClientId.UniqueThread);
    }

    printf("\n");


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

// Getting CPU count and info
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

// hardware breakpoint
BOOL breakpoint(DWORD threadId, PVOID address, HANDLE hProcess) {

    printf("Address: %p\n", address);
    CONTEXT contextBreak;
    HANDLE hThread;
 
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, threadId);
    if (hThread == NULL) {
        printf("Error: Unable to open thread. %lu\n", GetLastError());
        return TRUE;
    }
/*
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

*/

   if (SuspendThread(hThread) == -1) {
    printf("failed to suspend %lu\n", GetLastError());
    return FALSE;
   }
    
    // Helps with getting context maybe? idk you can remove probably
    Sleep(1000);

    contextBreak.ContextFlags = CONTEXT_FULL | CONTEXT_AMD64;
    //setting conetext can help avoid detection
    if (GetThreadContext(hThread, &contextBreak)) {
        
        contextBreak.Dr1 = (DWORD64)(uintptr_t)address;
        contextBreak.Dr7 |= (1 << 2);  // Enable DR1
        contextBreak.Dr7 |= (3 << 20); // Break on execution
        contextBreak.Dr7 |= (0 << 22); // 1-byte breakpoint
        SetThreadContext(hThread, &contextBreak);

        printf("RIP: 0x%016llX\n", contextBreak.Rip);
        printf("RAX: 0x%016llX\n", contextBreak.Rax);
        printf("RBX: 0x%016llX\n", contextBreak.Rbx);
        printf("RCX: 0x%016llX\n", contextBreak.Rcx);
        printf("RDX: 0x%016llX\n", contextBreak.Rdx);
        printf("DR1: 0x%016llX\n", contextBreak.Dr1);

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

    BYTE* address = (BYTE*)peb.Base + section.VirtualAddress;
    printf("\x1b[92m[+]\x1b[0m Section: %s | Address: 0x%p | Size: %d\n", section.Name, (void*)address, section.SizeOfRawData);

    char buffer[0x1000];
    if (!ReadProcessMemory(hProcess, (BYTE*)peb.Base + section.VirtualAddress, &buffer, sizeof(buffer), NULL)) {
        printf("Error reading data %lu\n", GetLastError());
    } else {
            for (int i = 0; i < sizeof(buffer); i++) {
            if (isprint(buffer[i])) {  // Very useful to print only valid chars
        printf("%c ", buffer[i]);
    }
    }
    printf("\n");

    // Mining
    if (section.Misc.VirtualSize > section.SizeOfRawData) {
    DWORD codeCaveSize = section.Misc.VirtualSize - section.SizeOfRawData;
    DWORD caveEntry = section.PointerToRawData + section.SizeOfRawData;

    printf("Cave Found: %p - Size: %lu\n", (BYTE*)peb.Base + caveEntry, codeCaveSize);

    }
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

DWORD threadid;
DWORD GetProc(wchar_t* procName) {

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
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return FALSE;
    }

    //printf("%lu\n", returnLen);
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

    // no "NULL" buffers
    if (info->ImageName.Buffer && info->ImageName.Length > 0) {
        
    if (wcscmp(info->ImageName.Buffer, procName) == 0) {

        ULONG threadCount = info->NumberOfThreads;

        // info + 1 walks from process struct to thread struct
        PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)(info + 1);

        threadid = threads[info->NumberOfThreads - 1].ClientId.UniqueThread;

        return info->UniqueProcessId;
    }
}



    //wprintf(L"\x1b[92m[+]\x1b[0m Image Name: %ls\n", info->ImageName.Buffer ? info->ImageName.Buffer : L"NULL, no image name\n");
    //printf("Number of Threads (process): %lu\n", info->NumberOfThreads);
    //printf("Next Entry offest: %lu\n", info->NextEntryOffset);
    //printf("Handle count: %lu\n", info->HandleCount);
   // printf("Memory Usage: %llu\n", info->VirtualSize);
    //printf("Process ID: %i\n", (int)info->UniqueProcessId);
    //printf("+++++++++++++++++++++++++++++++++++++++++++\n");
    procCount++;
    if (info->NextEntryOffset == 0) break;
    info = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)info + info->NextEntryOffset); //loop through using next next entry offset
}
   
   // printf("\x1b[92m[+]\x1b[0m # of processes: %i\n", procCount);

    return 0;
}

// Getting files signature
int getSignature(wchar_t* readFile) {

FILE* file = _wfopen(readFile, L"rb");
if (!file) {
    puts("error\n");
    return 1;
}

//wprintf(L"%ws\n", readFile);
fseek(file, 0, SEEK_END);
size_t size = ftell(file);
fseek(file, 0, SEEK_SET);

BYTE* buff = malloc(size);

if (!fread(buff, 1, size, file )) {
    printf("error\n");
    return 1;
 }

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buff;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid PE file\n");
    return 1;
}

PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("error 2\n");
    return 1;
}


PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
    printf("Does not have any imports.\n");
    return 1;
}

DWORD secOffset = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
LPWIN_CERTIFICATE id = (LPWIN_CERTIFICATE)(buff + secOffset);

if (secOffset == 0) {
    printf("No signature.\n");
    return 1;
}


printf("Signature:\n-----------\n");

for (int i=0; i < id->dwLength; i++) {
printf("%02X ", id->bCertificate[i]);
// Learned this 
if ((i + 1) % 16 == 0) printf("\n");
}

printf("+++++++++++++++++++++++++++++++++\n");
return 0;
}

BOOL cfgCheck(wchar_t* readFile) {

FILE* file = _wfopen(readFile, L"rb");

fseek(file, 0, SEEK_END);
size_t size = ftell(file);
fseek(file, 0, SEEK_SET);

BYTE* buff = malloc(size);

if (!fread(buff, 1, size, file )) {
    printf("error\n");
    return 1;
 }

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buff;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid PE file\n");
    return 1;
}

PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("error 2\n");
    return 1;
}

PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

PIMAGE_LOAD_CONFIG_DIRECTORY64  id = (PIMAGE_LOAD_CONFIG_DIRECTORY64)VAFromRVA(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, nt, buff);
if (!id) {
    printf("error\n");
    return 1;
}

if (id->GuardFlags != 0) {
    wprintf(L"CFG protections FOUND on - %ws\n", readFile);
    if (id->GuardFlags == 0x00417500) {
        puts("XFG enabled\n");
    }
} else {
    wprintf(L"*No CFG detected on - [%ws]*\n", readFile);
}

return 0;
}

// DLL check
BOOL isDLL = 0;
// Getting DLL exports
BOOL dllExports(wchar_t* path) {

// wide load
HMODULE hMod = LoadLibraryExW(path, NULL, 0);
if (!hMod) {
    printf("Wrong path...\n");
    return 1;
}

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3\n");
    return 1;
}


PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("error 2\n");
    return 1;
}


PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

PIMAGE_DATA_DIRECTORY exportDataDir = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)oh->ImageBase + exportDataDir->VirtualAddress);


int functionNum = 0;
DWORD* nameRVAs = (DWORD*)((BYTE*)oh->ImageBase + exportDir->AddressOfNames);
for (size_t i = 0; i < exportDir->NumberOfNames; i++) {
    functionNum++;
    printf("%i: ", functionNum);
    printf("Function: %s\n", (char*)oh->ImageBase + nameRVAs[i]);
}

printf("# of functions: %lu\n", exportDir->NumberOfFunctions);
printf("address of functions: 0x%p\n", (void*)exportDir->AddressOfFunctions);
printf("Image base: 0x%p\n", (void*)oh->ImageBase);


return 0;
}

// Getting DLL imports
BOOL dllImports(wchar_t* path) {

HMODULE hMod = LoadLibraryExW(path, NULL, 0);
if (!hMod) {
    printf("Wrong path...\n");
    return 1;
}

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    return 1;
} else {
    printf("Valdid PE file: %x\n", dh->e_magic);
}

PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return 1;
}

PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
    printf("Does not have any imports.\n");
    return 1;
}

PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)oh->ImageBase + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

while (id->Name != 0) {
    printf("Import: %s\n", (char*)oh->ImageBase + id->Name);
    printf("Characteristics: %X\n", id->Characteristics);
    id++; // Move to the next one
}

return 0;
}

BOOL dumpHandle(ULONG_PTR procNum) {

HANDLE hNtdll = GetModuleHandle("ntdll.dll");

pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

ULONG retlen = 0;

// 64 is for Handles system wide enumeration
NTSTATUS status = NtQuerySystemInformation(64, NULL, 0, &retlen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return 1;
    }

    //Global set
    SYSTEM_HANDLE_INFORMATION_EX* handles = NULL;

    // loop to get entire retlen becuase handles update a lot
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
    handles = (SYSTEM_HANDLE_INFORMATION_EX*)malloc(retlen);
    status = NtQuerySystemInformation(64, handles, retlen, &retlen);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        free(handles);
    }
    }

    for (ULONG_PTR i=0; i < handles->NumberOfHandles; i++) {
     SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX data = handles->Handles[i];

     // Compare
    if (procNum == data.UniqueProcessId) {
         printf("PID: %llu | Handle: 0x%llx | Type: %hu\n", (unsigned long long)data.UniqueProcessId, (unsigned long long)data.HandleValue, data.ObjectTypeIndex);
        }
    
    }


    return TRUE;
}

///////////////////////////////////////////////////////////////////
//         Reading elfs from disk using raw parsing              //
///////////////////////////////////////////////////////////////////

// Sleepy 2025

typedef unsigned short      uint16_t;  
typedef unsigned int        uint32_t;  
typedef unsigned long long  uint64_t;  

// structs who needs elf.h
typedef struct {
    unsigned char e_ident[16]; // Magic number and other info
    uint16_t e_type;           // Object file type
    uint16_t e_machine;        // Architecture
    uint32_t e_version;        // Object file version
    uint64_t e_entry;          // Entry point virtual address
    uint64_t e_phoff;          // Program header table file offset
    uint64_t e_shoff;          // Section header table file offset
    uint32_t e_flags;          // Processor-specific flags
    uint16_t e_ehsize;         // ELF header size in bytes
    uint16_t e_phentsize;      // Program header table entry size
    uint16_t e_phnum;          // Program header table entry count
    uint16_t e_shentsize;      // Section header table entry size
    uint16_t e_shnum;          // Section header table entry count
    uint16_t e_shstrndx;       // Section header string table index
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;    // Segment type
    uint32_t p_flags;   // Segment flags
    uint64_t p_offset;  // Offset in file
    uint64_t p_vaddr;   // Virtual address in memory
    uint64_t p_paddr;   // Physical address (unused)
    uint64_t p_filesz;  // Size of segment in file
    uint64_t p_memsz;   // Size of segment in memory
    uint64_t p_align;   // Alignment
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;      // Section name (index into string table)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section attributes
    uint64_t sh_addr;      // Virtual address in memory
    uint64_t sh_offset;    // Offset in file
    uint64_t sh_size;      // Size of section
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
} Elf64_Shdr;

typedef uint64_t Elf64_Addr;   // Unsigned program address
typedef uint16_t Elf64_Half;   // Unsigned medium integer
typedef uint64_t Elf64_Off;    // Unsigned file offset
typedef int      Elf64_Sword;  // Signed 32-bit integer
typedef uint32_t Elf64_Word;   // Unsigned 32-bit integer
typedef int long long  Elf64_Sxword; // Signed 64-bit integer
typedef uint64_t Elf64_Xword;  // Unsigned 64-bit integer


typedef struct {
    Elf64_Sxword d_tag;     // Dynamic entry type (e.g., DT_SYMTAB, DT_STRTAB)
    union {
        Elf64_Xword d_val;  // Integer value
        Elf64_Addr  d_ptr;  // Program virtual address
    } d_un;
} Elf64_Dyn;

typedef struct {
    Elf64_Word    st_name;   // Index into the string table
    unsigned char st_info;   // Symbol type and binding
    unsigned char st_other;  // Visibility
    Elf64_Half    st_shndx;  // Section index
    Elf64_Addr    st_value;  // Symbol value (e.g., address)
    Elf64_Xword   st_size;   // Size of the symbol
} Elf64_Sym;

#define ELF64_ST_BIND(val)   ((val) >> 4)
#define ELF64_ST_TYPE(val)   ((val) & 0xf)

#define DT_NULL     0   // Marks end of dynamic array
#define DT_NEEDED   1   // Name of needed library
#define DT_PLTRELSZ 2   // Size of relocation entries for PLT
#define DT_PLTGOT   3   // Address of PLT/GOT
#define DT_HASH     4   // Address of symbol hash table
#define DT_STRTAB   5   // Address of string table
#define DT_SYMTAB   6   // Address of symbol table
#define DT_RELA     7   // Address of relocation table
#define DT_RELASZ   8   // Size of relocation table
#define DT_RELAENT  9   // Size of each relocation entry
#define DT_STRSZ    10  // Size of string table
#define DT_SYMENT   11  // Size of each symbol table entry
#define DT_INIT     12  // Address of initialization function
#define DT_FINI     13  // Address of termination function
#define DT_SONAME   14  // Name of shared object
#define DT_RPATH    15  // Library search path
#define DT_SYMBOLIC 16  // Symbol resolution behavior
#define DT_REL      17  // Address of REL relocation table
#define DT_RELSZ    18  // Size of REL relocation table
#define DT_RELENT   19  // Size of each REL entry
#define DT_PLTREL   20  // Type of relocation for PLT
#define DT_DEBUG    21  // Debugging info
#define DT_TEXTREL  22  // Indicates text relocations
#define DT_JMPREL   23  // Address of PLT relocations

size_t vaddr_to_offset(Elf64_Addr vaddr, Elf64_Phdr* phdr, int phnum) {
    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type == 1 &&
            vaddr >= phdr[i].p_vaddr &&
            vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            return phdr[i].p_offset + (vaddr - phdr[i].p_vaddr);
        }
    }
    return 0;
}

BOOL elfWalk(wchar_t* path) {

FILE* file = _wfopen(path, L"rb");

fseek(file, 0, SEEK_END);
size_t size = ftell(file);
fseek(file, 0, SEEK_SET);

unsigned char* buff = malloc(size);

fread(buff, 1, size, file);

// Header / check elf
Elf64_Ehdr* hdr = (Elf64_Ehdr*)buff;

if (hdr->e_ident[0] == 0x7F &&
hdr->e_ident[1] == 'E' &&
hdr->e_ident[2] == 'L' &&
hdr->e_ident[3] == 'F') {
// elf
} else {
    return 1;
}

// phdr
Elf64_Phdr* phdr = (Elf64_Phdr*)(buff + hdr->e_phoff);

for (int i = 0; i < hdr->e_phnum; i++) {
  //  printf("Type: %u, Offset: 0x%lx, Vaddr: 0x%lx, Filesz: 0x%lx, Memsz: 0x%lx\n",
    //    phdr[i].p_type,
     //   phdr[i].p_offset,
       // phdr[i].p_vaddr,
       // phdr[i].p_filesz,
        //phdr[i].p_memsz);

        // Check for export entry only
    if (phdr[i].p_type != 2) continue;

        // Entry stuff
    Elf64_Dyn* dyn = (Elf64_Dyn*)(buff + phdr[i].p_offset);

    Elf64_Addr symtab_offset = 0;
    Elf64_Addr strtab_offset = 0;
    Elf64_Xword syment_size = sizeof(Elf64_Sym);

// Setting symtab strtab and syment size
for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
    if (dyn[i].d_tag == DT_SYMTAB) {
        symtab_offset = dyn[i].d_un.d_ptr;
    } else if (dyn[i].d_tag == DT_STRTAB) {
        strtab_offset = dyn[i].d_un.d_ptr;
    } else if (dyn[i].d_tag == DT_SYMENT) {
        syment_size = dyn[i].d_un.d_val;
    }
}

printf("syment size: %lu\n", syment_size);
printf("strtab_offset %x\n", strtab_offset);
printf("symtab %lu\n", symtab_offset);

// Export time
Elf64_Sym* symtab = (Elf64_Sym*)(buff + vaddr_to_offset(symtab_offset, phdr, hdr->e_phnum));
char* strtab = (char*)(buff + vaddr_to_offset(strtab_offset, phdr, hdr->e_phnum));

if (symtab == 0 || strtab == 0) {
    fprintf(stderr, "Failed to resolve offsets\n");
    return 1;
}

for (size_t i = 0; i < 1000; i++) {
    Elf64_Sym* sym = (Elf64_Sym*)((char*)symtab + i * syment_size);

    const char* name = strtab + sym->st_name;
    if (name == NULL) break;
    printf("%s at 0x%lx\n", name, sym->st_value);
}

}

    return 0;
}

BOOL getCpuPower() {
    
    HANDLE hNtdll = GetModuleHandle("ntdll.dll");

    typedef ULONG (NTAPI *EtwpGetCpuSpeed_t)(PULONG, PULONG);

    EtwpGetCpuSpeed_t speed = (EtwpGetCpuSpeed_t)GetProcAddress(hNtdll, "EtwpGetCpuSpeed");

    if (!speed) {
        perror("error\n");
        return 0;
    }
    
    ULONG num;
    DWORD check;
    
    speed(&num, &check);

    printf("CPU Speed: %.3f GHz\n", num / 1000.0);

    if (check == 231) {
    printf("check: %lu - Running\n", check);
    } else if (check == 0) {
    printf("check: %lu - OK\n", check);
    } else {
    printf("check: %lu - STATUS\n", check);
    }
    

    return 0;

}

SHELLEXECUTEINFOW sei = {
    .cbSize = sizeof(SHELLEXECUTEINFOW),
    .fMask = SEE_MASK_FLAG_NO_UI,
    .hwnd = NULL,
    .lpVerb = L"open",
    .lpFile = L"https:////github.com//sleepyG8//Remote-Debugger",
    .lpParameters = NULL,
    .lpDirectory = NULL,
    .nShow = SW_SHOWNORMAL,
    .hInstApp = NULL,
    .lpIDList = NULL,
    .lpClass = NULL,
    .hkeyClass = NULL,
    .dwHotKey = 0,
    .hIcon = NULL,
    .hProcess = NULL
};

BOOL docs() {

if (ShellExecuteExW(&sei)) {
    wprintf(L"Browser launched successfully.\n");
} else {
    wprintf(L"Failed to launch browser. Error: %lu\n", GetLastError());
}
}

BOOL printHelp() {

    printf("\n===== Debugger Usage =====\n");
    printf("-- Registers & Breakpoints --\n");
                                    
    printf("!reg      - Print process registers\n");
    
    printf("!getreg   - Print registers at current memory location\n");
    
    printf("!break    - Set a breakpoint and read registers\n");
    
    printf("!synbreak - Break at a debug symbol (not stable yet)\n");

    printf("!cc       - int3 break at a function address\n");

    printf("!ccraw    - Break at a supplied address\n");

    printf("\n-- Memory & Data Inspection --\n");
    
    printf("!dump     - Dump a raw address (retry if ERROR_ACCESS_DENIED)\n");
    
    printf("!mbi      - Get MBI info (only for unprotected processes)\n");
    
    printf("!bit      - Display Bitfield data - PPL check\n");
    
    printf("!var      - Display section data\n");
    
    printf("!veh      - VEH Info\n");
    
    printf("!imports  - Get Remote Imports\n");
    
    printf("!entry    - Get entry address\n");

    printf("!vehtable - Read remote VEH table\n");

    printf("!dllcheck - walk remote dll sections\n");
    
    printf("!wor      - Walker object ranger - Object scanner\n");
    
    printf("!Inject   - Inject an extention Dll - Must have the DebuggerInjector.exe\n");

    printf("\n-- Process & System Info --\n");
    
    printf("!proc     - Display all running processes\n");
    
    printf("!cpu      - Display CPU data per processor\n");
    
    printf("!attr     - Retrieve object attributes\n");
    
    printf("!peb      - Display PEB details\n");
    
    printf("!params   - Show process parameters (debug status & path)\n");
    
    printf("!gsi      - Get System Info\n");
    
    printf("!cfg      - Check for CFG\n");
    
    printf("!sig      - Get signature\n");
    
    printf("!pwr      - Check CPU GHz\n");
    
    printf("!handles  - Dump Handles\n");

    printf("!dll       - List all loaded modules\n");

    printf("\n-- General Commands --\n");
    
    printf("clear      - Clear the console screen\n");
    
    printf("exit       - Terminate debugging session\n");
    
    printf("kill       - Close the debugged process\n");
    
    printf("help       - Display additional commands\n");
    
    printf("!ext       - Load extension (DLL)\n");
    
    printf("docs       - Go to documentation online\n");

    printf("start clip - start clip disasm shortcut\n");

    printf("==============================\n");
}

BOOL samedata = FALSE;
char *LastData = NULL;

unsigned char* clipBoard() {

    //printf("%lu", samedata);
    if (IsClipboardFormatAvailable(CF_TEXT)) {

        HANDLE hData = GetClipboardData(CF_TEXT);
  
        if (hData == NULL) {
            printf("error\n");
             return FALSE;
            }
  
            unsigned char *clipData = (char*)GlobalLock(hData);
  
            //printf("%s and %s\n", LastData, clipData);
  
            if (LastData == NULL || strcmp(LastData, clipData) != 0) {
                //printf("Its diff Lastdata %s\n", LastData);
                samedata = FALSE;
             } else {
               //printf("Its the same %s\n", LastData);
               samedata = TRUE;
            }


            if (clipData != NULL && !samedata) {
                LastData = strdup((char*)clipData);
                GlobalUnlock(hData);
                return (unsigned char *)clipData;
            
            } else {
                LastData = strdup(clipData);
                GlobalUnlock(hData);
                return "nope";
            }

}
}

DWORD WINAPI clipThread(LPVOID lpParam) { 

while (1) {

        Sleep(300);


    if (OpenClipboard(NULL)) {
                                   
        unsigned char* clipData = clipBoard();

        ULONGLONG addr = 0;
        if (sscanf((const char*)clipData, "%llx", &addr) != 1 || addr == 0) {    
            CloseClipboard();           
            continue;
        }

        if (strcmp(clipData, "nope") == 0) {
            CloseClipboard();
            continue;
        };
         
        // Address check
        
        if (strncmp(clipData, "0x", 2) == 0 && strlen(clipData) < 50) {
        
            printf("Printing from clipboard...\n");
            readRawAddr(lpParam, addr, 500);
        
        }
                                         
        CloseClipboard();
                    
    }
   
}
}

// Shout out to rad98 - https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
BOOL checkRemoteDLL(HANDLE hProcess, PVOID base, int size2read) {

printf("base: %p\n", ntdllBase);

if (base) {
    ntdllBase = base;
}

//reading dos header
IMAGE_DOS_HEADER dh;
if (!ReadProcessMemory(hProcess, ntdllBase, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
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
if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return FALSE;
}

//getting offset and starting a for loop to get all sections
DWORD sectionOffset = dh.e_lfanew + sizeof(IMAGE_NT_HEADERS);
IMAGE_SECTION_HEADER section;

//looping through
for (int i=0; i < nt.FileHeader.NumberOfSections; i++) {

    
if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)), &section, sizeof(IMAGE_SECTION_HEADER), NULL)) {
    printf("Error reading section memory %lu", GetLastError());
    }

    printf("\x1b[92m[+]\x1b[0m %s\n", (char*)section.Name);

    BYTE* address = (BYTE*)ntdllBase + section.VirtualAddress;
    printf("\x1b[92m[+]\x1b[0m Section: %s | Address: 0x%p | Size: %d\n", section.Name, (void*)address, section.SizeOfRawData);

    char* buffer = malloc(section.SizeOfRawData);
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + section.VirtualAddress, buffer, section.SizeOfRawData, NULL)) {
        printf("Error reading data %lu\n", GetLastError());
    } else {
            for (int i = 0; i < size2read; i++) {
            if (isprint(buffer[i])) { 
        printf("%c ", buffer[i]);
    }
    }

    printf("\n");

    for (int i = 0; i < size2read; i++) {
        printf("%02X ", (BYTE)buffer[i]);
    }    

    printf("\n");


    }
    
}
}

typedef struct _VECTXCPT_CALLOUT_ENTRY {
    LIST_ENTRY Links;                        // Doubly linked list: Flink & Blink
    PVOID reserved[2];                       
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, *PVECTXCPT_CALLOUT_ENTRY;


BOOL getVehTable(HANDLE hProcess, int size2read) {

printf("base: %p\n", ntdllBase);

//reading dos header
IMAGE_DOS_HEADER dh;
if (!ReadProcessMemory(hProcess, ntdllBase, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
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
if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return FALSE;
}

//getting offset and starting a for loop to get all sections
DWORD sectionOffset = dh.e_lfanew + sizeof(IMAGE_NT_HEADERS);
IMAGE_SECTION_HEADER section;

//looping through
for (int i=0; i < nt.FileHeader.NumberOfSections; i++) {

    
if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)), &section, sizeof(IMAGE_SECTION_HEADER), NULL)) {
    printf("Error reading section memory %lu", GetLastError());
    }

    if (strcmp(section.Name, ".data") == 0) {
    printf("\x1b[92m[+]\x1b[0m %s\n", (char*)section.Name);

    BYTE* address = (BYTE*)ntdllBase + section.VirtualAddress;
    printf("\x1b[92m[+]\x1b[0m Section: %s | Address: 0x%p | Size: %d\n", section.Name, (void*)address, section.SizeOfRawData);

    LIST_ENTRY* buffer = (LIST_ENTRY*)malloc(section.SizeOfRawData);
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdllBase + section.VirtualAddress, buffer, section.SizeOfRawData, NULL)) {
        printf("Error reading data %lu\n", GetLastError());
    }

    // Common list walk
    LIST_ENTRY* head = buffer;
    LIST_ENTRY* next = head->Flink;

    while (next != head) {
        VECTXCPT_CALLOUT_ENTRY entry;
        if (!ReadProcessMemory(hProcess, next, &entry, sizeof(VECTXCPT_CALLOUT_ENTRY), NULL)) {
            printf("error\n");
            return 0;
        }

        printf("Encoded Handler: %p\n", entry.VectoredHandler);
        printf("Decoded Handler: %p\n", DecodePointer(entry.VectoredHandler));

        
        next = entry.Links.Flink;
    }





    }
    
}
}

BOOL writeMem(HANDLE hProcess, void* address, BYTE* data, int size) {

    if (!WriteProcessMemory(hProcess, address, data, size, NULL)) {
        printf("Error writing to process memory at 0x%p: Error %lu\n", address, GetLastError());
    }


}

wchar_t* secondParam = NULL; // argv[2]
wchar_t* dllChoice; // Only for DLLs
// Eyes start bleeding now

char *breakBuff;
BOOL clipSniper = 0;
BOOL clipRan = 0;

BYTE* AllocatedRegion;
int offsetHandles; // first allocation offset
int offsetDump; // current do + 100
BOOL WINAPI debug(LPCVOID param) {

    wchar_t *arg = (wchar_t*)param;
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t *process = arg;

    logo();

    // ATTACH stuff
    if (wcscmp(process, L"-c") == 0) {

                pi.dwProcessId = GetProc(secondParam);
                //printf("%lu\n", pi.dwProcessId);
                pi.dwThreadId = threadid;
                //printf("%lu\n", pi.dwProcessId);

                if (pi.dwProcessId != 0 && pi.dwThreadId != 0) {
                wprintf(L"\x1b[92m[+]\x1b[0m \033[35mDebugging %s:\033[0m\n", secondParam);
                } else {
                    printf("Error Wrong Process Name\n");
                }

            } else {
                // START process stuff
                if (CreateProcessW(
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

        wprintf(L"\x1b[92m[+]\x1b[0m \033[35mDebugging %ws:\033[0m\n", arg);

            } else {
                puts("Wrong path...");
                return 1;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////
        //                                     Start of main Engine                                   // 
        ////////////////////////////////////////////////////////////////////////////////////////////////
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        if (!hProcess) {
            printf("Problem starting the debugger\n");
        } else {

            DWORD threadId = pi.dwThreadId;
            
            if (threadId == NULL) {
                printf("Error getting the thread ID...\n");
                return FALSE;
            } 
       
            // Dumping Registers
            getThreads(threadId);

            // Getting PEB / Startup info
            GetPEBFromAnotherProcess(hProcess, pi.dwThreadId, pi.dwProcessId);

            printf("\x1b[92m[+]\x1b[0m Thread address/ID: %lu\n", threadId);

            // if -b is found set a breakpoint on that import (breakBuff)
            if (breakpointSet) {
                getRemoteImports(hProcess, breakBuff, 0);
            }

            ////////////////////////////////////////////////////////////////////
            // Each strcmp() is a feature, go down the list                   //
            ////////////////////////////////////////////////////////////////////

                    while (1) {   
                        
                               // unsigned char* clipData;
    
                            if (clipSniper == 1) {
                             HANDLE hThread = CreateThread(NULL, 0, clipThread, hProcess, NULL, NULL);
                             if (hThread) {
                                puts("Clipboard is being sniped for addressess! Anything starting with 0x");
                                clipSniper = 0;
                                clipRan = 1;
                             }

                            }
    
                            
                            printf("\033[35mDebug>>\033[0m");

                            // Custom memory allocator
                            allocStdin(AllocatedRegion, offsetHandles + 200, stdin);

                            // Reading from allocated region
                            char* buff = (char*)readAlloc(AllocatedRegion, offsetHandles + 200);
                            
                            buff[strcspn(buff, "\n")] = '\0';
                            
                            if (buff != NULL) {
                                        
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
/////////-HELP-/////////
                                else if (strcmp(buff, "help") == 0) {

                                    printHelp();

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
                                
                                    free(breakBuffer);
                                }
                                
                                // Check memory protections
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

                                    free(breakBuffer);
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

                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                    DWORD64 address = strtoull(breakBuffer, NULL, 0);

                                    if (!breakpoint( pi.dwThreadId , address, hProcess)) {
                                        printf("failed to set breakpoint, protected memory region.\n");
                                    }

                                    free(breakBuffer);
                                }
                                
                                // Get current register state dump
                                 else if (strcmp(buff, "!getreg") == 0) {
                                            if (!getThreads(threadId)) {
                                            printf("error getting threads\n");
                                            }
                                    }
                                // CPU info
                                    else if (strcmp(buff, "!cpu") == 0) {
                                        if (!Getcpuinfo()) {
                                            printf("error %lu", GetLastError());
                                        }
                                    }
                                // Dump raw bytes by address
                                    else if (strcmp(buff, "!dump") == 0) {
                            
                                        printf("Which addr to get?\n");

                                        offsetDump = allocStdin(AllocatedRegion, offsetHandles + 100, stdin);

                                        BYTE* breakBuffer = readAlloc(AllocatedRegion, offsetHandles + 100);
                                        
                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        // Had to add for correct formating
                                        ULONGLONG addr = 0;
                                        if (sscanf(breakBuffer, "%llx", &addr) != 1 || addr == 0) {
                                        printf("Error: invalid address '%s'\n", breakBuffer);
                                        return FALSE;
                                        }

                                        char bytes2Read[100];
                                        puts("How many bytes to read?");
                                        fgets(bytes2Read, 99, stdin);

                                        bytes2Read[strcspn(bytes2Read, "\n")] = '\0';

                                        DWORD bytesNum = strtoul(bytes2Read, NULL, 10);

                                        // Read Raw function 
                                        if (!readRawAddr(hProcess, (LPVOID)addr, bytesNum)) {
                                        printf("Error invalid address\n");
                                        }
                                        
                                    }

                                    else if (strcmp(buff, "!cc") == 0) {
                                        
                                        char breakBuffer[100] = {0};
                                        if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                        }

                                        printf("Which function to break at? (Ex: GetProcAddress)\n");

                                        if (!fgets(breakBuffer, 99, stdin)) {
                                         printf("buffer to large\n");
                                        }

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                       if (!getRemoteImports(hProcess, breakBuffer, 0)) {
                                        printf("Error setting the breakpoint at %s\n", breakBuffer);
                                       }

                                    }

                                    else if (strcmp(buff, "!ccraw") == 0) {

                                        char breakBuffer[100] = {0};
                                        if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                        }

                                        printf("Which address to break at? (Ex: 0x00007FFCEFEF7C60)\n");

                                        if (!fgets(breakBuffer, 99, stdin)) {
                                         printf("buffer to large\n");
                                        }

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        // convert string to address 
                                        void* targetAddress = (void*)strtoull(breakBuffer, NULL, 0);

                                        BYTE cc[5] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
                                        if (!WriteProcessMemory(hProcess, targetAddress, cc, sizeof(cc), NULL)) {
                                            printf("Failed to write breakpoint at %s: error %lu\n", breakBuffer, GetLastError());
                                        } else {
                                            printf("Wrote a breakpoint at %s\n", breakBuffer);
                                        }

                                    }

                                    // Get section data 
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

                                    // Run a DLL (Local)
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

                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                    if (!Extensions(breakBuffer)) {
                                        printf("Error loading extension\n");
                                    }

                                    free(breakBuffer);

                                    }
                                    // Get info from kuser
                                    else if (strcmp(buff, "!gsi") == 0) {
                                        getSystemInfo();
                                    }
                                    // get remote imports
                                    else if (strcmp(buff, "!imports") == 0) {
                                        getRemoteImports(hProcess, NULL, 0);
                                    }
                                    // get signature of the file
                                    else if (strcmp(buff, "!sig") == 0) {
                                        //wprintf(L"%ws", imagePath);
                                        getSignature(imagePath);
                                    }
                                    // cfg check
                                    else if (strcmp(buff, "!cfg") == 0) {
                                        cfgCheck(imagePath);
                                    }

                                    else if (strcmp(buff, "!pwr") == 0) {
                                        getCpuPower();
                                    }

                                    else if (strcmp(buff, "!Inject") == 0) {
                                            STARTUPINFO siI = { sizeof(si) };
                                            PROCESS_INFORMATION piI = { 0 };
                                        if (!CreateProcessA("DebuggerInjector.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &siI, &piI)) {
                                            printf("Error starting up the Injector make sure its in the debuggers directory\n");
                                        }
                                    }

                                    else if (strcmp(buff, "!wor") == 0) {
                                            
                                        STARTUPINFO siO = { sizeof(si) };
                                        PROCESS_INFORMATION piO = { 0 };
                                    
                                    char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                    if (!breakBuffer) {
                                        printf("Memory allocation error\n");
                                    }
                                    
                                    printf("\x1b[92m[-]\x1b[0m Which path to Load? (Object Directory Ex: \\Device)\n");
                                   
                                    if  (!fgets(breakBuffer, 99, stdin)) {
                                    printf("buffer to large\n");
                                    return FALSE;
                                    }

                                    char finalbuff[100];

                                    snprintf(finalbuff, 99, "cmd.exe /k wor.exe %s & pause", breakBuffer);

                                    breakBuffer[strcspn(breakBuffer, "\n")] = '\0';
                                        if (!CreateProcessA(NULL, finalbuff, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &siO, &piO)) {
                                            printf("Make sure wor.exe is inside of the current Directory, use docs to get it.\n");
                                        }
                                    }

                                    else if (strcmp(buff, "!handles") == 0) {
                                    
                                        printf("\x1b[92m[-]\x1b[0m Proccess Number? - Enter for current process\n");
                                   
                                        offsetHandles = allocStdin(AllocatedRegion, 0, stdin);

                                        BYTE* breakBuffer = readAlloc(AllocatedRegion, 0);

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        ULONG_PTR value = strtoul(breakBuffer, NULL, 0);

                                        DWORD temp;
                                        if (value == 0) {
                                            temp = pi.dwProcessId;
                                        } else {
                                            temp = value;
                                        }

                                        dumpHandle(temp);

                                        free(breakBuffer);
                                    }

                                    else if (strcmp(buff, "docs") == 0) {
                                        docs();
                                    }

                                    else if (strcmp(buff, "!entry") == 0) {
                                        getRemoteImports(hProcess, NULL, 1);
                                    }

                                    else if (strcmp(buff, "start clip") == 0) {
                                        if (clipRan == 0) {
                                            clipSniper = 1;
                                        } else {
                                            puts("Its already started up...\n");
                                        }   
                                    }

                                    else if (strcmp(buff, "!dllcheck") == 0) {

                                        char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                        if (!breakBuffer) {
                                           printf("Memory allocation error\n");
                                        }
                                    
                                        printf("\x1b[92m[-]\x1b[0m Address to get sections?\n");
                                   
                                        if  (!fgets(breakBuffer, 99, stdin)) {
                                        printf("buffer to large\n");
                                        return FALSE;
                                        }

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        void* targetAddress = (void*)strtoull(breakBuffer, NULL, 0);

                                        checkRemoteDLL(hProcess, targetAddress, 100);
                                    }

                                    else if (strcmp(buff, "!vehtable") == 0) {
                                        getVehTable(hProcess, 100);
                                    }

                                    else if (strcmp(buff, "!write") == 0) {

                                        char *breakBuffer = (char*)malloc(100 * sizeof(char));
                                        if (!breakBuffer) {
                                           printf("Memory allocation error\n");
                                        }
                                    
                                        printf("\x1b[92m[!]\x1b[0m Address write data?\n");
                                   
                                        if  (!fgets(breakBuffer, 99, stdin)) {
                                        printf("buffer to large\n");
                                        return FALSE;
                                        }

                                        breakBuffer[strcspn(breakBuffer, "\n")] = '\0';

                                        // char to void*
                                        void* targetAddress = (void*)strtoull(breakBuffer, NULL, 0);

                                        BYTE bytes2Write[100];
                                        puts("what Bytes to write??");
                                        fgets(bytes2Write, 99, stdin);

                                        bytes2Write[strcspn(bytes2Write, "\n")] = '\0';

                                        size_t len = strlen(bytes2Write);
                                        size_t byteCount = len / 2;

                                        // Convert char to actual bytes so basically combining C 3 into C3 thats why / 2
                                        for (size_t i = 0; i < byteCount; ++i) {
                                            sscanf(&bytes2Write[i * 2], "%2hhx", &bytes2Write[i]);
                                        }

                                        writeMem(hProcess, targetAddress, bytes2Write, byteCount);
                                    }

                                    else if (strcmp(buff, "!dll") == 0) {
                                        listModules();
                                    }
                                    

                                     } else {
                                         printf("run -help- to see the help menu.\n");
                                        }
                            }                  
                        }   
                                                                 
    WaitForInputIdle(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

    if (!IsDebuggerPresent) {
        puts("No debugging the debugger");
        return 0;
    }

    AllocatedRegion = makeMem(0x2000);


    LPVOID fiberMain = ConvertThreadToFiber(NULL); 
    LPVOID debugFiber = CreateFiber(0, debug, argv[1]);

    if (argc < 2) {
        //puts("\033[35mGlyph - Remote debugger engine by Sleepy\033[0m\n");
        logo();
        puts("\x1b[92mUsage:\x1b[0m\n-c <Remote process name> ex. Notepad.exe (ATTACH)\n<path to executable> ex. C:\\Windows\\System32\\notepad.exe start(START)\n-c <process> -b (BREAKPOINT)");
        puts("-l (LIST)");
        puts("-open <Path> (optional: -open <Path> -suspended)(start a process)");
        puts("-c <ProcName> -b (CC Breakpoint, must install a handler)");

        puts("\n\x1b[92mDLL parsing:\x1b[0m\n-DLL <path to DLL> -imports\n-DLL <path to DLL> -exports");

        puts("\n\x1b[92mELF parsing:\x1b[0m\n-ELF <path to .so>\n");

        puts("run with -help for more help\n");

        return 0;
    }

        if (wcscmp(argv[1], L"-l") == 0) {
        listProcesses();
        return 0;
    }

    if (wcscmp(argv[1], L"-help") == 0) {
        logo();
        puts("\x1b[92mUsage:\x1b[0m\n[+] -c <Remote process name> ex. Notepad.exe (ATTACH)\n[+] <path to executable> ex. C:\\Windows\\System32\\notepad.exe (START)");
        puts("[+] -l (LIST)");
        puts("[+] -open <Path> (optional: -open <Path> -suspended)(start a process)");
        puts("[+] -c <ProcName> -b (CC Breakpoint, must install a handler)");

        puts("\n\x1b[92mDLL parsing:\x1b[0m\n[+]-DLL <path to DLL> -imports\n[+] -DLL <path to DLL> -exports");

        puts("\n\x1b[92mELF parsing:\x1b[0m\n[+] -ELF <path to .so>\n");

        puts("\x1b[92mAttached features:\x1b[0m");
        printHelp();

        return 0;
    }


    if (wcscmp(argv[1], L"-open") == 0) {

        if (argv[3]) {

         STARTUPINFO si = { sizeof(si) };
         PROCESS_INFORMATION pi = { 0 };
        if (!CreateProcessW(argv[2], NULL, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            printf("Error creating process %lu\n", GetLastError());
            return 1;
        } else {
            printf("Process created! and suspended, -c <ProcName> to connect");
            return 0;
        }

    }

         STARTUPINFO si = { sizeof(si) };
         PROCESS_INFORMATION pi = { 0 };
        if (!CreateProcessW(argv[2], NULL, NULL, NULL, 0, 0, NULL, NULL, &si, &pi)) {
            printf("Error creating process %lu\n", GetLastError());
            return 1;
        } else {
            printf("Process created!, -c <ProcName> to connect");
            return 0;
        }
    }

    
    if (wcscmp(argv[2], L"-b") == 0) {
        breakpointSet = 1;
        
        breakBuff = (char*)malloc(100 * sizeof(char));
                                             
        printf("\x1b[92m[-]\x1b[0m What address to break at? Might crash the proc\n");
                                   
        if  (!fgets(breakBuff, 99, stdin)) {
            printf("buffer to large\n");
            return FALSE;
            }

        breakBuff[strcspn(breakBuff, "\n")] = '\0';


    }
    

    if (wcscmp(argv[1], L"-ELF") == 0) {
        if (argc < 3) {
            printf("Path to .so file\n");
        }
        elfWalk(argv[2]);
        return 0;
    }

    // sus
    if (argc > 2) {
        secondParam = argv[2];

        // DLL stuff
        if (wcscmp(argv[1], L"-DLL") == 0) {

        if (argc < 4) {
            puts("-DLL <path to DLL> -imports\n-DLL <path to DLL> -exports");
            return 0;
        }

        dllChoice = argv[3];
        wprintf(L"%ws\n", dllChoice);

        
        if (wcscmp(dllChoice, L"-imports") == 0) {
        dllImports(secondParam);
        return 0;
        }

        else if (wcscmp(dllChoice, L"-exports") == 0) {
        dllExports(secondParam);
        return 0;
        }

        return 0;
    }

        if (argv[3]) {

        breakpointSet = 1;
        
        breakBuff = (char*)malloc(100 * sizeof(char));
                                             
        printf("\x1b[92m[-]\x1b[0m What address to break at?\n");
                                   
        if  (!fgets(breakBuff, 99, stdin)) {
            printf("buffer to large\n");
            return FALSE;
            }

        breakBuff[strcspn(breakBuff, "\n")] = '\0';


    }
        //wprintf(L"%ws\n", argv[2]);
    }

    if (debugFiber) {
        while (1) {
        SwitchToFiber(debugFiber);
        DeleteFiber(debugFiber); 
        } // Launch debugger inside fiber
          // Cleanup

}
return 0;
}
