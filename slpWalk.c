#include <Windows.h>
#include <stdio.h>

typedef struct {
    FARPROC address;   // NOT void*
    DWORD size;
    char mnum[10];
    char asm[50];
} opstr;

typedef struct {
    FARPROC begin;
    FARPROC end;
    DWORD size;
    DWORD num;
    BYTE firstByte;
    opstr op[80];
} function;

function* functions;    // each function has its own struct and opstr embeded struct

typedef struct {
    char name[100];
    FARPROC address;
} Imports;

typedef struct {
    wchar_t modName[200];
    FARPROC modAddress;
} Dlls;

int main(int argc, char* argv[]) {

    FILE* f = fopen(argv[1], "rb");

    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* slp = malloc(size);
    fread(slp, 1, size, f);

    int i = 0;
    int importCount = 0;
    puts("Import List:\n");
    while (1) {
        Imports* import = slp + (i * sizeof(Imports));
        if (import->name[0] == 'C' && import->name[1] == NULL ) break;                  // Break on found Module
        printf("%s\n", import->name);
        i++;
        importCount++;
    }
    
    //importCount -= 1;           // Go back one before Module was found with '.'
    int ModuleOffset = importCount * sizeof(Imports);
    int j = 0;
    puts("\nModules:");
    while (1) {
        Dlls* module = slp + ModuleOffset + j * sizeof(Dlls);

        if (module->modName[0] != 'C') break;

        wprintf(L"%ws\n", module->modName);
        j++;
    }

    for (int s=0; s < 500; s++) {

        function* functions = slp + ModuleOffset + j * sizeof(Dlls) + s * sizeof(function);

        printf("%lu Begin: %p\t End: %p\n", s, functions->begin, functions->end);

        for (int i=0; i < 80; i++) {
        if (!functions->op[i].address) break;
        printf("%s\n", functions->op[i].asm);
        }

    }




}
