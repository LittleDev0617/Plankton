#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#define IMAGE_BASE (void*)0x12340000

static const DWORD prot[8] = {
    PAGE_NOACCESS,
    PAGE_EXECUTE,
    PAGE_READONLY,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
    PAGE_EXECUTE_READWRITE,
};

void hex_log(void* address, int size) {
    printf("[DEBUG]: %p ~ %p", address, ((BYTE*)address)+size);
    for (int i=0; i < size; ++i) {
        if (i % 16 == 0) {
            putchar('\t');
            for (int j=0; i != 0 && j < 16; ++j) {
                char byte = *((BYTE*)address+i-16+j);
                if (byte < 32 || byte > 126)
                    byte = '.';
                putchar(byte);
            }
            printf("\n%5X:\t", i);
        } else if (i % 8 == 0)
            printf("  ");
        
        printf("%02X ", *((BYTE*)address+i));
    }
    puts("");
    puts("");
}

typedef struct _PE {
    IMAGE_DOS_HEADER* dos_header;
    IMAGE_NT_HEADERS* nt_header;
    IMAGE_SECTION_HEADER** section_headers;
    BYTE** sections;
} PE;

void error(const char* error_message) {
    printf("[ERROR] %s\n", error_message);
    printf("[ERROR] GetLastError(): %lu\n", GetLastError());
    exit(-1);
}

PE* parse_pe(FILE* stream) {
    fseek(stream, 0, SEEK_SET);
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
    fread(dos_header, sizeof(IMAGE_DOS_HEADER), 1, stream);

    hex_log(dos_header, sizeof(IMAGE_DOS_HEADER));
    
    fseek(stream, dos_header->e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
    fread(nt_header, sizeof(IMAGE_NT_HEADERS), 1, stream);

    // hex_log(nt_header, sizeof(IMAGE_NT_HEADERS));
    
    IMAGE_SECTION_HEADER** section_headers = (IMAGE_SECTION_HEADER**)malloc(sizeof(IMAGE_SECTION_HEADER*) * nt_header->FileHeader.NumberOfSections);
    for (int i=0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        section_headers[i] = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
        fread(section_headers[i], sizeof(IMAGE_SECTION_HEADER), 1, stream);

        // hex_log(section_headers[i], sizeof(IMAGE_SECTION_HEADER));
    }

    BYTE** sections = (BYTE**)malloc(sizeof(BYTE*) * nt_header->FileHeader.NumberOfSections);
    for (int i=0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        sections[i] = (BYTE*)malloc(section_headers[i]->SizeOfRawData);
        fseek(stream, section_headers[i]->PointerToRawData, SEEK_SET);
        fread(sections[i], 1, section_headers[i]->SizeOfRawData, stream);    
    }

    PE* pe = (PE*)malloc(sizeof(PE));
    pe->dos_header = dos_header;
    pe->nt_header = nt_header;
    pe->section_headers = section_headers;
    pe->sections = sections;
        
    return pe;
}

void load(const char* file_path) {
    FILE* fp = fopen(file_path, "rb");
    fseek(fp, 0, SEEK_END);
    
    int size = ftell(fp);
    printf("[*] SIZE: %d\n", size);

    PE* pe = parse_pe(fp);

    BYTE** sections = (BYTE**)malloc(sizeof(BYTE*) * pe->nt_header->FileHeader.NumberOfSections);
    
    printf("%lx\n", pe->nt_header->OptionalHeader.SizeOfImage);

    BYTE* image_base = VirtualAlloc(IMAGE_BASE, pe->nt_header->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
    if (!image_base) {
        error("VirtualAlloc - image_base failed");
    }
    
    // image_base -= pe->nt_header->OptionalHeader.SectionAlignment;
    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) {        
        DWORD virtual_size = pe->section_headers[i]->Misc.VirtualSize;
        void* section = VirtualAlloc(image_base + pe->section_headers[i]->VirtualAddress, virtual_size, MEM_COMMIT, PAGE_READWRITE);
        if (!section) {
            error("VirtualAlloc - section failed");
        }
        
        printf("[DEBUG] section: %p, size: %lx\n", section, virtual_size);
        memcpy(section, pe->sections[i], pe->section_headers[i]->SizeOfRawData);
        sections[i] = section;
    }
    
    IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + pe->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; import_descriptor->Name; import_descriptor++) {
        const char* dll_name = (char*)image_base+import_descriptor->Name;
        HMODULE dll_handle = LoadLibrary(dll_name);
        printf("%s: %p\n", dll_name, dll_handle);

        IMAGE_THUNK_DATA* import_name_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->OriginalFirstThunk);
        IMAGE_THUNK_DATA* import_address_table = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->FirstThunk);

        for (; import_name_table->u1.AddressOfData; import_name_table++) {
            if (import_name_table->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
    
            } else {
                IMAGE_IMPORT_BY_NAME* name = (IMAGE_IMPORT_BY_NAME*)(image_base+import_name_table->u1.AddressOfData);
                void* proc_address = GetProcAddress(dll_handle, name->Name);
                printf("\t%s: %p\n", name->Name, proc_address);
    
                (import_address_table++)->u1.Function = (ULONGLONG)proc_address;
            }
        }
    }

    IMAGE_DATA_DIRECTORY* reloc_directory = &pe->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* relocation_table = (IMAGE_BASE_RELOCATION*)(image_base + reloc_directory->VirtualAddress);
    IMAGE_BASE_RELOCATION* relocation_table_end = (IMAGE_BASE_RELOCATION*)((BYTE*)relocation_table + reloc_directory->Size);
    ULONG_PTR delta = (ULONG_PTR)image_base - pe->nt_header->OptionalHeader.ImageBase;

    for (; relocation_table < relocation_table_end && relocation_table->SizeOfBlock; relocation_table = (IMAGE_BASE_RELOCATION*)((char*)relocation_table + relocation_table->SizeOfBlock)) {
        int count = (relocation_table->SizeOfBlock - 8) / sizeof(WORD);
        WORD* entrys = (WORD*)(relocation_table+1);
        for (int i=0; i < count; ++i) {
            BYTE type = entrys[i] >> 12;
            WORD offset = entrys[i] & 0xFFF;
            void* addr = image_base + relocation_table->VirtualAddress + offset;
            switch (type) {
                case 10:
                    *(ULONGLONG*)addr += delta;
                    break;
                default:
                    break;
            }
        }
    }

    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) {
        DWORD virtual_size = pe->section_headers[i]->Misc.VirtualSize;
        DWORD old;
        VirtualProtect(sections[i], virtual_size, prot[pe->section_headers[i]->Characteristics >> 29], &old);
    }
    
    void* entrypoint = image_base + pe->nt_header->OptionalHeader.AddressOfEntryPoint;
    ((void(*)(void))entrypoint)();

    puts("FINISH");
    
    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) 
        free(pe->section_headers[i]);
    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) 
        free(pe->sections[i]);
    
    VirtualFree(IMAGE_BASE, 0, MEM_RELEASE);
    free(pe->section_headers);
    free(pe->sections);
    free(sections);
    free(pe->nt_header);
    free(pe->dos_header);
    free(pe);
}

int main() {
    load("./game.exe");

    return 1;
}