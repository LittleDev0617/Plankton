#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winnt.h>
#include <stdio.h>

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

PE* parse_pe(FILE* stream) {    
    fseek(stream, 0, SEEK_SET);
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
    fread(dos_header, sizeof(IMAGE_DOS_HEADER), 1, stream);

    // hex_log(dos_header, sizeof(IMAGE_DOS_HEADER));
    
    fseek(stream, dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER), SEEK_CUR);
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
    FILE* fp = fopen(file_path, "r");
    fseek(fp, 0, SEEK_END);
    
    int size = ftell(fp);
    printf("[*] SIZE: %d\n", size);

    PE* pe = parse_pe(fp);

    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) {
        hex_log(pe->sections[i], 64);
    }

    

    for (int i=0; i < pe->nt_header->FileHeader.NumberOfSections; ++i) 
        free(pe->section_headers[i]);
    free(pe->section_headers);
    free(pe->nt_header);
    free(pe->dos_header);
    free(pe);
}

int main() {
    load("./main.exe");

    return 1;
}