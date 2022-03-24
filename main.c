#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <winnt.h>

int main (int argc, char** argv) {
    
    /* Sanity check for the command line */
    if (argc < 2) {
        fprintf(stderr, "error usage, please provide a file path to be parsed\n");
        return 1;
    }

    /* Open the file */
    FILE* exe_file = fopen(argv[1], "rb");
    if (!exe_file) {
        fprintf(stderr, "error opening the file\n");
        return 1;
    } else {
        printf("[OK] file (%s) opened\n", argv[1]);
    }

    /* Get the size of the file and allocate memory for it */
    fseek(exe_file, 0, SEEK_END);
    long int file_size = ftell(exe_file);
    fseek(exe_file, 0, SEEK_SET);
    char* exe_file_data = malloc(file_size + 1);

    /* Read file into memory */
    size_t n_read = fread(exe_file_data, 1, file_size, exe_file);
    if (n_read != file_size) {
        fprintf(stderr, "reading error (%lld)\n", n_read);
        return 1;
    } else {
        printf("[OK] file size = %ld byte.\n", file_size);
    }

    /* Prepare the parser */
    /* 1. DOS header (starts at the start of the file) */
    IMAGE_DOS_HEADER* p_dos_header = (IMAGE_DOS_HEADER*) exe_file_data;
    /* 2. NT header at the e_lfanew offset from the start of the file */
    IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*) ((char*)p_dos_header + p_dos_header->e_lfanew);

    /* Print parsed information */
    /* 1. PE compile time */
    /* 2. PE characteristics */
    /* 3. Address of entry point */
    /* 4. Section info */
    /* 5. Section locations */
    /* 6. Parse .rsrc section and extract the content */
    /* 7. Other essential information */

    fclose(exe_file);

    return 0;
}