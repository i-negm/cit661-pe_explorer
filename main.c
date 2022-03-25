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

    /**
     * @brief Print parsed information
     */
    /* 1. PE compile time */
    DWORD compile_time = p_nt_header->FileHeader.TimeDateStamp;
    printf("  Compile time / Time date stamp = %lu\n", compile_time);
    printf("\n");

    /* 2. PE characteristics */
    WORD pe_characteristics = p_nt_header->FileHeader.Characteristics;
    printf("  PE Characteristics:\n");
    printf("    [%s] is exectuable\n"                                      , (pe_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE        )?"*": " ");
    printf("    [%s] is DLL\n"                                             , (pe_characteristics & IMAGE_FILE_DLL                     )?"*": " ");
    printf("    [%s] can handle large 2G > addresses\n"                    , (pe_characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE     )?"*": " ");
    printf("    [%s] is system file\n"                                     , (pe_characteristics & IMAGE_FILE_SYSTEM                  )?"*": " ");
    printf("    [%s] reallocation info stripped\n"                         , (pe_characteristics & IMAGE_FILE_RELOCS_STRIPPED         )?"*": " ");
    printf("    [%s] line numbers stripped\n"                              , (pe_characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED      )?"*": " ");
    printf("    [%s] symbol table stripped\n"                              , (pe_characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED     )?"*": " ");
    printf("    [%s] debug info stripped\n"                                , (pe_characteristics & IMAGE_FILE_DEBUG_STRIPPED          )?"*": " ");
    printf("    [%s] 32-bit word machine\n"                                , (pe_characteristics & IMAGE_FILE_32BIT_MACHINE           )?"*": " ");
    printf("    [%s] if on removeable media, copy and run from swap\n"     , (pe_characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP )?"*": " ");
    printf("    [%s] if on network, copy and run from swap\n"              , (pe_characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP       )?"*": " ");
    printf("    [%s] should run on uni-processor machine\n"                , (pe_characteristics & IMAGE_FILE_UP_SYSTEM_ONLY          )?"*": " ");
    printf("\n");
    /* 3. Address of entry point */
    DWORD image_base = p_nt_header->OptionalHeader.ImageBase;
    DWORD entry_point_addr = p_nt_header->OptionalHeader.AddressOfEntryPoint;
    printf("  Entry point Address = 0x%lX\n", entry_point_addr);
    printf("  Entry point Address (RVA) = 0x%lX\n", image_base + entry_point_addr);
    printf("\n");
    /* 4. Section info */
    WORD num_sections = p_nt_header->FileHeader.NumberOfSections;
    printf("  Number of sections = %u\n", num_sections);

    /* 5. Section locations */
    /* 6. Parse .rsrc section and extract the content */
    /* 7. Other essential information */

    fclose(exe_file);

    return 0;
}