#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <winnt.h>

static char* windows_subsystems[17] = {
    "Unknown",
    "Native",
    "Windows GUI",
    "Windows Console",
    "Invalid",
    "OS/2 Console",
    "Invalid",
    "Posix Console",
    "Native Win9x Driver",
    "WinCE",
    "EFI Application",
    "EFI Boot Driver",
    "EFI Runtime Driver",
    "EFI ROM",
    "XBox",
    "Invalid",
    "Windows boot application",
};

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
    /* 3. Section header */
    IMAGE_SECTION_HEADER* p_section_header = (IMAGE_SECTION_HEADER*) ((char*)IMAGE_FIRST_SECTION(p_nt_header));

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
    printf("    [%s] is exectuable\n"                                      , (pe_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE        )?"*": "-");
    printf("    [%s] is DLL\n"                                             , (pe_characteristics & IMAGE_FILE_DLL                     )?"*": "-");
    printf("    [%s] can handle large 2G > addresses\n"                    , (pe_characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE     )?"*": "-");
    printf("    [%s] is system file\n"                                     , (pe_characteristics & IMAGE_FILE_SYSTEM                  )?"*": "-");
    printf("    [%s] reallocation info stripped\n"                         , (pe_characteristics & IMAGE_FILE_RELOCS_STRIPPED         )?"*": "-");
    printf("    [%s] line numbers stripped\n"                              , (pe_characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED      )?"*": "-");
    printf("    [%s] symbol table stripped\n"                              , (pe_characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED     )?"*": "-");
    printf("    [%s] debug info stripped\n"                                , (pe_characteristics & IMAGE_FILE_DEBUG_STRIPPED          )?"*": "-");
    printf("    [%s] 32-bit word machine\n"                                , (pe_characteristics & IMAGE_FILE_32BIT_MACHINE           )?"*": "-");
    printf("    [%s] if on removeable media, copy and run from swap\n"     , (pe_characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP )?"*": "-");
    printf("    [%s] if on network, copy and run from swap\n"              , (pe_characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP       )?"*": "-");
    printf("    [%s] should run on uni-processor machine\n"                , (pe_characteristics & IMAGE_FILE_UP_SYSTEM_ONLY          )?"*": "-");
    printf("\n");
    
    /* 3. Address of entry point */
    DWORD image_base = p_nt_header->OptionalHeader.ImageBase;
    DWORD entry_point_addr = p_nt_header->OptionalHeader.AddressOfEntryPoint;
    printf("  Entry point Address = 0x%lX\n", entry_point_addr);
    printf("  Entry point Address (RVA) = 0x%lX\n", image_base + entry_point_addr);
    printf("\n");

    /* 4. Section info */
    /* 5. Section locations */
    WORD num_sections = p_nt_header->FileHeader.NumberOfSections;
    printf("  Number of sections = %u\n", num_sections);
   
    printf("  Sections info:\n");
    printf("      INDEX\t|\tNAME\t\t|\tR_ADDR\t\t|\tCHARACTERISTICS\n");
    printf("           \t|\t    \t\t|\t      \t\t|\tR | W | X | SH | U_DATA | I_DATA | CODE\n");

    IMAGE_SECTION_HEADER* p_current_section = (IMAGE_SECTION_HEADER*) p_section_header;
    for (int i = 1; i < num_sections + 1; i++, p_current_section++) {
        DWORD sec_characteristics = p_current_section->Characteristics;
        printf("      %d\t\t|\t", i);
        printf("%s\t\t|\t", p_current_section->Name);
        printf("0x%lX\t\t|\t", p_current_section->PointerToRawData);
        printf("%s | ", (sec_characteristics & IMAGE_SCN_MEM_READ)?"*": "-");
        printf("%s | ", (sec_characteristics & IMAGE_SCN_MEM_WRITE)?"*": "-");
        printf("%s | ", (sec_characteristics & IMAGE_SCN_MEM_EXECUTE)?"*": "-");
        printf("%s  | ", (sec_characteristics & IMAGE_SCN_MEM_SHARED)?"*": "-");
        printf("  %s    | ", (sec_characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)?"*": "-");
        printf("  %s    | ", (sec_characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)?"*": "-");
        printf(" %s", (sec_characteristics & IMAGE_SCN_CNT_CODE)?"*": "-");
        printf("\n");
    }
    printf("\n");
    
    /* 6. Parse .rsrc section and extract the content */
    // PIMAGE_RESOURCE_DIRECTORY p_rd_root = (PIMAGE_RESOURCE_DIRECTORY) &p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    // printf("x = %d\n", p_rd_root->NumberOfIdEntries);
    int num_data_directories = p_nt_header->OptionalHeader.NumberOfRvaAndSizes;
    PIMAGE_DATA_DIRECTORY data_entry = p_nt_header->OptionalHeader.DataDirectory;

    printf("\n");
    printf("##### DATA DIRECTORIES #####\n");
    printf("  Number of data directories = %d\n", num_data_directories);

    printf("  Resource Directory is the 3rd directory.\n");
    PIMAGE_DATA_DIRECTORY rsrc_dir_data = &data_entry[2];

    printf("    RSRC Dir, address = 0x%X, size=0x%X.\n", rsrc_dir_data->VirtualAddress, rsrc_dir_data->Size);

    PIMAGE_RESOURCE_DIRECTORY rsrc_dir = rsrc_dir_data->VirtualAddress;
    printf("    RSRC number of entries = ID(%d), Named(%d).\n", rsrc_dir->NumberOfIdEntries, rsrc_dir->NumberOfNamedEntries);
    // DATA_DIRECTORIES
    printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", p_nt_header->OptionalHeader.DataDirectory[1].VirtualAddress, p_nt_header->OptionalHeader.DataDirectory[1].Size);
    printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", p_nt_header->OptionalHeader.DataDirectory[2].VirtualAddress, p_nt_header->OptionalHeader.DataDirectory[1].Size);
#if 0
// SECTION_HEADERS
printf("\n******* SECTION HEADERS *******\n");
// get offset to first section headeer
DWORD sectionLocation = (DWORD)p_nt_header + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)p_nt_header->FileHeader.SizeOfOptionalHeader;
DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

// get offset to the import directory RVA
DWORD importDirectoryRVA = p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

// print section data
for (int i = 0; i < p_nt_header->FileHeader.NumberOfSections; i++) {
sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
printf("\t%s\n", sectionHeader->Name);
printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);

// save section that contains import directory table
if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
importSection = sectionHeader;
}
sectionLocation += sectionSize;
}

// get file offset to import table
rawOffset = (DWORD)fileData + importSection->PointerToRawData;

// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

printf("\n******* DLL IMPORTS *******\n");	
for (; importDescriptor->Name != 0; importDescriptor++)	{
// imported dll modules
printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

// dll exported functions
for (; thunkData->u1.AddressOfData != 0; thunkData++) {
//a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
if (thunkData->u1.AddressOfData > 0x80000000) {
//show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
} else {
printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
}
}
}
#endif

    /* 7. Other essential information */
    printf("  Other information:\n");

    WORD machine = p_nt_header->FileHeader.Machine;
    printf("    Machine = 0x%X\n", machine);

    WORD major_os_ver = p_nt_header->OptionalHeader.MajorOperatingSystemVersion;
    WORD minor_os_ver = p_nt_header->OptionalHeader.MinorOperatingSystemVersion;
    printf("    Major OS version = 0x%X\n", major_os_ver);
    printf("    Minor OS version = 0x%X\n", minor_os_ver);

    DWORD checksum = p_nt_header->OptionalHeader.CheckSum;
    printf("    Checksum = 0x%lX\n", checksum);
    
    WORD sub_system = p_nt_header->OptionalHeader.Subsystem;
    printf("    Subsystem = 0x%X (%s)\n", sub_system, windows_subsystems[sub_system]);




    fclose(exe_file);

    return 0;
}