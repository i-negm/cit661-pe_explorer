#include <stdio.h>
#include <stdlib.h>

int main (int argc, void* argv[]) {
    
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
        fprintf(stderr, "reading error (%d)\n", n_read);
        return 1;
    } else {
        printf("[OK] file size = %ld byte.\n", file_size);
    }

    fclose(exe_file);

    return 0;
}