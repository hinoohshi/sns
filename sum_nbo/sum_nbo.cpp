#include "sum_nbo.h"
#include <arpa/inet.h>
#include <stdio.h>

void print_number(uint32_t num) {
    unsigned char* bytes = (unsigned char*)&num;
    int start = 3;

    while (start > 0 && bytes[start] == 0) {
        start--;
    }

    printf("%u(", num);

    printf("0x");
    for (int i = start; i >= 0; i--) {
        printf("%02x", bytes[i]);
    }
    printf(")");
}

uint32_t read_nbo(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening %s", filename);
        return UINT32_MAX;
    }

    uint32_t num;
    size_t read_size = fread(&num, sizeof(uint32_t), 1, file);
    fclose(file);

    if (read_size != 1) {
        fprintf(stderr, "Error reading %s", filename);
        return UINT32_MAX;
    }

    return ntohl(num);
}

uint32_t sum_nbo(int file_count, char* filename[]) {

    uint32_t total = 0;

    for (int i = 1; i < file_count; i++) {
        uint32_t num = read_nbo(filename[i]);
        print_number(num);

        if (i < file_count - 1) {
            printf(" + ");
        }
        total += num;
    }

    printf(" = ");
    print_number(total);
    printf("\n");

    return total;
}
