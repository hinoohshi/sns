#include "sum_nbo.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: ./sum-nbo <file1> <file2> [<file3>...]\n");
        return 1;
    }

    sum_nbo(argc, argv);
    return 0;
}
