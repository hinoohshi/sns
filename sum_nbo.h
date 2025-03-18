#ifndef SUM_NBO_H
#define SUM_NBO_H

#include <stdint.h>
#include <stdio.h>

void print_number(uint32_t num);
uint32_t read_nbo(const char* filename);
uint32_t sum_nbo(int file_count, char* filename[]);

#endif // SUM_NBO_H
