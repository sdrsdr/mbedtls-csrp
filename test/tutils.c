#include <stdlib.h>
#include <stdio.h>

#include "tutils.h"
void tutils_array_print(char* tag, unsigned char* buf, int len)
{
    printf("%s(len:%d)", tag, len);
    for (int i=0; i<len; i++) {
        if (i % 0xf == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void tutils_mpi_print(char* tag, mbedtls_mpi* x)
{
    int len_x = mbedtls_mpi_size(x);
    unsigned char* num = malloc(len_x);
    mbedtls_mpi_write_binary(x, num, len_x);

    printf("%s (len:%d)", tag, len_x);
    for (int i=0; i<len_x; i++) {
        printf("%02X ", num[i]);
        if (i % 0xf == 0)
            printf("\n");
    }
    printf("\n");
    free(num);
}
