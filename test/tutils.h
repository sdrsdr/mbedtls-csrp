#pragma once
#include "mbedtls/bignum.h"
void tutils_array_print(char* tag, unsigned char* buf, int len);
void tutils_mpi_print(char* tag, mbedtls_mpi* x);
