default: build

.PHONY: clean distclean
.ONESHELL:

CFLAGS ?= -g -Og
LDFLAGS ?= -g

build: mbedtls mbedtls/library/libmbedcrypto.a test

mbedtls:
	git clone https://github.com/ARMmbed/mbedtls.git

mbedtls/library/libmbedcrypto.a: mbedtls
	cd mbedtls && make no_test

srp.o: mbedtls ../srp.c
	$(CC) `realpath -s ../srp.c` -c -o srp.o  -I../ -I./mbedtls/include $(CFLAGS)

test.o: test.c
	$(CC) `realpath -s test.c` -c -o test.o  -I../  $(CFLAGS)

test: mbedtls/library/libmbedcrypto.a srp.o test.o
	$(CC) srp.o test.o -o test  -Lmbedtls/library/ -lmbedcrypto $(LDFLAGS)

clean:
	rm *.o test 
distclean: clean
	rm -rf mbedtls 

