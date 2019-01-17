default: test

.PHONY: clean distclean
.ONESHELL:

CFLAGS ?= -g -Og
LDFLAGS ?= -g


mbedtls:
	git clone https://github.com/ARMmbed/mbedtls.git

mbedtls/library/libmbedcrypto.a: mbedtls
	cd mbedtls && make no_test

srp.o: ../srp.c mbedtls
	$(CC) `realpath -s ../srp.c` -c -o srp.o  -I../ -I./mbedtls/include $(CFLAGS) -DHAPTEST

tutils.o: tutils.c mbedtls
	$(CC) `realpath -s tutils.c` -c -o tutils.o  -I../ -I./mbedtls/include $(CFLAGS)


test.o: test.c mbedtls
	$(CC) `realpath -s test.c` -c -o test.o  -I../  $(CFLAGS)

test: mbedtls/library/libmbedcrypto.a srp.o test.o tutils.o
	$(CC) $^ -o $@  -Lmbedtls/library/ -lmbedcrypto $(LDFLAGS)

clean:
	rm *.o test 
distclean: clean
	rm -rf mbedtls 

