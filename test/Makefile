default: test

.PHONY: clean distclean
.ONESHELL:

CFLAGS ?= -g -Og -DSRP_TEST
LDFLAGS ?= -g
HDRS = tutils.h ../srp_internal.h srp_test_config.h

mbedtls:
	git clone https://github.com/ARMmbed/mbedtls.git

mbedtls/library/libmbedcrypto.a: mbedtls
	cd mbedtls && make no_test

srp.o: ../srp.c mbedtls $(HDRS)
	$(CC) `realpath -s $< ` -c -o $@  -I`realpath -s .` -I./mbedtls/include $(CFLAGS)

tutils.o: tutils.c mbedtls $(HDRS)
	$(CC) `realpath -s $< ` -c -o $@  -I../ -I./mbedtls/include $(CFLAGS)


test.o: test.c mbedtls $(HDRS)
	$(CC) `realpath -s $< ` -c -o $@  -I../ -I./mbedtls/include $(CFLAGS)

test: mbedtls/library/libmbedcrypto.a srp.o test.o tutils.o
	$(CC) $^ -o $@  -Lmbedtls/library/ -lmbedcrypto $(LDFLAGS)

clean:
	rm *.o test 
distclean: clean
	rm -rf mbedtls 

