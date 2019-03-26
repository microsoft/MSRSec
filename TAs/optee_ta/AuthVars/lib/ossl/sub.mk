# Compiles a Stand ALone Open SSL (SASSL) and copies it along with the 
# supporting OP-TEE standard library stubs needed to successfully link it.

all: update_sassl
clean: clean_sassl

.PHONY: update_sassl clean_sassl download_sassl

update_sassl: download_sassl ./lib/ossl/include/
	$(MAKE) -C $(OSSL_ROOT)
	cp -f $(OSSL_ROOT)/openssl/libcrypto.a ./lib/ossl/libcrypto.a
	cp -R $(OSSL_ROOT)/openssl/include/openssl/ ./lib/ossl/include/
	cp -R $(OSSL_ROOT)/optee_lib/. ./lib/ossl/

./lib/ossl/include/:
	mkdir ./lib/ossl/include/

download_sassl:
# sassl makefile handles this internally.

clean_sassl:
	rm -f ./lib/ossl/libcrypto.a
	rm -r -f ./lib/ossl/include/
	$(MAKE) -C $(OSSL_ROOT) clean

libnames += crypto
libdeps += ./lib/ossl/libcrypto.a
libdirs += ./lib/ossl/

srcs-y += optee_stdlib.c
incdirs-optee_os.c-y = ./
global-incdirs-y += include

all: 