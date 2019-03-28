all: update_sassl
clean: clean_sassl

.PHONY: update_sassl clean_sassl

# Compiles Open SSL and copies it along with the supporting OP-TEE standard library stubs
# needed to successfully link it.
update_sassl: ./lib/libssl/include/
	$(MAKE) -C ../../external/StaticOSSL
	cp -f ../../external/StaticOSSL/openssl/libcrypto.a ./lib/libssl/libcrypto.a
	cp -R ../../external/StaticOSSL/openssl/include/openssl/ ./lib/libssl/include/
	cp -R ../../external/StaticOSSL/optee_lib/. ./lib/libssl/

./lib/libssl/include/:
	mkdir ./lib/libssl/include/

clean_sassl:
	rm -f ./lib/libssl/libcrypto.a
	rm -r -f ./lib/libssl/include/
	$(MAKE) -C ../../external/StaticOSSL clean

libnames += crypto
libdeps += ./lib/libssl/libcrypto.a
libdirs += ./lib/libssl/

srcs-y += optee_stdlib.c
incdirs-optee_os.c-y = ./
global-incdirs-y += include

all: 