CFLAGS += -Imbedtls/crypto/include/ -Imbedtls/install/include/ -mrdrnd
LDFLAGS += -Lmbedtls/install/lib -lmbedtls -lmbedcrypto

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
DEBUG_CFLAGS = -g -O0
CFLAGS += $(DEBUG_CFLAGS)
else
MBED_BUILD_TYPE=Release
DEBUG_CFLAGS = -O2
CFLAGS += $(DEBUG_CFLAGS)
endif

all: client server

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= https://github.com/ARMmbed/mbed-crypto/archive/
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

$(MBEDTLS_SRC):
	wget --timeout=10 $(MBEDTLS_URI)/$(MBEDTLS_SRC) -O tmp
	@[ "`sha256sum tmp`" = "$(MBEDTLS_CHECKSUM)  tmp" ] || \
		(echo "*** $@ has a wrong checksum ***"; rm -f tmp; exit 255)
	mv -f tmp $@

$(MBEDCRYPTO_SRC):
	wget --timeout=10 $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) -O tmp
	@[ "`sha256sum tmp`" = "$(MBEDCRYPTO_CHECKSUM)  tmp" ] || \
		(echo "*** $@ has a wrong checksum ***"; rm -f tmp; exit 255)
	mv -f tmp $@

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
	tar -mxzf $(MBEDTLS_SRC)
	tar -mxzf $(MBEDCRYPTO_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	$(RM) -r mbedtls/crypto
	mv mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls
	mv mbedtls/mbed-crypto-mbedcrypto-3.1.0 mbedtls/crypto
	cp config.h mbedtls/include/mbedtls
	cp config.h mbedtls/crypto/include/mbedtls
	sed -i 's|$$(MAKE) -C programs|echo "Not building mbedTLS sample programs"|g' mbedtls/Makefile
	cd mbedtls && patch -p1 < ../mbedtls-$(MBEDTLS_VERSION).diff || exit 255
	mkdir mbedtls/install
	cd mbedtls && make DESTDIR=install DEBUG=$(DEBUG) CFLAGS="$(DEBUG_CFLAGS)" install .

client: client.c mbedtls/CMakeLists.txt
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

server: server.c mbedtls/CMakeLists.txt
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) server client

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls tmp $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
