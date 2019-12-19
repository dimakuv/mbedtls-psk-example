CFLAGS += -Imbedtls/install/include/ -mrdrnd
LDFLAGS += -Lmbedtls/install/lib -lmbedtls -lmbedcrypto

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
CFLAGS += -g -O0
else
MBED_BUILD_TYPE=Release
CFLAGS += -O2
endif

all: client server

MBEDTLS_VERSION ?= 2.16.3
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= ec72ecf39275327f52b5ee9787271313a0d2960e7342b488d223a118ba164caa

$(MBEDTLS_SRC):
	wget --timeout=10 $(MBEDTLS_URI)/$(MBEDTLS_SRC) -O tmp
	@[ "`sha256sum tmp`" = "$(MBEDTLS_CHECKSUM)  tmp" ] || \
		(echo "*** $@ has a wrong checksum ***"; rm -f tmp; exit 255)
	mv -f tmp $@

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC)
	tar -mxzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	cp config.h mbedtls/include/mbedtls
	sed -i 's|$$(MAKE) -C programs|echo "Not building mbedTLS sample programs"|g' mbedtls/Makefile
	mkdir mbedtls/install
	cd mbedtls && make DESTDIR=install install .

client: client.c mbedtls/CMakeLists.txt
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

server: server.c mbedtls/CMakeLists.txt
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) server client

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls tmp $(MBEDTLS_SRC)
