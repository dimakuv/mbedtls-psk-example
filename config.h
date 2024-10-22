#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* Pre-Shared Keys with plain PSK and 256 AES-GCM */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256
#define MBEDTLS_SSL_PROTO_TLS1_2

/* want to test mbedtls_ssl_context_save() / mbedtls_ssl_context_load() */
#define MBEDTLS_SSL_CONTEXT_SERIALIZATION

#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY

#define MBEDTLS_AESNI_C
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_X86_64

#define MBEDTLS_AES_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CMAC_C
#define MBEDTLS_GCM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_SHA256_C

#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_ERROR_C
#define MBEDTLS_MD_C
#define MBEDTLS_PLATFORM_C

#define MBEDTLS_NET_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C

#include "mbedtls/check_config.h"

#endif
