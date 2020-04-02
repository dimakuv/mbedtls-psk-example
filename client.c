/*  Minimal TLS-PSK client */

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_SSL_CLI_C)
int main(void) {
    mbedtls_printf("MBEDTLS_CTR_DRBG_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_SSL_CLI_C and/or UNIX "
                   "not defined.\n");
    return  -1;
}
#else

#include <errno.h>
#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"  /* used only for error codes */
#include "mbedtls/ssl.h"

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ssl_internal.h"

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

const unsigned char psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const char psk_id[] = "Client_identity";

const char unix_socket_name[] = "mbedtls_test_unix_socket";

enum exit_codes {
    exit_ok = 0,
    ctr_drbg_seed_failed,
    ssl_config_defaults_failed,
    ssl_setup_failed,
    hostname_failed,
    socket_failed,                /* 05 */
    connect_failed,
    x509_crt_parse_failed,
    ssl_handshake_failed,
    ssl_write_failed,
    ssl_read_failed,              /* 10 */
    ssl_context_save_failed,
    ssl_context_load_failed,
};

static int recv_cb(void *ctx, unsigned char *buf, size_t len) {
    int fd = *((int*)ctx);
    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)read(fd, buf, len);

    if (ret < 0) {
        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;
        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;
}

static int send_cb(void *ctx, unsigned char const *buf, size_t len) {
    int fd = *((int*)ctx);
    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)write(fd, buf, len);
    if (ret < 0) {
        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;
        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t* olen) {
    (void) data;
    *olen = 0;

    for (size_t i = 0; i < len; i += 8) {
        unsigned long long rand64;
        while (__builtin_ia32_rdrand64_step(&rand64) == 0)
            /*nop*/;
        memcpy(output + i, &rand64, sizeof(rand64));
    }

    *olen = len;
    return 0;
}

int main(void) {
    int ret = exit_ok;
    int server_fd = -1;

    unsigned char buf[512];
    int bytes_read = 0;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

	signal(SIGPIPE, SIG_IGN);

    /* initialize and setup mbedtls objects */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        ret = ctr_drbg_seed_failed;
        goto exit;
    }

    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        ret = ssl_config_defaults_failed;
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk), (const uint8_t*)psk_id, sizeof(psk_id) - 1);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        ret = ssl_setup_failed;
        goto exit;
    }

    /* start the connection */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unix_socket_name, sizeof(addr.sun_path)-1);

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ret = socket_failed;
        goto exit;
    }

    if (connect(server_fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ret = connect_failed;
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, send_cb, recv_cb, NULL);

    if (mbedtls_ssl_handshake(&ssl) != 0) {
        ret = ssl_handshake_failed;
        goto exit;
    }

    /* send HTTP request and receive HTTP response */
    if (mbedtls_ssl_write(&ssl, (const uint8_t*)GET_REQUEST, sizeof(GET_REQUEST) - 1) <= 0) {
        ret = ssl_write_failed;
        goto exit;
    }

    if ((bytes_read = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1)) <= 0) {
        ret = ssl_read_failed;
        goto exit;
    };
    buf[bytes_read - 1] = '\0';

    mbedtls_printf("Reply from server:\n%s\n", buf);
    fflush(stdout);

    /* serialize the context (it will be de-serialized again to perform another request) */
    unsigned char* context_buf = NULL;
    size_t context_buf_len;
	size_t buf_len;

    if (mbedtls_ssl_context_save(&ssl, NULL, 0, &buf_len) != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        ret = ssl_context_save_failed;
        goto exit;
    }

    if ((context_buf = mbedtls_calloc(1, buf_len)) == NULL) {
        ret = ssl_context_save_failed;
        goto exit;
    }
    context_buf_len = buf_len;

    if (mbedtls_ssl_context_save(&ssl, context_buf, buf_len, &buf_len) != 0) {
        ret = ssl_context_save_failed;
        goto exit;
    }

    /* deserialize the context back */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_init(&ssl);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        ret = ssl_setup_failed;
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, send_cb, recv_cb, NULL);

    if (mbedtls_ssl_context_load(&ssl, context_buf, buf_len) != 0) {
        ret = ssl_context_load_failed;
        goto exit;
    }

    mbedtls_free(context_buf);
    context_buf     = NULL;
    context_buf_len = 0;

    /* again, send HTTP request and receive HTTP response */
    if (mbedtls_ssl_write(&ssl, (const uint8_t*)GET_REQUEST, sizeof(GET_REQUEST) - 1) <= 0) {
        ret = ssl_write_failed;
        goto exit;
    }

    if ((bytes_read = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1)) <= 0) {
        ret = ssl_read_failed;
        goto exit;
    };
    buf[bytes_read - 1] = '\0';

    mbedtls_printf("[after context serialize/deserialize] Reply from server:\n%s\n", buf);
    fflush(stdout);

    /* finish */
    mbedtls_ssl_close_notify(&ssl);

exit:
    shutdown(server_fd, 2);
    close(server_fd);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}
#endif
