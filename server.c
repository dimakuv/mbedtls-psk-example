/*  Minimal TLS-PSK server */

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void) {
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_CTR_DRBG_C and/or not defined.\n");
    return 0;
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
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"  /* used only for error codes */
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#define DFL_RESPONSE_SIZE       256
#define DFL_READ_TIMEOUT        0
#define DFL_EXCHANGES           1

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

/* size of the basic I/O buffer, able to hold our default response */
#define DFL_IO_BUF_LEN 200

const unsigned char psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const char psk_id[] = "Client_identity";

const char unix_socket_name[] = "mbedtls_test_unix_socket";

static int listen_fd;
static int client_fd;

static int received_sigterm = 0;

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++)
        if (*p == '/' || *p == '\\')
            basename = p + 1;

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: |%d| %s", basename, line, level, str);
    fflush((FILE *) ctx);
}

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

static int mbedtls_bind(int* bound_fd) {
    int ret;
    int fd;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unix_socket_name, sizeof(addr.sun_path)-1);

    fd = (int)socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
        goto out;
    }

    int n = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&n, sizeof(n)) != 0 ) {
        close(fd);
        ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
        goto out;
    }

    if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        ret = MBEDTLS_ERR_NET_BIND_FAILED;
        goto out;
    }

    if (listen(fd, MBEDTLS_NET_LISTEN_BACKLOG) != 0) {
        close(fd);
        ret = MBEDTLS_ERR_NET_LISTEN_FAILED;
        goto out;
    }

    /* bind was successful */
    *bound_fd = fd;
    ret = 0;
out:
    return ret;
}

static int mbedtls_accept(int bind_fd, int *client_fd) {
    int fd = accept(bind_fd, NULL, NULL);
    if (fd < 0)
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    *client_fd = fd;
    return 0;
}

static void mbedtls_fd_cleanup(int* fd) {
    if (*fd == -1)
        return;

    shutdown(*fd, 2);
    close(*fd);

    *fd = -1;
}

static int mbedtls_status_is_ssl_in_progress(int ret) {
    return ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
           ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS;
}

static void term_handler(int sig) {
    (void) sig;
    received_sigterm = 1;

    mbedtls_fd_cleanup(&client_fd);
    mbedtls_fd_cleanup(&listen_fd);
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

int main(int argc, char* argv[]) {
    int ret = 0, len, written, frags, exchanges_left;
    unsigned char* buf = NULL;
    size_t psk_len = sizeof(psk);

    unlink(unix_socket_name);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);

	signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);

    if (argc == 0) {
        goto exit;
    }

    buf = mbedtls_calloc(1, DFL_IO_BUF_LEN + 1);
    if (buf == NULL) {
        mbedtls_printf("Could not allocate %u bytes\n", DFL_IO_BUF_LEN);
        ret = 3;
        goto exit;
    }

    /* initialize the RNG and the session data */
    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /* setup the listening socket */
    mbedtls_printf("  . Bind on UNIX domain socket %s ...", unix_socket_name);
    fflush(stdout);

    if ((ret = mbedtls_bind(&listen_fd)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_bind returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /* setup stuff */
    mbedtls_printf("  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    ret = mbedtls_ssl_conf_psk(&conf, psk, psk_len, psk_id, strlen(psk_id));
    if (ret != 0) {
        mbedtls_printf("  failed\n  mbedtls_ssl_conf_psk returned -0x%04X\n\n", - ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, send_cb, recv_cb, NULL);

    mbedtls_printf(" ok\n");

reset:
    if (received_sigterm) {
        mbedtls_printf(" interrupted by SIGTERM (not in accept())\n");
        if (ret == MBEDTLS_ERR_NET_INVALID_CONTEXT)
            ret = 0;
        goto exit;
    }

    if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
        mbedtls_printf("  ! Client initiated reconnection from same port\n");
        goto handshake;
    }

    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }

    mbedtls_fd_cleanup(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /* wait until a client connects */
    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_accept(listen_fd, &client_fd)) != 0) {
        if (received_sigterm) {
            mbedtls_printf(" interrupted by SIGTERM (in accept())\n");
            if (ret == MBEDTLS_ERR_NET_ACCEPT_FAILED)
                ret = 0;
            goto exit;
        }

        mbedtls_printf(" failed\n  ! mbedtls_accept returned -0x%x\n\n", -ret);
        goto exit;
    }

    ret = fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL) & ~O_NONBLOCK);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! set blocking returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_read_timeout(&conf, DFL_READ_TIMEOUT);

    mbedtls_printf(" ok\n");

    /* handshake */
handshake:
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (!mbedtls_status_is_ssl_in_progress(ret))
            break;
    }

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        mbedtls_printf(" hello verification requested\n");
        ret = 0;
        goto reset;
    } else if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
        goto reset;
    }
    else /* ret == 0 */ {
        mbedtls_printf(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
                       mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));
    }

    if ((ret = mbedtls_ssl_get_record_expansion(&ssl)) >= 0)
        mbedtls_printf("    [ Record expansion is %d ]\n", ret);
    else
        mbedtls_printf("    [ Record expansion is unknown (compression) ]\n");

    exchanges_left = DFL_EXCHANGES;

data_exchange:
    /* read the HTTP Request */
    mbedtls_printf("  < Read from client:");
    fflush(stdout);

    do {
        int terminated = 0;
        len = DFL_IO_BUF_LEN - 1;
        memset(buf, 0, DFL_IO_BUF_LEN);
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (mbedtls_status_is_ssl_in_progress(ret))
            continue;

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    goto close_notify;

                case 0:
                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    ret = MBEDTLS_ERR_NET_CONN_RESET;
                    goto reset;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    goto reset;
            }
        }

        if (mbedtls_ssl_get_bytes_avail(&ssl) == 0) {
            len = ret;
            buf[len] = '\0';
            mbedtls_printf(" %d bytes read\n\n%s\n", len, (char*)buf);

            /* End of message should be detected according to the syntax of the
             * application protocol (eg HTTP), just use a dummy test here. */
            if (buf[len - 1] == '\n')
                terminated = 1;
        } else {
            int extra_len, ori_len;
            unsigned char *larger_buf;

            ori_len = ret;
            extra_len = (int) mbedtls_ssl_get_bytes_avail(&ssl);

            larger_buf = mbedtls_calloc(1, ori_len + extra_len + 1);
            if (larger_buf == NULL) {
                mbedtls_printf("  ! memory allocation failed\n");
                ret = 1;
                goto reset;
            }

            memset(larger_buf, 0, ori_len + extra_len);
            memcpy(larger_buf, buf, ori_len);

            /* This read should never fail and get the whole cached data */
            ret = mbedtls_ssl_read(&ssl, larger_buf + ori_len, extra_len);
            if (ret != extra_len || mbedtls_ssl_get_bytes_avail(&ssl) != 0) {
                mbedtls_printf("  ! mbedtls_ssl_read failed on cached data\n");
                ret = 1;
                goto reset;
            }

            larger_buf[ori_len + extra_len] = '\0';
            mbedtls_printf(" %u bytes read (%u + %u)\n\n%s\n",
                           ori_len + extra_len, ori_len, extra_len,
                           (char*)larger_buf);

            /* End of message should be detected according to the syntax of the
             * application protocol (eg HTTP), just use a dummy test here. */
            if (larger_buf[ori_len + extra_len - 1] == '\n')
                terminated = 1;

            mbedtls_free(larger_buf);
        }

        if (terminated) {
            ret = 0;
            break;
        }
    } while (1);

    /* write the 200 Response */
    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    len = sprintf((char*)buf, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl));

    /* add padding/truncate response to reach response_size */
    if (len < DFL_RESPONSE_SIZE) {
        memset(buf + len, 'B', DFL_RESPONSE_SIZE - len);
        len += DFL_RESPONSE_SIZE - len;
    } else if (len > DFL_RESPONSE_SIZE) {
        len = DFL_RESPONSE_SIZE;
        if (len >= 1)
            buf[len - 1] = '\n';
    }

    for (written = 0, frags = 0; written < len; written += ret, frags++) {
        while ((ret = mbedtls_ssl_write(&ssl, buf + written, len - written)) <= 0) {
            if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
                goto reset;
            }

            if (!mbedtls_status_is_ssl_in_progress(ret)) {
                mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
                goto reset;
            }
        }
    }

    buf[written] = '\0';
    mbedtls_printf(" %d bytes written in %d fragments\n\n%s\n", written, frags, (char*)buf);
    ret = 0;

    if (--exchanges_left > 0)
        goto data_exchange;

    /* done, cleanly close the connection */
close_notify:
    mbedtls_printf("  . Closing the connection...");

    /* no error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    mbedtls_printf(" done\n");

    goto reset;

    /* cleanup and exit */
exit:
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: -0x%X - %s\n\n", -ret, error_buf);
    }

    mbedtls_printf("  . Cleaning up...");
    fflush(stdout);

    mbedtls_fd_cleanup(&client_fd);
    mbedtls_fd_cleanup(&listen_fd);

    unlink(unix_socket_name);

    mbedtls_printf(" done.\n");

    if (ret < 0)
        ret = 1;

    return ret;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CTR_DRBG_C */
