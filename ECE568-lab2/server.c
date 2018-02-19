#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "sslcomm.h"

#define PORT 8765
#define KEYFILE "bob.pem"
#define PASSWORD "password"
#define CIPHER_LIST "SSLv2:SSLv3:TLSv1"

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

void check_cert(SSL* ssl);

int main(int argc, char** argv) {
    int s, sock, port = PORT;
    struct sockaddr_in sin;
    int val = 1;
    pid_t pid;

    /*Parse command line arguments*/

    switch (argc) {
        case 1:
            break;
        case 2:
            port = atoi(argv[1]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s port\n", argv[0]);
            exit(0);
    }

    int status;
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* sbio;

    ctx = initialize_ctx(KEYFILE, PASSWORD);
    status = SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);
    if (!status) {  // status == 0 => failure
        printf("Fatal! set cipher list failed\n");
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        close(sock);
        exit(0);
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if (bind(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        close(sock);
        exit(0);
    }

    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        exit(0);
    }

    while (1) {
        if ((s = accept(sock, NULL, 0)) < 0) {
            perror("accept");
            close(sock);
            close(s);
            exit(0);
        }

        /*fork a child to handle the connection*/

        if ((pid = fork())) {
            close(s);
        } else {
            /*Child code*/
            int len;
            len = 0; // @supress warning
            char buf[256];
            char* answer = "42";

            sbio = BIO_new_socket(s, BIO_NOCLOSE);
            ssl = SSL_new(ctx);
            SSL_set_bio(ssl, sbio, sbio);

            if (SSL_accept(ssl) <= 0) {
                berr_exit(FMT_ACCEPT_ERR);
            }
            check_cert(ssl);

            int ret = SSL_read(ssl, buf, 256);
            buf[ret] = '\0';
            switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    printf("shut down ssl connection\n");
                    ret = SSL_shutdown(ssl);
                    switch (ret) {
                        case 1:
                            // Success
                            break;
                        default:
                            berr_exit("shut down ssl failed\n");
                    }
                case SSL_ERROR_SYSCALL:
                    berr_exit(FMT_INCOMPLETE_CLOSE);
                default:
                    BIO_printf(bio_err, FMT_OUTPUT, "Unknown ssl problem", "");
                    ERR_print_errors(bio_err);
                    exit(1);
            }
            printf(FMT_OUTPUT, buf, answer);

            ret = SSL_write(ssl, answer, strlen(answer));
            switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_NONE:
                    assert(strlen(answer) == ret);
                    break;
                case SSL_ERROR_SYSCALL:
                    berr_exit(FMT_INCOMPLETE_CLOSE);
                    break;
                default:
                    BIO_printf(bio_err, FMT_OUTPUT, "Unknown ssl problem", "");
                    ERR_print_errors(bio_err);
                    exit(1);
            }
            close(sock);
            close(s);
            return 0;
        }
    }
    SSL_CTX_free(ctx);
    close(sock);
    return 1;
}

void check_cert(SSL* ssl) {
    X509* peer;
    char peer_CN[256];
    char peer_email[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        berr_exit(FMT_ACCEPT_ERR);
    }

    peer = SSL_get_peer_certificate(ssl);
    X509_NAME* peer_name = X509_get_subject_name(peer);
    X509_NAME_get_text_by_NID(peer_name, NID_commonName, peer_CN, 256);
    X509_NAME_get_text_by_NID(peer_name, NID_pkcs9_emailAddress, peer_email,
                              256);

    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}
