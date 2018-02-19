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

#define HOST "localhost"
#define PORT 8765
#define KEYFILE "alice.pem"
#define PASSWORD "password"

#define SERVER "Bob's Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define BUF_SIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

void check_cert(SSL* ssl, char* host);
void request(SSL* ssl, char* host, int port, char* req, char* res);

int main(int argc, char** argv) {
    int len, sock, port = PORT;
    char* host = HOST;
    struct sockaddr_in addr;
    struct hostent* host_entry;
    char buf[BUF_SIZE];
    char* secret = "What's the question?";

    len = 0; // @supress warning

    /*Parse command line arguments*/

    switch (argc) {
        case 1:
            break;
        case 3:
            host = argv[1];
            port = atoi(argv[2]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s server port\n", argv[0]);
            exit(0);
    }

    /*get ip address of the host*/

    host_entry = gethostbyname(host);

    if (!host_entry) {
        fprintf(stderr, "Couldn't resolve host");
        exit(0);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)host_entry->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr), port);

    /*open socket*/

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        perror("socket");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        perror("connect");

    // Before are boilplate code provided by default
    int status;
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* sbio;

    int require_server_auth = 1;

    // initialize SSL context
    ctx = initialize_ctx(KEYFILE, PASSWORD);
    status = SSL_CTX_set_cipher_list(ctx, "SHA1");
    if (!status) {  // status == 0 => failure
        printf("Fatal! set cipher list failed\n");
        exit(1);
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    // Connect to the SSL socket
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    if (SSL_connect(ssl) <= 0) {
        berr_exit("SSL connect error");
    }

    if (require_server_auth) {
        check_cert(ssl, host);
    }

    request(ssl, host, port, secret, buf);
    /* this is how you output something for the marker to pick up */
    printf(FMT_OUTPUT, secret, buf);

    close(sock);
    return 1;
}

void check_cert(SSL* ssl, char* host) {
    X509* peer;
    char peer_CN[256];
    char peer_email[256];
    char issuer[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        berr_exit(FMT_NO_VERIFY);
    }

    peer = SSL_get_peer_certificate(ssl);
    X509_NAME* peer_name = X509_get_subject_name(peer);
    X509_NAME_get_text_by_NID(peer_name, NID_commonName, peer_CN, 256);
    X509_NAME_get_text_by_NID(peer_name, NID_pkcs9_emailAddress, peer_email,
                              256);
    X509_NAME_get_text_by_NID(peer_name, NID_commonName, issuer, 256);

    if (strcasecmp(peer_CN, SERVER)) {
        berr_exit(FMT_CN_MISMATCH);
    }

    if (strcasecmp(peer_email, EMAIL)) {
        berr_exit(FMT_EMAIL_MISMATCH);
    }

    printf(FMT_SERVER_INFO, peer_CN, peer_email, issuer);
}

void request(SSL* ssl, char* host, int port, char* req, char* res) {
    int request_len = strlen(req);
    int ret = SSL_write(ssl, req, request_len);

    switch (SSL_get_error(ssl, ret)) {
        case SSL_ERROR_NONE:
            assert(request_len == ret);
            break;
        case SSL_ERROR_SYSCALL:
            berr_exit(FMT_INCORRECT_CLOSE);
            break;
        default:
            BIO_printf(bio_err, FMT_OUTPUT, "Unknown ssl problem", "");
            ERR_print_errors(bio_err);
            exit(1);
    }

    while (1) {
        ret = SSL_read(ssl, res, BUF_SIZE);
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:
                res[ret] = '\0';
                return;
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
                berr_exit(FMT_INCORRECT_CLOSE);
            default:
                BIO_printf(bio_err, FMT_OUTPUT, "Unknown ssl problem", "");
                ERR_print_errors(bio_err);
                exit(1);
        }
    }
}
