#ifndef SSL_COMM_H
#define SSL_COMM_H

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define CA_LIST "568ca.pem"

extern BIO *bio_err;
int berr_exit (char *fmt);

SSL_CTX* initialize_ctx(char* keyfile, char* password);

#endif
