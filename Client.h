#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ossl_iovec.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

const int PORT = 4433;
const char* SERVER_IP = "127.0.0.1";
const int BUFFER_SIZE = 1024;

void InitialiseOpenSSL() { 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* CreateContext() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void RunClient() {
    InitialiseOpenSSL();
    SSL_CTX *ctx = CreateContext();

    int serverFd;
    struct sockaddr_in addr;
    SSL *ssl;

    serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(serverFd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, serverFd);

    char buffer[BUFFER_SIZE];

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        OSSL_IOVEC iov[3];
        const char msg0[] = "Hello,";
        iov[0].data = (void*) msg0;
        iov[0].data_len = strlen(msg0);
        const char msg1[] = " SSL";
        iov[1].data = (void*) msg1;
        iov[1].data_len = strlen(msg1);
        const char msg2[] = " server!";
        iov[2].data = (void*) msg2;
        iov[2].data_len = strlen(msg2);
        SSL_writev(ssl, iov, 3);
        std::cout << "[Client] Sent: " << std::string(msg0, strlen(msg0)) << std::string(msg1, strlen(msg1)) << std::string(msg2, strlen(msg2)) << "\n";
        // int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        // std::cout << "Received: " << buffer << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    // close(serverFd);
    SSL_CTX_free(ctx);
}