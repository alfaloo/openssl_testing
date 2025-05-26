#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

const int PORT = 4433;
const int BUFFER_SIZE = 1024;

void InitialiseOpenSSL() { 
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* CreateConfigureContext() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int CreateSocket(int port) {
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(serverFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(serverFd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return serverFd;
}

void RunServer() {
    InitialiseOpenSSL();

    SSL_CTX *ctx = CreateConfigureContext();
    int socket = CreateSocket(PORT);

    std::cout << "[Server] Listening on port " << PORT << std::endl;

    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);

    int client;

    char buffer[BUFFER_SIZE];
    while ((client = accept(socket, (struct sockaddr*) &addr, &len)) >= 0) {
        std::cout << "[Server] Connected with client: " << client << "\n";

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0)
            ERR_print_errors_fp(stderr);
        
    
        int len;
        while ((len = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
            std::cout << "[Server] Recieved: " << std::string(buffer, len) << "\n";
        }

        if (len < 0) {
            std::cerr << "SSL_read failed: " << len << std::endl;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    if (client < 0) {
        std::cerr << "Unable to accept client" << len << std::endl;
    }

    close(socket);
    SSL_CTX_free(ctx);
}