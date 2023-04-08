#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context(int is_server) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (is_server) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int create_client_socket(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void server_loop(SSL_CTX *ctx, int port) {
    int sockfd, client;
    SSL *ssl;
    char buf[BUFFER_SIZE];
    int bytes;
    int bytes_read;

    sockfd = create_server_socket(port);

    printf("Server listening on port %d\n", port);
    while (1) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        client = accept(sockfd, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            bytes_read = SSL_read(ssl, buf, BUFFER_SIZE - 1);
            buf[bytes_read] = '\0';
            printf("Received: %s\n", buf);

            if (strcmp(buf, "Andy is awesome!") == 0) {
                SSL_write(ssl, "Yes, he is!", strlen("Yes, he is!"));
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sockfd);
}

void client_loop(SSL_CTX *ctx, const char *ip, int port) {
    int sockfd;
    SSL *ssl;
    char buf[BUFFER_SIZE];
    int bytes_read;

    sockfd = create_client_socket(ip, port);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Andy is awesome!", strlen("Andy is awesome!"));

        bytes_read = SSL_read(ssl, buf, BUFFER_SIZE - 1);
        buf[bytes_read] = '\0';
        printf("Received: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <server|client> <ip> <port>\n", argv[0]);
        return 1;
    }

    int is_server = strcmp(argv[1], "server") == 0;
    const char *ip = argv[2];
    int port = atoi(argv[3]);

    init_openssl();
    SSL_CTX *ctx = create_context(is_server);
    configure_context(ctx);

    if (is_server) {
        server_loop(ctx, port);
    } else {
        client_loop(ctx, ip, port);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
