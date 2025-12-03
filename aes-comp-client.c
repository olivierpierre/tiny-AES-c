// Client code, to be compiled with any program wishing to make use of the
// compartmentalized version of the library. It exposes a similar API as the
// library, so adapting a program making use of the vanilla (monolithic) version
// of the library should be very easy: replace the inclusion of aes.h by that of
// aes-comp-client.h, and edit build rule to compile the program against
// aes-comp-client.o rather than aes.o

#include "aes-comp.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>

// The compartment binary
#define SERVER_BINARY "./aes-comp"

int sock;     // socket used for communication with the compartment
int aes_pid;  // pid of the compartment server

// Wait for the socket to be created by the compartment server
static int wait_for_socket() {
    struct stat buffer;
    int timeout_us = 1000000; // 1 sec timeout

    while (timeout_us) {
        if (stat(SOCKET_PATH, &buffer) == 0)
            return 0; // file exists

        usleep(1000);
        timeout_us -= 1000;
    }

    return -1; // timeout
}

static int init_connection() {
    struct sockaddr_un addr;

    // Create a UNIX domain socket
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock < 0)
        errx(-1, "client socket");

    // Set up the address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Connect to the server
    int timeout_us = 1000000; // 1 sec timeout
    while (timeout_us) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
            usleep(1000);
            timeout_us -= 1000;
            if(!timeout_us) {
                errx(-1, "client connect");
            }
        } else {
            break;
        }
    }

    return 0;
}

static int start_server() {
    char *args[] = {SERVER_BINARY, NULL};
    char *envp[] = {NULL};

    int r = fork();

    if(r < 0)
        return r;

    if(r == 0) {
        execve(SERVER_BINARY, args, envp);
        return -1; // shouldn't reach this
    } else
        aes_pid = r;

    if(wait_for_socket())
        return -1;

    return 0;
}

__attribute__((constructor))
void init() {

    if(start_server())
        errx(-1, "client cannot start AES compartment");

    if(init_connection())
        errx(-1, "client cannot init connection with AES compartment...\n");

    printf("connection OK\n");
}

__attribute__((destructor))
void destroy() {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_EXIT;

    if (write(sock, &msg, sizeof(msg)) == -1)
        perror("write"); // can't really do anything else in a destructor

    close(sock);
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_INIT;
    memcpy(msg.msg.init.key, key, AES_KEYLEN);

    if (write(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client AES_init_ctx write");

    if (read(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client AES_init_ctx read");

    memcpy(ctx, &msg.msg.init.ctx, sizeof(struct AES_ctx));
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_INIT_IV;
    memcpy(msg.msg.init.key, key, AES_KEYLEN);
    memcpy(msg.msg.init.iv, iv, AES_BLOCKLEN);

    if (write(sock, &msg, sizeof(aes_comp_msg)) == -1)
        errx(-1, "client AES_init_ctx_iv write");

    if (read(sock, &msg, sizeof(aes_comp_msg)) == -1)
        errx(-1, "client AES_init_ctx_iv read");

    memcpy(ctx, &(msg.msg.init.ctx), sizeof(struct AES_ctx));

}

void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_SET_IV;
    memcpy(&msg.msg.init.ctx, ctx, sizeof(struct AES_ctx));
    memcpy(msg.msg.init.iv, iv, AES_BLOCKLEN);

    if (write(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client AES_ctx_set_iv write");

    if (read(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client AES_ctx_set_iv read");

    memcpy(ctx, &msg.msg.init.ctx, sizeof(struct AES_ctx));
}

void do_generic_crypt(aes_comp_crypt_mode mode, struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_CRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));
    msg.msg.crypt.mode = mode;
    msg.msg.crypt.buflen = length;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client crypt request write ctx");

    // send buffer
    if (write(sock, buf, length) == -1)
        errx(-1, "client crypt request write buffer");

    // read response ctx
    if (read(sock, &msg, sizeof(msg)) == -1)
        errx(-1, "client crypt request read ctx");

    memcpy(ctx, &msg.msg.crypt.ctx, sizeof(struct AES_ctx));

    // read response buffer
    if (read(sock, buf, length) == -1)
        errx(-1, "client crypt request read buffer");
}

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf) {
    // with ECB bufsize is always AES_BLOCKLEN
    do_generic_crypt(AES_COMP_ECB_ENCRYPT, (struct AES_ctx*) ctx, buf, AES_BLOCKLEN);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf) {
    do_generic_crypt(AES_COMP_ECB_DECRYPT, (struct AES_ctx*) ctx, buf, AES_BLOCKLEN);
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    do_generic_crypt(AES_COMP_CBC_ENCRYPT, ctx, buf, length);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    do_generic_crypt(AES_COMP_CBC_DECRYPT, ctx, buf, length);
}

void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    do_generic_crypt(AES_COMP_CTR_XCRYPT, ctx, buf, length);
}
