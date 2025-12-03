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

#define SERVER_BINARY "./aes-comp"

int sock;
int aes_pid;


// prints string as hex
// static void phex(uint8_t* str) {

// #if defined(AES256)
//     uint8_t len = 32;
// #elif defined(AES192)
//     uint8_t len = 24;
// #elif defined(AES128)
//     uint8_t len = 16;
// #endif

//     unsigned char i;
//     for (i = 0; i < len; ++i)
//         printf("%.2x", str[i]);
//     printf("\n");
// }

int wait_for_socket() {
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

int init_connection() {
    struct sockaddr_un addr;

    // Create a UNIX domain socket
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

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
                perror("client connect");
                close(sock);
                return EXIT_FAILURE;
            }
        } else {
            break;
        }
    }

    return 0;
}

int start_server() {
    char *args[] = {SERVER_BINARY, NULL};
    char *envp[] = {NULL};

    int r = fork();

    if(r < 0)
        return -1;

    if(r == 0) {
        execve(SERVER_BINARY, args, envp);
        return -1;
    } else
        aes_pid = r;

    if(wait_for_socket()) {
        return -1;
    }

    return 0;
}

__attribute__((constructor))
void init() {
    printf("initializing compartment...\n");

    if(start_server()) {
        printf("ERROR: cannot start AES compartment...\n");
        exit(-1);
    }

    printf("sever start OK\n");

    if(init_connection()) {
        printf("ERROR: cannot init connection with AES compartment...\n");
        exit(-1);
    }

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

    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    if (read(sock, &msg, sizeof(msg)) == -1) {
        perror("read");
        exit(-1);
    }

    memcpy(ctx, &msg.msg.init.ctx, sizeof(struct AES_ctx));
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_INIT_IV;
    memcpy(msg.msg.init.key, key, AES_KEYLEN);
    memcpy(msg.msg.init.iv, iv, AES_BLOCKLEN);

    if (write(sock, &msg, sizeof(aes_comp_msg)) == -1) {
        perror("write");
        exit(-1);
    }

    if (read(sock, &msg, sizeof(aes_comp_msg)) == -1) {
        perror("read");
        exit(-1);
    }

    memcpy(ctx, &(msg.msg.init.ctx), sizeof(struct AES_ctx));

}

void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_SET_IV;
    memcpy(&msg.msg.init.ctx, ctx, sizeof(struct AES_ctx));
    memcpy(msg.msg.init.iv, iv, AES_BLOCKLEN);

    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    if (read(sock, &msg, sizeof(msg)) == -1) {
        perror("read");
        exit(-1);
    }

    memcpy(ctx, &msg.msg.init.ctx, sizeof(struct AES_ctx));
}

void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_ECB_ENCRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));

    // here the buffer size is always AES_BLOCKLEN
    msg.msg.crypt.buflen = AES_BLOCKLEN;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    // send buffer
    if (write(sock, buf, AES_BLOCKLEN) == -1) {
        perror("write");
        exit(-1);
    }

    // read response buffer
    if (read(sock, buf, AES_BLOCKLEN) == -1) {
        perror("read");
        exit(-1);
    }
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_ECB_DECRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));

    // here the buffer size is always AES_BLOCKLEN
    msg.msg.crypt.buflen = AES_BLOCKLEN;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    // send buffer
    if (write(sock, buf, AES_BLOCKLEN) == -1) {
        perror("write");
        exit(-1);
    }

    // read response buffer
    if (read(sock, buf, AES_BLOCKLEN) == -1) {
        perror("read");
        exit(-1);
    }
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_CBC_ENCRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));
    msg.msg.crypt.buflen = length;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    // send buffer
    if (write(sock, buf, length) == -1) {
        perror("write");
        exit(-1);
    }

    // read response ctx: contrary to ECB this is needed here because the call
    // will update the IV which is part of ctx
    if (read(sock, &msg, sizeof(msg)) == -1) {
        perror("read");
        exit(-1);
    }
    memcpy(ctx, &msg.msg.crypt.ctx, sizeof(struct AES_ctx));

    // read response buffer
    if (read(sock, buf, length) == -1) {
        perror("read");
        exit(-1);
    }
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_CBC_DECRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));
    msg.msg.crypt.buflen = length;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    // send buffer
    if (write(sock, buf, length) == -1) {
        perror("write");
        exit(-1);
    }

    // read response ctx
    if (read(sock, &msg, sizeof(msg)) == -1) {
        perror("read");
        exit(-1);
    }
    memcpy(ctx, &msg.msg.crypt.ctx, sizeof(struct AES_ctx));

    // read response buffer
    if (read(sock, buf, length) == -1) {
        perror("read");
        exit(-1);
    }
}

void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_CTR_XCRYPT;
    memcpy(&msg.msg.crypt.ctx, ctx, sizeof(struct AES_ctx));
    msg.msg.crypt.buflen = length;

    // send message
    if (write(sock, &msg, sizeof(msg)) == -1) {
        perror("write");
        exit(-1);
    }

    // send buffer
    if (write(sock, buf, length) == -1) {
        perror("write");
        exit(-1);
    }

    // read response ctx
    if (read(sock, &msg, sizeof(msg)) == -1) {
        perror("read");
        exit(-1);
    }
    memcpy(ctx, &msg.msg.crypt.ctx, sizeof(struct AES_ctx));

    // read response buffer
    if (read(sock, buf, length) == -1) {
        perror("read");
        exit(-1);
    }
}