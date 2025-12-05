// This is the compartment code: it implements the compartmentalised library.
// It receives requests from a client program through a socket and execute
// library calls on its behalf, sending the results back over the socket.

#include "aes-comp.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/random.h>

#define READ_TIMEOUT_MS    1500
#define ENABLE_FUZZING

#define MAX_BUFLEN  (10 * 1024 * 1024) // 10 MB

#ifdef ENABLE_FUZZING

static int init_connection(int *sock) {
    struct sockaddr_un addr;

    // Create a UNIX domain socket
    *sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(*sock < 0)
        errx(-1, "client socket");

    // Set up the address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Connect to the server
    int timeout_us = 1000000; // 1 sec timeout
    while (timeout_us) {
        if (connect(*sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
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

static void send_exit_msg(int *client_sock);
static int do_test_init_ctx(int *client_sock);

static void *client(void *arg) {
    int client_fd;

    init_connection(&client_fd);

    for(int i=0; i<10000; i++) {
        do_test_init_ctx(&client_fd);
    }
    
    send_exit_msg(&client_fd);

    pthread_exit(0);
}

static void send_exit_msg(int *client_sock) {
    aes_comp_msg msg;
    msg.type = AES_COMP_MSG_EXIT;
    write(*client_sock, &msg, sizeof(msg));
}

ssize_t read_with_timeout(int fd, void *buf, size_t len, int timeout_ms) {
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0)
        return -1;   // error
    if (ret == 0)
        return -2;   // timeout

    return read(fd, buf, len);
}

int  get_bytes_available(int fd) {
    int nbytes;
    ioctl(fd, FIONREAD, &nbytes);
    return nbytes;
}

static int do_test_init_ctx(int *client_sock) {
    char *buffer;
    int crypt_mode = 0;

    aes_comp_msg msg;
    getrandom(&msg, sizeof(msg), 0);

    do {
        msg.type = rand()%AES_COMP_MSG_NUM; // restrict message type to the ones that make sense
    } while(msg.type == AES_COMP_MSG_EXIT); // we don't want the exit message


    if(msg.type == AES_COMP_MSG_CRYPT)
        crypt_mode = 1;

    if(crypt_mode) {
        msg.msg.crypt.buflen = rand()%MAX_BUFLEN;
        msg.msg.crypt.mode = rand()%AES_COMP_CRYPT_NUM;

        // If we go crazy on buflen and comment the following two things the server times out for now...

        // force buflen to be a multiple of AES_BLOCKLEN
        // msg.msg.crypt.buflen = msg.msg.crypt.buflen - (msg.msg.crypt.buflen % AES_BLOCKLEN);

        // ECB will only accept buffers of size AES_BLOCKLEN
        // if (msg.msg.crypt.mode == AES_COMP_ECB_ENCRYPT || msg.msg.crypt.mode == AES_COMP_ECB_DECRYPT)
        //     msg.msg.crypt.buflen = AES_BLOCKLEN;
    }

    printf("type: %d, mode: %d, buflen: %lu\n", msg.type, msg.msg.crypt.mode, 
        msg.msg.crypt.buflen);

    int bytes_written = write(*client_sock, &msg, sizeof(aes_comp_msg));

    if(bytes_written == -1)
        errx(-1, "client write 1");

    if(crypt_mode) {
        int buflen = msg.msg.crypt.buflen;
        buffer = malloc(buflen);
        getrandom(buffer, buflen, 0);
        if (write(*client_sock, buffer, buflen) == -1)
            errx(-1, "client write 2");
    }

    int to_read = sizeof(aes_comp_msg);

    while(to_read) {
        int r = read_with_timeout(*client_sock, &msg, sizeof(aes_comp_msg), READ_TIMEOUT_MS);

        if(r == -1)
            errx(-1, "client read 1");

        if(r == -2) {
            if(crypt_mode)
                free(buffer);

            errx(-1, "client read 1 timed out");
        }

        to_read -= r;
    }

    if(crypt_mode) {
        if(!msg.msg.crypt.result) {

            int bytes_left = msg.msg.crypt.buflen;

            while(bytes_left) {
                int r = read_with_timeout(*client_sock, buffer, msg.msg.crypt.buflen, READ_TIMEOUT_MS);

                if(r == -1)
                    errx(-1, "client read 2");

                if(r == -2) {
                    free(buffer);
                    errx(-1, "client read 2 timed out");
                }

                bytes_left -= r;
            }
        }
        free(buffer);
    }

    int bytes_left = get_bytes_available(*client_sock);
    if(bytes_left)
        errx(-1, "%d bytes left in the socket at the end of a test!\n", bytes_left);

    return 0;
}

#endif /* ENABLE_FUZZING */

static int crypt_buflen_ok(size_t buflen, aes_comp_crypt_mode mode) {
    int ok = 1;

    // check that the buffer size is not too big
    if(buflen > MAX_BUFLEN)
        ok = 0;

    // check that buffer for CBC is a multiple of AES_BLOCKLEN
    if(buflen % AES_BLOCKLEN)
        ok = 0;

    // check that buffer for ECB is properly sized
    if(mode == AES_COMP_ECB_ENCRYPT || mode == AES_COMP_ECB_DECRYPT)
        if(buflen != AES_BLOCKLEN)
            ok = 0;

    return ok;
}

int main() {
    aes_comp_msg msg;
    uint8_t *buffer;
    int server_fd, client_fd;
    struct sockaddr_un addr;
    
#ifdef ENABLE_FUZZING
    pthread_t client_thread;
    pthread_create(&client_thread, NULL, client, NULL);
#endif

    // Remove any existing socket file
    unlink(SOCKET_PATH);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0)
        errx(-1, "compartment socket");

     // Set up the socket address structure
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        errx(-1, "compartment bind");

    // Listen for a connection
    if (listen(server_fd, 1) < 0)
        errx(-1, "compartment listen");

    // Accept a connection
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0)
        errx(-1, "compartment accept");

    int stop_server = 0;

    printf("compartment running\n");
    while(!stop_server) {

        // Receive request message
        int bytes_read = read(client_fd, &msg, sizeof(aes_comp_msg));

        if(bytes_read == -1)
            errx(-1, "compartment reading message");

        switch(msg.type) {
            case AES_COMP_MSG_INIT: {
                // AES_init_ctx

                aes_comp_init_msg *init = &msg.msg.init;
                AES_init_ctx(&(init->ctx), init->key);

                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                    errx(-1, "compartment write responding to AES_init_ctx");

                break;
            }

            case AES_COMP_MSG_INIT_IV: {
                // AES_ctx_set_iv

                aes_comp_init_msg *init = &msg.msg.init;
                AES_init_ctx_iv(&(init->ctx), init->key, init->iv);

                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                    errx(-1, "compartment write responding to AES_init_ctx_iv");

                break;
            }

            case AES_COMP_MSG_SET_IV: {
                // AES_ctx_set_iv

                aes_comp_init_msg *init = &msg.msg.init;
                AES_ctx_set_iv(&init->ctx, init->iv);
                
                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                    errx(-1, "compartment write responding to AES_ctx_set_iv");

                break;
            }

            case AES_COMP_MSG_CRYPT: {
                // encryption/decryption request

                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // check if buffer size is suitable
                if(!crypt_buflen_ok(crypt->buflen, crypt->mode)) {
                    // Something's wrong, send return ctx with an error code and abort
                    crypt->result = -1;
                    if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                        errx(-1, "compartment encrypt/decrypt header write");

                    continue;
                }

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer)
                    errx(-1, "compartment encrypt/decrypt cannot allocate mem (%lu bytes)", crypt->buflen);
                
                // buffer can be large enough to require several calls to read()
                int left_to_read = crypt->buflen;
                while(left_to_read) {
                    int bytes_read = read(client_fd, buffer, crypt->buflen);

                    if(bytes_read == -1)
                        errx(-1, "compartment encrypt/decrypt buffer read error");

                    left_to_read -= bytes_read;
                }

                // Call library function
                switch(msg.msg.crypt.mode) {
                    case AES_COMP_ECB_ENCRYPT:
                        AES_ECB_encrypt(&crypt->ctx, buffer);
                        crypt->result = 0;
                        break;

                    case AES_COMP_ECB_DECRYPT:
                        AES_ECB_decrypt(&crypt->ctx, buffer);
                        crypt->result = 0;
                        break;

                    case AES_COMP_CBC_ENCRYPT:
                        AES_CBC_encrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        crypt->result = 0;
                        break;

                    case AES_COMP_CBC_DECRYPT:
                        AES_CBC_decrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        crypt->result = 0;
                        break;

                    case AES_COMP_CTR_XCRYPT:
                        AES_CTR_xcrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        crypt->result = 0;
                        break;

                    default:
                        crypt->result = -1;
                }

                // send result ctx
                if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                    errx(-1, "compartment encrypt/decrypt header write");

                // send encrypted buffer 
                int to_send = crypt->buflen;
                while(to_send) {
                    int sent = write(client_fd, buffer, crypt->buflen);

                    if(sent == -1)
                        errx(-1, "compartment encrypt/decrypt buffer write");

                    to_send -= sent;
                }

                free(buffer);
                break;
            }

            case AES_COMP_MSG_EXIT: {
                stop_server = 1;
                break;
            }

            default: // to suppress warnings
        }

    }

    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);

#ifdef ENABLE_FUZZING
    pthread_join(client_thread, NULL);
#endif

    return 0;
}