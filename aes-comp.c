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

int main() {
    aes_comp_msg msg;
    uint8_t *buffer;
    int server_fd, client_fd;
    struct sockaddr_un addr;

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
        if(read(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
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

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer)
                    errx(-1, "compartment encrypt/decrypt cannot allocate mem");
                
                if (read(client_fd, buffer, crypt->buflen) == -1)
                    errx(-1, "compartment encrypt/decrypt buffer read error");

                // Call library function
                switch(msg.msg.crypt.mode) {
                    case AES_COMP_ECB_ENCRYPT:
                        AES_ECB_encrypt(&crypt->ctx, buffer);
                        break;
                    case AES_COMP_ECB_DECRYPT:
                        AES_ECB_decrypt(&crypt->ctx, buffer);
                        break;
                    case AES_COMP_CBC_ENCRYPT:
                        AES_CBC_encrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        break;
                    case AES_COMP_CBC_DECRYPT:
                        AES_CBC_decrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        break;
                    case AES_COMP_CTR_XCRYPT:
                        AES_CTR_xcrypt_buffer(&crypt->ctx, buffer, crypt->buflen);
                        break;
                }

                // send result ctx
                if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1)
                    errx(-1, "compartment encrypt/decrypt header write");

                // send encrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1)
                    errx(-1, "compartment encrypt/decrypt buffer write");

                free(buffer);
                break;
            }

            case AES_COMP_MSG_EXIT: {
                stop_server = 1;
                break;
            }
        }

    }

    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);

    return 0;
}