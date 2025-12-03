#include "aes-comp.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    aes_comp_msg msg;
    uint8_t *buffer;
    int server_fd, client_fd;
    struct sockaddr_un addr;

    // Remove any existing socket file
    unlink(SOCKET_PATH);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

     // Set up the socket address structure
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }

    // Listen for a connection
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    // Accept a connection
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        exit(1);
    }

    int stop_server = 0;

    printf("server running\n");
    while(!stop_server) {

        // Receive data
        int r = read(client_fd, &msg, sizeof(aes_comp_msg));
        if(r == -1) {
            printf("error reading request\n");
            break;
        }

        switch(msg.type) {
            case AES_COMP_MSG_INIT: {
                // printf("received request for AES_init_ctx\n");

                aes_comp_init_msg *init = &msg.msg.init;
                AES_init_ctx(&(init->ctx), init->key);

                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }
                break;
            }

            case AES_COMP_MSG_INIT_IV: {
                aes_comp_init_msg *init = &msg.msg.init;
                AES_init_ctx_iv(&(init->ctx), init->key, init->iv);

                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }
                break;
            }

            case AES_COMP_MSG_SET_IV: {
                aes_comp_init_msg *init = &msg.msg.init;
                AES_ctx_set_iv(&init->ctx, init->iv);
                
                if(write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }
                break;
            }

            case AES_COMP_MSG_ECB_ENCRYPT: {
                // printf("received request for AES_ECB_encrypt\n");
                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer) {
                    perror("malloc");
                    break;
                }

                if (read(client_fd, buffer, crypt->buflen) == -1) {
                    perror("read");
                    break;
                }

                AES_ECB_encrypt(&crypt->ctx, buffer);

                // send result: we just need to send back the encrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1) {
                    perror("write");
                    break;
                }

                free(buffer);
                break;
            }

            case AES_COMP_MSG_ECB_DECRYPT: {
                // printf("received request for AES_ECB_decrypt\n");
                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer) {
                    perror("malloc");
                    break;
                }

                if (read(client_fd, buffer, crypt->buflen) == -1) {
                    perror("read");
                    break;
                }

                AES_ECB_decrypt(&crypt->ctx, buffer);

                // send decrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1) {
                    perror("write");
                    break;
                }

                free(buffer);
                break;
            }

            case AES_COMP_MSG_CBC_ENCRYPT: {
                // printf("received request for AES_CBC_encrypt\n");
                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer) {
                    perror("malloc");
                    break;
                }
                
                if (read(client_fd, buffer, crypt->buflen) == -1) {
                    perror("read");
                    break;
                }

                AES_CBC_encrypt_buffer(&crypt->ctx, buffer, crypt->buflen);

                // send result ctx
                if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }

                // send encrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1) {
                    perror("write");
                    break;
                }

                free(buffer);
                break;
            }

            case AES_COMP_MSG_CBC_DECRYPT: {
                // printf("received request for AES_CBC_decrypt\n");
                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer) {
                    perror("malloc");
                    break;
                }
                
                if (read(client_fd, buffer, crypt->buflen) == -1) {
                    perror("read");
                    break;
                }

                AES_CBC_decrypt_buffer(&crypt->ctx, buffer, crypt->buflen);

                // send result ctx
                if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }

                // send encrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1) {
                    perror("write");
                    break;
                }

                free(buffer);
                break;
            }

            case AES_COMP_MSG_CTR_XCRYPT: {
                // printf("received request for AES_CTR_xcrypt\n");
                aes_comp_crypt_msg *crypt = &msg.msg.crypt;

                // allocate and receive buffer
                buffer = malloc(crypt->buflen);
                if(!buffer) {
                    perror("malloc");
                    break;
                }
                
                if (read(client_fd, buffer, crypt->buflen) == -1) {
                    perror("read");
                    break;
                }

                AES_CTR_xcrypt_buffer(&crypt->ctx, buffer, crypt->buflen);

                // send result ctx
                if (write(client_fd, &msg, sizeof(aes_comp_msg)) == -1) {
                    perror("write");
                    break;
                }

                // send encrypted buffer 
                if (write(client_fd, buffer, crypt->buflen) == -1) {
                    perror("write");
                    break;
                }

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