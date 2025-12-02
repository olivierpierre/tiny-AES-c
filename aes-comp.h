#ifndef AES_COMP_H
#define AES_COMP_H

#include "aes.h"

// TODO make that a random tempfile
#define SOCKET_PATH "/tmp/aes-comp.h"

// The API exposed by the compartment, mirrors the API exposed by aes.h
typedef enum {
    AES_COMP_MSG_INIT=0,
    AES_COMP_MSG_INIT_IV,
    AES_COMP_MSG_SET_IV,
    AES_COMP_MSG_ECB_ENCRYPT,
    AES_COMP_MSG_ECB_DECRYPT,
    AES_COMP_MSG_CBC_ENCRYPT,
    AES_COMP_MSG_EXIT
} aes_comp_msg_t;

// Message used for initialization functions: AES_init_ctx, AES_init_ctx_iv, 
// and AES_ctx_set_iv
typedef struct {
    struct AES_ctx ctx;
    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
} aes_comp_init_msg;

// encrypt/decrypt is a two phase operation: first we send this message
// containing the length of the buffer to transmit, then we send the buffer
// as raw bytes. This is the message that is sent first as part of calls to
// AES_ECB_encrypt/decrypt, AES_CBC_encrypt_buffer/decrypt_buffer, and
// AES_CTR_xcrypt_buffer
typedef struct {
    struct AES_ctx ctx;
    size_t buflen;
} aes_comp_crypt_msg;

// Generic message
typedef struct {
    aes_comp_msg_t type;
    union {
        aes_comp_init_msg init;
        aes_comp_crypt_msg crypt;
    } msg;
} aes_comp_msg;

#endif /* AES_COMP_H */