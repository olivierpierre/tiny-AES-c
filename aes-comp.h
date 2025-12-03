#ifndef AES_COMP_H
#define AES_COMP_H

// This file is included in both the compartment program, and in its client
// code. It describes the socket and data structures used for cross-compartment
// communications

#include "aes.h"

// Not idea, usng a UNIX socket with a hardcoded path makes that only one
// instance of the compartmentalized library can run at a time. The solution
// here would be to use a temporary file each time an instance is launched
#define SOCKET_PATH "/tmp/aes-comp.socket"

// The API exposed by the compartment, mirrors the API exposed by aes.h
typedef enum {
    AES_COMP_MSG_INIT=0,
    AES_COMP_MSG_INIT_IV,
    AES_COMP_MSG_SET_IV,
    AES_COMP_MSG_CRYPT, // factorize all encrypt/decrypt operations
    AES_COMP_MSG_EXIT
} aes_comp_msg_t;

// Message used for initialization functions: AES_init_ctx, AES_init_ctx_iv, 
// and AES_ctx_set_iv
typedef struct {
    struct AES_ctx ctx;
    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
} aes_comp_init_msg;

// encryption/decryption modes: AES_ECB_encrypt, AES_ECB_decrypt,
// AES_CBC_encrypt_buffer, AES_CBC_decrypt_buffer, and AES_CTR_xcrypt_buffer
typedef enum {
    AES_COMP_ECB_ENCRYPT=0,
    AES_COMP_ECB_DECRYPT,
    AES_COMP_CBC_ENCRYPT,
    AES_COMP_CBC_DECRYPT,
    AES_COMP_CTR_XCRYPT
} aes_comp_crypt_mode;

// encrypt/decrypt is a two phase operation: first we send this message
// containing the length of the buffer to transmit (ctx.buflen), then we send
// the buffer as raw bytes. This is the message that is sent first as part of
// calls to AES_ECB_encrypt/decrypt, AES_CBC_encrypt_buffer/decrypt_buffer, and
// AES_CTR_xcrypt_buffer
typedef struct {
    struct AES_ctx ctx;
    size_t buflen;
    aes_comp_crypt_mode mode;
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