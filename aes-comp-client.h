#ifndef AES_COMP_CLIENT_H
#define AES_COMP_CLIENT_H

// Interface exposed by our compartmentalized library client, i.e. the code
// that runs with any program wishing to make use of the compartmentalised
// version of the library. It exposes the exact same API as the library, so
// integration is mostly transparent

#include "aes-comp.h"

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
int do_generic_crypt(aes_comp_crypt_mode mode, struct AES_ctx* ctx,
        uint8_t* buf, size_t length);
int AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
int AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
int AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
int AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
int AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif /* AES_COMP_CLIENT_H */