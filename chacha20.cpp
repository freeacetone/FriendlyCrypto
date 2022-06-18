/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include "chacha20.h"

#include <memory>
#include <openssl/evp.h>

namespace FriendlyCrypto {

std::vector<uint8_t> chaCha20 (const std::vector<uint8_t> &msg, const std::array<uint8_t, 32> &key, const uint8_t *nonce)
{
    uint8_t fakenonce[24] {0};
    if (!nonce)
    {
        nonce = fakenonce;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
    uint32_t iv[4];
    iv[0] = htole32 (1); memcpy (iv + 1, nonce, 12); // counter | nonce
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key.data(), reinterpret_cast<const uint8_t*>(iv));
    std::vector<uint8_t> out(msg.size());
    int outlen = msg.size();
    EVP_EncryptUpdate(ctx, out.data(), &outlen, msg.data(), msg.size());
    EVP_EncryptFinal_ex(ctx, NULL, &outlen);
    EVP_CIPHER_CTX_free (ctx);
    return out;
}

std::vector<uint8_t> chaCha20 (const uint8_t *msg, size_t msgSize, const std::array<uint8_t, 32> &key, const uint8_t *nonce)
{
    std::vector<uint8_t> vector;
    for (size_t i = 0; i < msgSize; ++i)
    {
        vector.push_back(msg[i]);
    }
    return chaCha20(vector, key, nonce);
}

} // namespace
