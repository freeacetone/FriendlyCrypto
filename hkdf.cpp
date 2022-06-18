/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include "hkdf.h"

#include <openssl/kdf.h>
#include <openssl/hmac.h>

namespace FriendlyCrypto {

std::array<uint8_t, 32> hkdf (const std::array<uint8_t, 32> &key, const std::string &info, const uint8_t *salt)
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init (pctx);
    EVP_PKEY_CTX_set_hkdf_md (pctx, EVP_sha256());
    if (key.size())
    {
        EVP_PKEY_CTX_set1_hkdf_salt (pctx, salt, 32);
        EVP_PKEY_CTX_set1_hkdf_key (pctx, key.data(), key.size());
    }
    else // zerolen
    {
        EVP_PKEY_CTX_hkdf_mode (pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        uint8_t tempKey[32]; unsigned int len;
        HMAC(EVP_sha256(), salt, 32, nullptr, 0, tempKey, &len);
        EVP_PKEY_CTX_set1_hkdf_key (pctx, tempKey, len);
    }

    if (info.length () > 0)
    {
        EVP_PKEY_CTX_add1_hkdf_info (pctx, info.c_str(), info.length());
    }

    std::array<uint8_t, 32> out;
    size_t len = out.size();
    EVP_PKEY_derive (pctx, out.data(), &len);
    EVP_PKEY_CTX_free (pctx);
    return out;
}

} // namespace
