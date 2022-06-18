/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include "ed25519.h"
#include "cppcodec/cppcodec/base64_default_rfc4648.hpp"

#include <openssl/evp.h>

namespace FriendlyCrypto {
namespace Ed25519 {

//// KeyPair

void KeyPair::generateKeys() noexcept
{
    EVP_PKEY_CTX * Ctx;
    EVP_PKEY * Pkey = nullptr;
    Ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_ED25519, NULL);

    EVP_PKEY_keygen_init (Ctx);
    EVP_PKEY_keygen (Ctx, &Pkey);

    size_t len = 32;
    EVP_PKEY_get_raw_public_key (Pkey, m_public.data(), &len);
    EVP_PKEY_get_raw_private_key (Pkey, m_secret.data(), &len);

    EVP_PKEY_CTX_free(Ctx);
    EVP_PKEY_free(Pkey);
}

void KeyPair::setSecretKey (const std::array<uint8_t, 32> &secret) noexcept
{
    m_secret = secret;

    EVP_PKEY * Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_ED25519, NULL, m_secret.data(), 32);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key (Pkey, m_public.data(), &len);

    EVP_PKEY_free(Pkey);
}

const std::array<uint8_t, 32> KeyPair::getSecretKey() const noexcept
{
    return m_secret;
}

const std::array<uint8_t, 32> KeyPair::getPublicKey() const noexcept
{
    return m_public;
}

std::string KeyPair::getPublicKeyBase64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode (getPublicKey().data(), getPublicKey().size());
}

std::string KeyPair::getSecretKeyBase64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode (getSecretKey().data(), getSecretKey().size());
}

//// Signature

const std::shared_ptr<std::array<uint8_t, 64>> Signature::data() const noexcept
{
    return m_data;
}

std::string Signature::base64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode(m_data->data(), 64);
}

bool Signature::operator==(const Signature &another) const noexcept
{
    return m_data == another.data();
}

bool Signature::operator==(const std::array<uint8_t, 64> &rawAnother) const noexcept
{
    return *m_data == rawAnother;
}

bool Signature::operator==(const std::string &base64String) const noexcept
{
    std::vector<uint8_t> anotherSignatureVector;
    try {
        anotherSignatureVector = cppcodec::base64_rfc4648::decode(base64String);
    } catch (...) {
        return false;
    }

    if (anotherSignatureVector.size() != 64)
    {
        return false;
    }

    std::array<uint8_t, 64> rawAnother;
    for (int i = 0; i < 64; ++i)
    {
        rawAnother[i] = anotherSignatureVector[i];
    }

    return operator==(rawAnother);
}

//// FUNCTIONS

Ed25519::Signature sign (const std::vector<uint8_t> &message, const std::array<uint8_t, 32> &secretKey) noexcept
{
    auto MDCtx = EVP_MD_CTX_create();
    auto PKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_ED25519, NULL, secretKey.data(), 32);
    EVP_DigestSignInit (MDCtx, NULL, NULL, NULL, PKey);

    size_t length = 64;
    std::array<uint8_t, 64> signature;

    EVP_DigestSign (MDCtx, signature.data(), &length, message.data(), message.size());

    EVP_PKEY_free(PKey);
    EVP_MD_CTX_destroy (MDCtx);

    return signature;
}

bool verify (const std::vector<uint8_t> &message, const Ed25519::Signature &signature, const std::array<uint8_t, 32> &publicKey) noexcept
{
    auto MDCtx = EVP_MD_CTX_create();
    auto PKey = EVP_PKEY_new_raw_public_key (EVP_PKEY_ED25519, NULL, publicKey.data(), 32);
    EVP_DigestVerifyInit (MDCtx, NULL, NULL, NULL, PKey);

    bool res = EVP_DigestVerify (MDCtx, signature.data()->data(), 64, message.data(), message.size());

    EVP_PKEY_free(PKey);
    EVP_MD_CTX_destroy (MDCtx);

    return res;
}

} // namespace Ed25519
} // namespace FriendlyCrypto
