/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include "x25519.h"
#include "cppcodec/cppcodec/base64_default_rfc4648.hpp"

#include <iostream>
#include <memory>

namespace FriendlyCrypto {

X25519Keys::X25519Keys()
{
    m_Ctx = EVP_PKEY_CTX_new_id (NID_X25519, NULL);
    m_Pkey = nullptr;
}

X25519Keys::X25519Keys (const std::array<uint8_t, 32> &priv, const std::array<uint8_t, 32> &pub)
{
    m_Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, priv.data(), 32);
    m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL);
    if (not pub.empty())
    {
        memcpy (m_publicKey.data(), pub.data(), 32);
    }
    else
    {
        size_t len = 32;
        EVP_PKEY_get_raw_public_key (m_Pkey, m_publicKey.data(), &len);
    }
}

X25519Keys::~X25519Keys()
{
    EVP_PKEY_CTX_free (m_Ctx);
    if (m_Pkey) EVP_PKEY_free (m_Pkey);
}

void X25519Keys::generateKeys() noexcept
{
    if (m_Pkey)
    {
        EVP_PKEY_free (m_Pkey);
        m_Pkey = nullptr;
    }
    EVP_PKEY_keygen_init (m_Ctx);
    EVP_PKEY_keygen (m_Ctx, &m_Pkey);
    EVP_PKEY_CTX_free (m_Ctx);
    m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key (m_Pkey, m_publicKey.data(), &len);
}

const std::array<uint8_t, 32> X25519Keys::getPublicKey() const noexcept
{
    return m_publicKey;
}

const std::array<uint8_t, 32> X25519Keys::getSecretKey() const noexcept
{
    std::array<uint8_t, 32> priv;
    size_t len = 32;
    EVP_PKEY_get_raw_private_key (m_Pkey, priv.data(), &len);
    return priv;
}

const std::array<uint8_t, 32> X25519Keys::agree (const std::array<uint8_t, 32> &pub) const noexcept
{
    std::array<uint8_t, 32> shared;
    if (pub.size() < 32 or (pub[31] & 0x80)) return shared; // not x25519 key

    EVP_PKEY_derive_init (m_Ctx);
    auto pkey = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, NULL, pub.data(), 32);
    if (!pkey) return shared;
    EVP_PKEY_derive_set_peer (m_Ctx, pkey);
    size_t len = 32;
    EVP_PKEY_derive (m_Ctx, shared.data(), &len);
    EVP_PKEY_free (pkey);
    return shared;
}

const std::array<uint8_t, 32> X25519Keys::agree (const std::string &pub) const noexcept
{
    std::vector<uint8_t> bytes;
    try {
        bytes = cppcodec::base64_rfc4648::decode(pub);
    } catch (...) {
        return  std::array<uint8_t, 32>();
    }
    return agree (bytes.data(), bytes.size());
}

const std::array<uint8_t, 32> X25519Keys::agree (const uint8_t *pub, size_t size) const noexcept
{
    if (size != 32)
    {
        return std::array<uint8_t, 32>();
    }

    std::array<uint8_t, 32> key;
    for (int i = 0; i < 32; i++)
    {
        key[i] = pub[i];
    }
    return agree(key);
}

void X25519Keys::setSecretKey (const uint8_t * priv, bool calculatePublic) noexcept
{
    if (m_Ctx) EVP_PKEY_CTX_free (m_Ctx);
    if (m_Pkey) EVP_PKEY_free (m_Pkey);
    m_Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, priv, 32);
    m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL);
    if (calculatePublic)
    {
        size_t len = 32;
        EVP_PKEY_get_raw_public_key (m_Pkey, m_publicKey.data(), &len);
    }
}

void X25519Keys::setSecretKey (const std::string &priv, bool calculatePublic)
{
    std::vector<uint8_t> keyBytes = cppcodec::base64_rfc4648::decode(priv);
    setSecretKey (keyBytes, calculatePublic);
}

void X25519Keys::setSecretKey (const std::vector<uint8_t>& priv, bool calculatePublic)
{
    if (priv.size() != 32)
    {
        throw std::runtime_error ("X25519Keys::setPrivateKey priv array size != 32");
    }
    setSecretKey (priv.data(), calculatePublic);
}

void X25519Keys::setSecretKey (const std::array<uint8_t, 32> &priv, bool calculatePublic)
{
    setSecretKey (priv.data(), calculatePublic);
}

std::string X25519Keys::getPublicKeyBase64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode (getPublicKey().data(), getPublicKey().size());
}

std::string X25519Keys::getSecretKeyBase64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode (getSecretKey().data(), getSecretKey().size());
}

} // namespace
