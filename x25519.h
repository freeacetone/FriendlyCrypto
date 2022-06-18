/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#ifndef X25519_H
#define X25519_H

#include <string>
#include <array>
#include <vector>
#include <openssl/evp.h>

namespace FriendlyCrypto {

class X25519Keys
{
public:
    X25519Keys (const std::array<uint8_t, 32>& priv, const std::array<uint8_t, 32>& pub);
    X25519Keys();
    ~X25519Keys();

    void generateKeys()                                                                         noexcept;
    void setSecretKey (const uint8_t * priv,                bool calculatePublic = false)       noexcept;
    void setSecretKey (const std::array<uint8_t, 32>& priv, bool calculatePublic = false)       noexcept;
    void setSecretKey (const std::vector<uint8_t>& priv,    bool calculatePublic = false)               ;
    void setSecretKey (const std::string& priv,             bool calculatePublic = false)               ;
    const std::array<uint8_t, 32> getPublicKey()                                          const noexcept;
    const std::array<uint8_t, 32> getSecretKey()                                          const noexcept;
    const std::array<uint8_t, 32> agree (const std::array<uint8_t, 32>& pub)              const noexcept;
    const std::array<uint8_t, 32> agree (const std::string& pub)                          const noexcept;
    const std::array<uint8_t, 32> agree (const uint8_t* pub, size_t size = 32)            const noexcept;

    const std::string getPublicKeyBase64String()                                          const noexcept;
    const std::string getSecretKeyBase64String()                                          const noexcept;

private:
    std::array<uint8_t, 32> m_publicKey {0};
    EVP_PKEY_CTX * m_Ctx;
    EVP_PKEY * m_Pkey;
};

} // namespace

#endif // X25519_H
