/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#ifndef ED25519_H
#define ED25519_H

#include <vector>
#include <string>
#include <array>
#include <memory>

using uint8_t = unsigned char;

namespace FriendlyCrypto {
namespace Ed25519 {

class KeyPair {
public:
    KeyPair() {}
    void generateKeys()                                            noexcept;
    void setSecretKey(const std::array<uint8_t, 32>& secret)       noexcept;
    const std::array<uint8_t, 32> getSecretKey()             const noexcept;
    const std::array<uint8_t, 32> getPublicKey()             const noexcept;

    std::string getPublicKeyBase64String()                   const noexcept;
    std::string getSecretKeyBase64String()                   const noexcept;

private:
    std::array<uint8_t, 32> m_secret;
    std::array<uint8_t, 32> m_public;
};

class Signature {
public:
    Signature(const std::array<uint8_t, 64>& raw)
        : m_data( new std::array<uint8_t, 64>(raw) ) {}
    const std::shared_ptr<std::array<uint8_t, 64>> data()      const noexcept;
    std::string base64String()                                 const noexcept;

    bool operator==(const Ed25519::Signature& another)           const noexcept;
    bool operator==(const std::array<uint8_t, 64>& rawAnother) const noexcept;
    bool operator==(const std::string& base64String)           const noexcept;

private:
    std::shared_ptr<std::array<uint8_t, 64>> m_data;
};

//// FUNTIONS

Ed25519::Signature sign (const std::vector<uint8_t>& message, const std::array<uint8_t, 32>& secretKey) noexcept;
bool verify (const std::vector<uint8_t>& message, const Ed25519::Signature& signature, const std::array<uint8_t, 32>& publicKey) noexcept;

} // namespace Ed25519
} // namespace FriendlyCrypto

#endif // ED25519_H
