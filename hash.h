#ifndef HASH_H
#define HASH_H

#include <vector>
/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include <string>

using uint8_t = unsigned char;

namespace FriendlyCrypto {
namespace Hash {

class Sum {
public:
    Sum (const std::vector<uint8_t>& raw)
        : m_data(raw) {};

    const std::vector<uint8_t> data()                       const noexcept;
    const std::string base64String()                        const noexcept;

    bool operator==(const Hash::Sum& another)               const noexcept;
    bool operator==(const std::vector<uint8_t>& rawAnother) const noexcept;
    bool operator==(const std::string& base64String)        const noexcept;

private:
    std::vector<uint8_t> m_data;
};

//// FUNCTIONS

Hash::Sum sha256 (const std::vector<uint8_t>& data) noexcept;
Hash::Sum sha512 (const std::vector<uint8_t>& data) noexcept;
Hash::Sum md5 (const std::vector<uint8_t>& data) noexcept;

} // namespace Hash
} // namespace FriendlyCrypto

#endif // HASH_H
