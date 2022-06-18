/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#include "hash.h"
#include "cppcodec/cppcodec/base64_default_rfc4648.hpp"

#include <openssl/sha.h>
#include <openssl/md5.h>

namespace FriendlyCrypto {
namespace Hash {

const std::vector<uint8_t> Sum::data() const noexcept
{
    return m_data;
}

const std::string Sum::base64String() const noexcept
{
    return cppcodec::base64_rfc4648::encode (data());
}

bool Sum::operator==(const Sum &another) const noexcept
{
    return m_data == another.data();
}

bool Sum::operator==(const std::vector<uint8_t> &rawAnother) const noexcept
{
    return m_data == rawAnother;
}

bool Sum::operator==(const std::string &base64String) const noexcept
{
    std::vector<uint8_t> rawAnother;
    try {
        rawAnother = cppcodec::base64_rfc4648::decode(base64String);
    } catch (...) {
        return false;
    }

    return operator==(rawAnother);
}

Sum sha256 (const std::vector<uint8_t> &data) noexcept
{
    std::vector<uint8_t> result (SHA256_DIGEST_LENGTH);
    SHA256 (data.data(), data.size(), result.data());
    return result;
}

Sum sha512 (const std::vector<uint8_t> &data) noexcept
{
    std::vector<uint8_t> result (SHA512_DIGEST_LENGTH);
    SHA512 (data.data(), data.size(), result.data());
    return result;
}

Sum md5 (const std::vector<uint8_t> &data) noexcept
{
    std::vector<uint8_t> result (MD5_DIGEST_LENGTH);
    MD5 (data.data(), data.size(), result.data());
    return result;
}

} // namespace Hash
} // namespace FriendlyCrypto
