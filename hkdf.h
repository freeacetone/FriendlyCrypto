/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#ifndef HKDF_H
#define HKDF_H

#include <array>
#include <string>

using uint8_t = unsigned char;

namespace FriendlyCrypto {
std::array<uint8_t, 32> hkdf (const std::array<uint8_t, 32> &key, const std::string &info, const uint8_t *salt = nullptr) noexcept;
}

#endif // HKDF_H
