/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#ifndef CHACHA20_H
#define CHACHA20_H

#include <vector>
#include <array>

using uint8_t = unsigned char;

namespace FriendlyCrypto {
#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/endian.h>

#elif defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__GLIBC__)
#include <endian.h>

#elif defined(__APPLE__) && defined(__MACH__)
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)

#else
#define htole32
#endif

std::vector<uint8_t> chaCha20 (const std::vector<uint8_t>& msg, const std::array<uint8_t, 32>& key, const uint8_t * nonce = nullptr) noexcept;
std::vector<uint8_t> chaCha20 (const uint8_t* msg, size_t msgSize, const std::array<uint8_t, 32>& key, const uint8_t * nonce = nullptr) noexcept;
}

#endif // CHACHA20_H
