/*
 * Based on
 * 1. OpenSSL lib
 * 2. PurpleI2P source code
 * 3. cppcodec lib
 *
 * PUBLIC DOMAIN C++ WRAPPER
 * acetone, 2022
 */

#ifndef TRANSFORM_H
#define TRANSFORM_H

#include <vector>
#include <array>

using uint8_t = unsigned char;

namespace FriendlyCrypto {
namespace Transform {

template<size_t T>
std::vector<uint8_t> arrayToVector (const std::array<uint8_t, T> &array) noexcept
{
    std::vector<uint8_t> result;
    for (const auto& byte: array)
    {
        result.push_back(byte);
    }
    return result;
}

template <size_t T>
std::array<uint8_t, T> vectorToArray (const std::vector<uint8_t>& vector) noexcept
{
    static_assert (T<512, "FriendlyCrypto::Transform::vectorToArray size of array too big (>512B). "
                          "For sure using a std::array which uses the stack (not the heap) is a bad solution for you.");

    std::array<uint8_t, T> result {0};
    for (size_t i = 0; i < T and i < vector.size(); ++i)
    {
        result[i] = vector[i];
    }
    return result;
}

} // namespace Transform
} // namespace FriendlyCrypto

#endif // TRANSFORM_H
