#include "exceptions.hpp"
#include <array>
#include <mbedtls/error.h>
#include <spdlog/spdlog.h>

auto mbedTlsTranslateError(int error) -> char const *
{
    static std::array<char, 256> buffer;
    mbedtls_strerror(error, buffer.data(), buffer.size());
    return buffer.data();
}

MbedTlsError::MbedTlsError(char const *message, int error)
    : OhcException{message}
{
    std::array<char, 256> buffer;
    mbedtls_strerror(error, buffer.data(), buffer.size());
    spdlog::error("{} ({}): {}", message, error, buffer.data());
}
