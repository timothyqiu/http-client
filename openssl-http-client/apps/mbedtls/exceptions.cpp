#include "exceptions.hpp"
#include <mbedtls/error.h>
#include <spdlog/spdlog.h>

MbedTlsError::MbedTlsError(char const *message, int error)
    : std::runtime_error{message}
{
    char buffer[256];
    mbedtls_strerror(error, buffer, sizeof(buffer));
    spdlog::error("{} ({}): {}", message, error, std::string{buffer});
}
