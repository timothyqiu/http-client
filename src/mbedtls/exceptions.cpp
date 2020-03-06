#include "exceptions.hpp"
#include <mbedtls/error.h>
#include <spdlog/spdlog.h>

char const *mbedTlsTranslateError(int error)
{
    static char buffer[256];
    mbedtls_strerror(error, buffer, sizeof(buffer));
    return buffer;
}

MbedTlsError::MbedTlsError(char const *message, int error)
    : OhcException{message}
{
    char buffer[256];
    mbedtls_strerror(error, buffer, sizeof(buffer));
    spdlog::error("{} ({}): {}", message, error, std::string{buffer});
}
