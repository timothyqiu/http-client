#ifndef APPS_MBEDTLS_EXCEPTIONS_HPP_
#define APPS_MBEDTLS_EXCEPTIONS_HPP_

#include <stdexcept>

class MbedTlsError : public std::runtime_error {
public:
    MbedTlsError(char const *message, int error);
};

#endif  // APPS_MBEDTLS_EXCEPTIONS_HPP_
