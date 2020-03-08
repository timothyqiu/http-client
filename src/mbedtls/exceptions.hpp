#ifndef OHC_MBEDTLS_EXCEPTIONS_HPP_
#define OHC_MBEDTLS_EXCEPTIONS_HPP_

#include <ohc/exceptions.hpp>

// static buffer
auto mbedTlsTranslateError(int error) -> char const *;

class MbedTlsError : public OhcException {
public:
    MbedTlsError(char const *message, int error);
};

#endif  // OHC_MBEDTLS_EXCEPTIONS_HPP_
