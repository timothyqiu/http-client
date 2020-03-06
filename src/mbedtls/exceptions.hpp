#ifndef OHC_MBEDTLS_EXCEPTIONS_HPP_
#define OHC_MBEDTLS_EXCEPTIONS_HPP_

#include <ohc/exceptions.hpp>

// static buffer
char const *mbedTlsTranslateError(int error);

class MbedTlsError : public OhcException {
public:
    MbedTlsError(char const *message, int error);
};

#endif  // OHC_MBEDTLS_EXCEPTIONS_HPP_
