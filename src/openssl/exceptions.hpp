#ifndef OHC_OPENSSL_EXCEPTION_HPP_
#define OHC_OPENSSL_EXCEPTION_HPP_

#include <ohc/exceptions.hpp>

class OpenSslError : public OhcException {
public:
    explicit OpenSslError(char const *message);
};

#endif  // OHC_OPENSSL_EXCEPTION_HPP_
