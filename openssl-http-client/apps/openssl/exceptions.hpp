#ifndef APPS_OPENSSL_EXCEPTION_HPP_
#define APPS_OPENSSL_EXCEPTION_HPP_

#include <stdexcept>

class OpenSslError : public std::runtime_error {
public:
    explicit OpenSslError(char const *message);
};

#endif  // APPS_OPENSSL_EXCEPTION_HPP_
