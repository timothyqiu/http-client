#ifndef OHC_EXCEPTION_HPP_
#define OHC_EXCEPTION_HPP_

#include <stdexcept>

class OpenSslError : public std::runtime_error {
public:
    explicit OpenSslError(char const *message);
};

#endif  // OHC_EXCEPTION_HPP_
