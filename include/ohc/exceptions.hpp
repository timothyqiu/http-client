#ifndef OHC_EXCEPTION_HPP_
#define OHC_EXCEPTION_HPP_

#include <stdexcept>
#include <string>

class OhcException : public std::runtime_error {
public:
    OhcException(char const *message)
        : std::runtime_error{message}
    {
    }

    OhcException(std::string const& message)
        : std::runtime_error{message}
    {
    }
};

class EndOfStreamError : public OhcException {
public:
    EndOfStreamError()
        : OhcException{"end of stream reached"}
    {
    }
};

#endif  // OHC_EXCEPTION_HPP_
