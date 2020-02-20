#include "exception.hpp"

#include <OpenSSL/err.h>

OpenSslError::OpenSslError(char const *message)
    : std::runtime_error{message}
{
    // TODO: store instead of print
    ERR_print_errors_fp(stderr);
}
