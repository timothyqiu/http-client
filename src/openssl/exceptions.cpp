#include "exceptions.hpp"
#include <openssl/err.h>

OpenSslError::OpenSslError(char const *message)
    : OhcException{message}
{
    // TODO: store instead of print
    ERR_print_errors_fp(stderr);
}
