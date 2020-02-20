#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <string>
#include <vector>

#include <OpenSSL/bio.h>
#include <OpenSSL/err.h>

#include "scope_guard.hpp"

class OpenSslError : public std::runtime_error {
public:
    OpenSslError(char const *message)
        : std::runtime_error{message}
    {
        // TODO: store instead of print
        ERR_print_errors_fp(stderr);
    }
};

// TODO: get rid of the ugly bool
static bool receiveData(BIO *bio, std::vector<char>& buffer, size_t& received)
{
    size_t const minimumAvailable = 128;
    while (buffer.size() - received < minimumAvailable) {
        buffer.resize(std::max(buffer.size() * 2, buffer.size() + minimumAvailable));
    }

    int const n = BIO_read(bio, buffer.data() + received, buffer.size() - received);
    if (n < 1) {
        if (BIO_should_retry(bio)) {
            return receiveData(bio, buffer, received);
        }
        if (n == 0) {  // TODO: Is this reasonable?
            return false;
        }
        throw OpenSslError{"error receiving response"};
    }
    received += n;
    return true;
}

int main()
try {
    BIO *bio = BIO_new_connect("httpbin.org:80");
    if (bio == nullptr) {
        throw OpenSslError{"error BIO_new_connect"};
    }
    SCOPE_EXIT([&]{ BIO_free_all(bio); });

    if (BIO_do_connect(bio) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }

    std::string const message{"GET /get HTTP/1.0\r\n\r\n"};

    size_t sent = 0;
    while (sent < message.size()) {
        int const n = BIO_write(bio, message.data() + sent, message.size() - sent);
        if (n < 1) {
            throw OpenSslError{"error sending request"};
        }
        sent += n;
    }

    // TODO: make a dedicated buffer class
    std::vector<char> buffer;
    size_t received = 0;

    // TODO: check content-length
    while (receiveData(bio, buffer, received)) {
    }
    buffer.resize(received);

    std::string const response{std::begin(buffer), std::end(buffer)};
    std::printf("%s\n", response.c_str());
}
catch (std::exception const& e) {
    std::fprintf(stderr, "Exception: %s\n", e.what());
    return EXIT_FAILURE;
}
