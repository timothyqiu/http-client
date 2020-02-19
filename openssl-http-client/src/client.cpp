#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <OpenSSL/bio.h>
#include <OpenSSL/err.h>

#include "scope_guard.hpp"

int main()
{
    BIO *bio = BIO_new_connect("httpbin.org:80");
    if (bio == nullptr) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    SCOPE_EXIT([&]{ BIO_free_all(bio); });

    if (BIO_do_connect(bio) < 1) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    std::string const message{"GET /get HTTP/1.0\r\n\r\n"};

    size_t sent = 0;
    while (sent < message.size()) {
        int const n = BIO_write(bio, message.data() + sent, message.size() - sent);
        if (n < 1) {
            std::fprintf(stderr, "Error sending request\n");
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
        sent += n;
    }

    size_t const initialBufferSize = 128;
    std::vector<char> buffer(initialBufferSize);
    size_t received = 0;
    while (true) {
        int const n = BIO_read(bio, buffer.data() + received, buffer.size() - received);
        if (n < 1) {
            if (BIO_should_retry(bio)) {
                continue;
            }
            if (n == 0) {
                break;
            }
            std::fprintf(stderr, "Error receiving response\n");
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
        received += n;

        if (buffer.size() - received == 0) {
            buffer.resize(buffer.size() * 2);
        }
    }

    std::string const response{std::begin(buffer), std::end(buffer)};
    std::printf("%zu: %s\n", received, response.c_str());
}
