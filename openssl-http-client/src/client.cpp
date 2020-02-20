#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <OpenSSL/bio.h>

#include "exception.hpp"
#include "scope_guard.hpp"

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

    size_t beginOfBody = 0;
    while (receiveData(bio, buffer, received)) {
        std::string_view view{buffer.data(), received};

        auto const n = view.find("\r\n\r\n");
        if (n != view.npos) {
            beginOfBody = n + 4;
            break;
        }
    }

    if (beginOfBody == 0) {
        throw std::runtime_error{"unexpected end of response"};
    }

    // TODO: use content-length
    while (receiveData(bio, buffer, received)) {
    }

    // -2 to get rid of the null line between headers and body
    std::string const headBlock{buffer.data(), beginOfBody - 2};
    std::string const bodyBlock{buffer.data() + beginOfBody, received - beginOfBody};

    std::printf("Head:\n%s<End of Head>\n\nBody:\n%s<End of Body>\n",
                headBlock.data(), bodyBlock.data());
}
catch (std::exception const& e) {
    std::fprintf(stderr, "Exception: %s\n", e.what());
    return EXIT_FAILURE;
}
