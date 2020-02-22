#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <regex>
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

static int extractStatus(std::vector<char> const& buffer, size_t received)
{
    std::string_view view{buffer.data(), received};

    auto const n = view.find("\r\n");
    assert(n != view.npos);  // use this after receiving the status line

    std::string_view statusLine{buffer.data(), n};
    std::regex const pattern{R"regex(HTTP/\d+\.\d+\s+(\d\d\d)\s+.*)regex"};

    std::match_results<std::string_view::const_iterator> match;  // regex lack of string view support
    if (!std::regex_match(std::begin(statusLine), std::end(statusLine),
                          match, pattern))
    {
        // TODO: make a dedicated exception, store instead of print
        std::string const str{statusLine};  // %*s won't work, maybe bug in stdlib impl
        std::fprintf(stderr, "%s\n", str.c_str());
        throw std::runtime_error{"Bad status line"};
    }

    return std::stoi(match.str(1));
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

    int const statusCode = extractStatus(buffer, received);
    std::printf("Status Code: %d\n", statusCode);

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
