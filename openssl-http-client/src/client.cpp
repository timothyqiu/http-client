#include <algorithm>
#include <cassert>
#include <cctype>
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

struct Response {
    std::vector<char> raw;
    int statusCode;
    std::map<std::string, std::string> headers;
    size_t beginOfBody;
    size_t contentLength;
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

static void parseMeta(std::vector<char> const& buffer, size_t beginOfBody, Response& resp)
{
    std::string_view view{buffer.data(), beginOfBody};

    auto const endOfStatus = view.find("\r\n");
    assert(endOfStatus != view.npos);  // use this after receiving the status line

    std::string_view statusLine{buffer.data(), endOfStatus};
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

    resp.statusCode = std::stoi(match.str(1));

    size_t const sepSize = 2;

    auto const beginOfHeaders = endOfStatus + sepSize;
    auto const endOfHeaders = beginOfBody - sepSize;  // so that every line is a valid header
    std::string_view headerBlock{buffer.data() + beginOfHeaders, endOfHeaders - beginOfHeaders};

    resp.headers.clear();

    std::regex const headerPattern{R"regex(\s*(.*)\s*:\s*(.*)\s*)regex"};

    size_t beginOfNextHeader = 0;
    size_t n = headerBlock.find("\r\n", beginOfNextHeader);
    while (n != headerBlock.npos) {
        std::string_view line{buffer.data() + beginOfHeaders + beginOfNextHeader, n - beginOfNextHeader};

        std::match_results<std::string_view::const_iterator> match;
        if (!std::regex_match(std::begin(line), std::end(line),
                              match, headerPattern))
        {
            std::string const str{line};  // %*s won't work, maybe bug in stdlib impl
            std::fprintf(stderr, "Bad header line: %s\n", str.c_str());
            continue;
        }

        std::string name = match.str(1);
        std::transform(std::begin(name), std::end(name),
                       std::begin(name),
                       [](char c) { return std::tolower(c); });

        resp.headers[name] = match.str(2);

        beginOfNextHeader = n + sepSize;
        n = headerBlock.find("\r\n", beginOfNextHeader);
    }

    auto iter = resp.headers.find("content-length");
    if (iter == std::end(resp.headers)) {  // should an empty value land here too?
        resp.contentLength = 0;
    } else {
        resp.contentLength = std::stoul(iter->second);
    }
}

static Response do_request(BIO *bio, std::string const& message)
{
    size_t sent = 0;
    while (sent < message.size()) {
        int const n = BIO_write(bio, message.data() + sent, message.size() - sent);
        if (n < 1) {
            throw OpenSslError{"error sending request"};
        }
        sent += n;
    }

    Response resp;

    std::vector<char>& buffer = resp.raw;
    size_t received = 0;

    resp.beginOfBody = 0;
    while (receiveData(bio, buffer, received)) {
        std::string_view view{buffer.data(), received};

        auto const n = view.find("\r\n\r\n");
        if (n != view.npos) {
            resp.beginOfBody = n + 4;
            break;
        }
    }

    if (resp.beginOfBody == 0) {
        throw std::runtime_error{"unexpected end of response"};
    }

    parseMeta(buffer, resp.beginOfBody, resp);

    if (400 <= resp.statusCode && resp.statusCode <= 599) {
        // TODO: better error handling
        std::fprintf(stderr, "Response: %d\n", resp.statusCode);
        throw std::runtime_error{"http error"};
    }

    // TODO: check for HEAD method before using content-length
    while (received < (resp.beginOfBody + resp.contentLength) && receiveData(bio, buffer, received)) {
    }

    if (received < (resp.beginOfBody + resp.contentLength)) {
        throw std::runtime_error{"unexpceted end of body"};
    }

    return resp;
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

    std::string const request{"GET /get HTTP/1.0\r\n\r\n"};
    auto const resp = do_request(bio, request);

    std::string body{resp.raw.data() + resp.beginOfBody, resp.contentLength};
    std::printf("Body:\n%s<End of Body>\n", body.c_str());
}
catch (std::exception const& e) {
    std::fprintf(stderr, "Exception: %s\n", e.what());
    return EXIT_FAILURE;
}
