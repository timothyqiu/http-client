#include "openssl.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <spdlog/spdlog.h>

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");

OpenSslError::OpenSslError(char const *message)
    : std::runtime_error{message}
{
    // TODO: store instead of print
    ERR_print_errors_fp(stderr);
}

BioBuffer::BioBuffer(BIO *bio)
    : bio_{bio}
{
    assert(bio_ != nullptr);
}

void BioBuffer::fetch()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = BIO_read(bio_, buffer, bufferSize);
    if (n < 1) {
        if (BIO_should_retry(bio_)) {
            this->fetch();
            return;
        }
        if (n == 0) {
            throw std::runtime_error{"end of stream reached"};
        }
        throw OpenSslError{"error reading data"};
    }
    this->markWritten(n);
}

static std::string toLower(std::string_view view)
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::tolower(c); });
    return result;
}

static void writeString(BIO *bio, std::string_view data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        int const n = BIO_write(bio, data.data() + sent, data.size() - sent);
        if (n < 1) {
            throw OpenSslError{"error writing data"};
        }
        sent += n;
    }
}

Response makeRequest(BIO *bio, Request const& req)
{
    auto const& message = req.makeMessage();
    spdlog::debug("Sending request:\n{}<EOM>", message);

    writeString(bio, message);

    Response resp;

    BioBuffer buffer{bio};

    // regex lack of string view support
    using string_view_match_result = std::match_results<std::string_view::const_iterator>;

    // first line should be status line, since http 1.0
    {
        auto const line = buffer.readLine();

        std::regex const pattern{R"regex(HTTP/\d+\.\d+\s+(\d\d\d)\s+.*)regex"};
        string_view_match_result match;
        if (!std::regex_match(std::begin(line), std::end(line),
                              match, pattern))
        {
            // TODO: make a dedicated exception, store instead of print
            spdlog::error("Bad status line: {}", line);
            throw std::runtime_error{"bad status line"};
        }
        resp.statusCode = std::stoi(match.str(1));
        spdlog::debug("Status code received: {}", resp.statusCode);
    }

    std::regex const headerPattern{R"regex(\s*([^:]*)\s*:\s*(.*)\s*)regex"};
    while (true) {
        auto const line = buffer.readLine();

        if (line.empty()) {
            break;
        }

        string_view_match_result match;
        if (!std::regex_match(std::begin(line), std::end(line),
                              match, headerPattern))
        {
            // TODO: make a dedicated exception, store instead of print
            spdlog::warn("Bad header line: {}", line);
            continue;
        }

        std::string name = toLower(match.str(1));

        // FIXME: should handle duplicated headers
        resp.headers[name] = match.str(2);
    }

    if (auto const iter = resp.headers.find("transfer-encoding"); iter != std::end(resp.headers)) {
        // FIXME: should allow multiple transfer-encoding headers
        resp.transferEncoding = toLower(iter->second);
    } else {
        resp.transferEncoding = "identity";
    }

    auto const emptyBody = (resp.statusCode / 100 == 1 || resp.statusCode == 204 || resp.statusCode == 304 || req.method == "HEAD");
    if (!emptyBody) {

        if (resp.transferEncoding == "identity") {

            size_t bodySize;
            if (auto const iter = resp.headers.find("content-length"); iter != std::end(resp.headers)) {
                bodySize = std::stoul(iter->second);
            } else {
                // should an empty value land here too?
                bodySize = 0;
            }
            resp.body = buffer.readAsVector(bodySize);

        } else if (resp.transferEncoding == "chunked") {

            std::regex const chunkHeaderPattern{R"regex(\s*([a-fA-F0-9]+)\s*(;.*)?)regex"};
            string_view_match_result match;

            while (true) {
                auto const line = buffer.readLine();

                if (!std::regex_match(std::begin(line), std::end(line),
                                      match, chunkHeaderPattern))
                {
                    // TODO: make a dedicated exception, store instead of print
                    spdlog::error("Bad chunk header: {}", line);
                    throw std::runtime_error{"bad chunk header"};
                }

                size_t const chunkSize = std::stoul(match.str(1), nullptr, 16);
                spdlog::debug("Chunk size: {}", chunkSize);

                if (chunkSize == 0) {
                    break;
                }

                auto const& chunk = buffer.readAsVector(chunkSize);

                resp.body.insert(std::end(resp.body),
                                 std::begin(chunk), std::end(chunk));

                buffer.dropLiteral("\r\n");
            }

            // TODO: make use of trailing headers
            while (true) {
                auto const line = buffer.readLine();

                if (line.empty()) {
                    break;
                }
                spdlog::debug("Trailing header: {}", line);
            }

        } else {
            throw std::runtime_error{"unsupported transfer encoding: " + resp.transferEncoding};
        }
    }

    return resp;
}
