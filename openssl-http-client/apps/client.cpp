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

#include <ohc/exception.hpp>
#include <ohc/url.hpp>

#include "scope_guard.hpp"

struct Request {
    std::string scheme;
    std::string host;
    std::string port;
    std::string method;
    std::string path;
    std::string http_proxy_host;
    std::string http_proxy_port;

    bool shouldUseHttpProxy() const { return !http_proxy_host.empty() && !http_proxy_port.empty(); }
};

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

static Response do_request(BIO *bio, Request const& req)
{
    auto const requestUri = req.shouldUseHttpProxy() ? req.scheme + "://" + req.host + ":" + req.port + req.path : req.path;
    auto const message = req.method + " " + requestUri + " HTTP/1.0\r\n\r\n";

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

        // a null line separates headers and body
        // although this approach is not friendly with Simple-Response
        // which body is the response
        auto const n = view.find("\r\n\r\n");
        if (n != view.npos) {
            resp.beginOfBody = n + 4;
            break;
        }
    }

    if (resp.beginOfBody == 0) {
        std::fprintf(stderr, "Raw response: %s\n", std::string{std::begin(buffer), std::begin(buffer) + received}.c_str());
        throw std::runtime_error{"unexpected end of response"};
    }

    parseMeta(buffer, resp.beginOfBody, resp);

    size_t const bodySize = req.method == "HEAD" ? 0 : resp.contentLength;
    while (received < (resp.beginOfBody + bodySize) && receiveData(bio, buffer, received)) {
    }
    if (received < (resp.beginOfBody + bodySize)) {
        std::fprintf(stderr, "Expected body size: %zu != %zu\n", bodySize, received - resp.beginOfBody);
        throw std::runtime_error{"unexpceted end of body"};
    }

    return resp;
}

static void connectBio(BIO *bio, Request const& req)
{
    auto const& host = req.shouldUseHttpProxy() ? req.http_proxy_host : req.host;
    auto const& port = req.shouldUseHttpProxy() ? req.http_proxy_port : req.port;

    if (BIO_set_conn_hostname(bio, host.c_str()) < 1) {
        throw OpenSslError{"error BIO_set_conn_hostname"};
    }
    BIO_set_conn_port(bio, port.c_str());

    if (BIO_do_connect(bio) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }
}

int main()
try {
    Url url = parseUrl("http://httpbin.org/get?a=b#token");

    Request req;
    req.scheme = url.scheme;
    req.host = url.host;
    req.port = url.port;
    req.method = "GET";
    req.path = relativeUrlString(url);

    char const *http_proxy = std::getenv("http_proxy");
    if (http_proxy) {
        Url proxyUrl = parseUrl(http_proxy);
        if (proxyUrl.port.empty()) {
            throw std::runtime_error{"proxy port missing"};
        }
        req.http_proxy_host = proxyUrl.host;
        req.http_proxy_port = proxyUrl.port;
    }

    BIO *bio = BIO_new(BIO_s_connect());
    if (bio == nullptr) {
        throw OpenSslError{"error BIO_new"};
    }
    SCOPE_EXIT([&]{ BIO_free_all(bio); });

    connectBio(bio, req);

    auto const resp = do_request(bio, req);

    std::printf("Status: %d\n", resp.statusCode);
    std::printf("Headers:\n");
    for (auto const& e : resp.headers) {
        std::printf("\t%s = %s\n", e.first.c_str(), e.second.c_str());
    }
    std::printf("Body:\n%s<End of Body>\n",
                std::string{resp.raw.data() + resp.beginOfBody, resp.contentLength}.c_str());
}
catch (std::exception const& e) {
    std::fprintf(stderr, "Exception: %s\n", e.what());
    return EXIT_FAILURE;
}
