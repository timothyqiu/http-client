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

#include <CLI/CLI.hpp>
#include <OpenSSL/bio.h>
#include <OpenSSL/ssl.h>

#include <ohc/exception.hpp>
#include <ohc/url.hpp>

#include "scope_guard.hpp"

enum class HttpVersion { VERSION_1_0, VERSION_1_1 };

struct Request {
    Url url;
    std::string method;
    std::string http_proxy_host;
    std::string http_proxy_port;

    std::string const& connectHost() const { return shouldUseHttpProxy() ? http_proxy_host : url.host; }
    std::string const& connectPort() const { return shouldUseHttpProxy() ? http_proxy_port : url.port; }

    bool shouldUseHttpProxy() const {
        return url.scheme == "http" && !http_proxy_host.empty() && !http_proxy_port.empty();
    }
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

    std::regex const headerPattern{R"regex(\s*([^:]*)\s*:\s*(.*)\s*)regex"};

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

static std::string makeRequestMessage(Request const& req, HttpVersion httpVersion)
{
    auto const requestUri = req.shouldUseHttpProxy() ? absoluteUrlString(req.url) : relativeUrlString(req.url);

    std::string versionMark;
    std::string header;

    switch (httpVersion) {
    case HttpVersion::VERSION_1_0:
        versionMark = "HTTP/1.0";
        break;

    case HttpVersion::VERSION_1_1:
        versionMark = "HTTP/1.1";
        header = "Host: " + req.url.host + "\r\n";
        break;
    }

    return req.method + " " + requestUri + " " + versionMark +"\r\n" + header + "\r\n";
}

static Response do_request(BIO *bio, Request const& req, HttpVersion httpVersion)
{
    auto const message = makeRequestMessage(req, httpVersion);
    std::printf("Message:\n%s<End of Message>\n", message.c_str());

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
    if (BIO_set_conn_hostname(bio, req.connectHost().c_str()) < 1) {
        throw OpenSslError{"error BIO_set_conn_hostname"};
    }
    BIO_set_conn_port(bio, req.connectPort().c_str());

    if (BIO_do_connect(bio) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }
}

static Response request(std::string_view method, std::string_view url_string,
                        std::string_view http_proxy={}, HttpVersion httpVersion=HttpVersion::VERSION_1_0)
{
    Url const url = parseUrl(url_string, "http");

    Request req;
    req.url = url;
    req.method = method;

    if (!http_proxy.empty()) {
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

    // TODO: would be better to use one do_request for http/https
    // this is now an early return basically due to SCOPE_EXIT of ctx
    if (req.url.scheme == "http") {
        return do_request(bio, req, httpVersion);
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        throw OpenSslError{"error SSL_CTX_new"};
    }
    SCOPE_EXIT([&]{ SSL_CTX_free(ctx); });

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) < 1) {
        throw OpenSslError{"error SSL_CTX_set_min_proto_version"};
    }

    BIO *ssl = BIO_new_ssl(ctx, /*client*/1);
    if (ssl == nullptr) {
        throw OpenSslError{"error BIO_new_ssl"};
    }

    // FIXME: this works, but ugly and error-prone
    // (bio) is now (ssl -> bio)
    bio = BIO_push(ssl, bio);

    // this step will be done at I/O if omitted
    if (BIO_do_handshake(bio) < 1) {
        throw OpenSslError{"error BIO_do_handshake"};
    }

    // TODO: verification

    return do_request(bio, req, httpVersion);
}

int main(int argc, char *argv[])
try {
    CLI::App app{"HTTP Client via OpenSSL"};

    HttpVersion version{HttpVersion::VERSION_1_0};
    std::map<std::string, HttpVersion> const versionMap{
        {"1.0", HttpVersion::VERSION_1_0},
        {"1.1", HttpVersion::VERSION_1_1},
    };
    app.add_option("--http-version", version, "HTTP version")
        ->transform(CLI::CheckedTransformer(versionMap, CLI::ignore_case));

    std::string url{"http://httpbin.org/get?a=b#token"};
    app.add_option("url", url, "Target URL");

    std::string http_proxy;
    app.add_option("--http-proxy", http_proxy, "HTTP proxy server")->envname("http_proxy");

    CLI11_PARSE(app, argc, argv);

    // TODO: make a Session object
    auto const resp = request("GET", url, http_proxy, version);

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
