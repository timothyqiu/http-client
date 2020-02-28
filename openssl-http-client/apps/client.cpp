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
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include <ohc/exception.hpp>
#include <ohc/http.hpp>
#include <ohc/url.hpp>

#include "scope_guard.hpp"

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");


// TODO: get rid of the ugly bool
static bool receiveData(BIO *bio, std::vector<char>& buffer, size_t& received)
{
    size_t const minimumAvailable = 128;
    if (buffer.size() < received + minimumAvailable) {
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
        spdlog::error("Bad status line: {}", statusLine);
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
            spdlog::warn("Bad header line: {}", line);
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

    if (auto const iter = resp.headers.find("transfer-encoding"); iter != std::end(resp.headers)) {
        // FIXME: should allow multiple transfer-encoding headers
        std::string transferEncoding{iter->second};
        std::transform(std::begin(transferEncoding), std::end(transferEncoding),
                       std::begin(transferEncoding),
                       [](char c) { return std::tolower(c); });
        resp.transferEncoding = transferEncoding;
    } else {
        resp.transferEncoding = "identity";
    }
}

static Response do_request(BIO *bio, Request const& req)
{
    auto const& message = req.makeMessage();
    spdlog::debug("Sending request:\n{}<EOM>", message);

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
        spdlog::error("Unexpected end of response: %s", std::string{std::begin(buffer), std::begin(buffer) + received});
        throw std::runtime_error{"unexpected end of response"};
    }

    parseMeta(buffer, resp.beginOfBody, resp);
    spdlog::debug("Response received: {}", resp.statusCode);

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

            while (received < (resp.beginOfBody + bodySize) && receiveData(bio, buffer, received)) {
            }
            if (received < (resp.beginOfBody + bodySize)) {
                spdlog::error("Expected body size to be {}, actual {}", bodySize, received - resp.beginOfBody);
                throw std::runtime_error{"unexpceted end of body"};
            }

            resp.body.assign(buffer.data() + resp.beginOfBody, buffer.data() + resp.beginOfBody + bodySize);

        } else if (resp.transferEncoding == "chunked") {

            std::regex const chunkHeaderPattern{R"regex(\s*([a-fA-F0-9]+)\s*(;.*)?)regex"};
            std::match_results<std::string_view::const_iterator> match;  // regex lack of string view support

            auto beginOfChunk = resp.beginOfBody;
            size_t endOfAllChunks = 0;
            while (true) {
                std::string_view view{buffer.data() + beginOfChunk, received - beginOfChunk};
                auto const n = view.find("\r\n");
                if (n == view.npos) {
                    if (!receiveData(bio, buffer, received)) {
                        break;
                    }
                    continue;
                }

                std::string_view header{view.data(), n};
                if (!std::regex_match(std::begin(header), std::end(header),
                                      match, chunkHeaderPattern))
                {
                    // TODO: make a dedicated exception, store instead of print
                    spdlog::error("Bad chunk header: {}", header);
                    throw std::runtime_error{"bad chunk header"};
                }

                size_t const chunkSize = std::stoul(match.str(1), nullptr, 16);
                spdlog::debug("Chunk size: {} / {}", chunkSize, header);

                if (chunkSize == 0) {
                    endOfAllChunks = beginOfChunk + n + 2;
                    break;
                }

                auto const chunkTotalSize = n + 2 + chunkSize + 2;
                if (beginOfChunk + chunkTotalSize > received) {
                    if (!receiveData(bio, buffer, received)) {
                        break;
                    }
                    continue;
                }

                resp.body.insert(std::end(resp.body),
                                 buffer.data() + beginOfChunk + n + 2,
                                 buffer.data() + beginOfChunk + n + 2 + chunkSize);

                beginOfChunk += chunkTotalSize;
            }

            if (endOfAllChunks == 0) {
                throw std::runtime_error{"unexpected end of chunks"};
            }

            // TODO: make use of trailing headers
            size_t beginOfCurrentHeader = 0;
            while (true) {
                auto const offset = endOfAllChunks + beginOfCurrentHeader;
                std::string_view headerBlock{buffer.data() + offset, received - offset};
                auto const n = headerBlock.find("\r\n");
                if (n == headerBlock.npos) {
                    if (!receiveData(bio, buffer, received)) {
                        throw std::runtime_error{"unexpected end of response"};
                    }
                    continue;
                }
                if (n == 0) {
                    break;
                }
                spdlog::debug("Trailing header: {}", std::string_view{headerBlock.data(), n});
                beginOfCurrentHeader += (n + 2);
            }

        } else {
            throw std::runtime_error{"unsupported transfer encoding: " + resp.transferEncoding};
        }
    }

    return resp;
}

class HttpClient {
public:
    HttpClient(HttpVersion version, Proxy const& proxy, bool noVerify)
        : version_{version}, proxy_{proxy}, noVerify_{noVerify}
        , bio_{nullptr}, ssl_ctx_{nullptr}
    {
    }

    ~HttpClient()
    {
        this->clear();
    }

    HttpClient(HttpClient const&) = delete;
    HttpClient& operator=(HttpClient const&) = delete;

    Response request(std::string_view method, std::string_view urlString)
    {
        Url const url = parseUrl(urlString, "http");

        // TODO: move to the end of current request?
        switch (version_) {
        case HttpVersion::VERSION_1_0:
            this->clear();
            break;

        case HttpVersion::VERSION_1_1:
            if (lastUrl_.scheme != url.scheme) {
                this->clear();
            } else if (lastUrl_.authority() != url.authority()) {
                // TODO: maybe as long as it's the same server, authority don't have to be the same?

                if (url.scheme != "http" || !proxy_.get(url.scheme)) {
                    this->clear();
                }
            }
            break;
        }

        Request req;
        req.version = version_;
        req.url = url;
        req.method = method;
        req.proxy = proxy_.get(url.scheme);

        try {
            if (bio_ == nullptr) {
                bio_ = BIO_new(BIO_s_connect());
                if (bio_ == nullptr) {
                    throw OpenSslError{"error BIO_new"};
                }
                this->connectBio(req);
                lastUrl_ = url;
            }

            return do_request(bio_, req);
        }
        catch (std::exception const&) {
            // won't be able to consume the response
            this->clear();
            throw;
        }
    }

private:
    HttpVersion version_;
    Proxy proxy_;
    bool noVerify_;

    BIO *bio_;
    SSL_CTX *ssl_ctx_;

    Url lastUrl_;

    void clear()
    {
        lastUrl_ = Url{};

        if (ssl_ctx_ != nullptr) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
        if (bio_ != nullptr) {
            BIO_free_all(bio_);
            bio_ = nullptr;
        }
    }

    void connectBio(Request const& req)
    {
        Url const targetUrl = req.proxy ? *req.proxy : req.url;

        spdlog::info("Connecting to {}:{}", targetUrl.host, targetUrl.port);

        if (BIO_set_conn_hostname(bio_, targetUrl.host.c_str()) < 1) {
            throw OpenSslError{"error BIO_set_conn_hostname"};
        }
        BIO_set_conn_port(bio_, targetUrl.port.c_str());

        if (BIO_do_connect(bio_) < 1) {
            throw OpenSslError{"error BIO_do_connect"};
        }

        if (req.url.scheme == "https") {
            this->connectHttps(req);
        }
    }

    void connectHttps(Request const& req)
    {
        if (req.proxy) {
            // HTTPS proxy CONNECT only available in 1.1
            Request proxyReq;
            proxyReq.version = HttpVersion::VERSION_1_1;
            proxyReq.method = "CONNECT";
            proxyReq.url = *req.proxy;
            proxyReq.connectAuthority = req.url;

            auto const& resp = do_request(bio_, proxyReq);

            if (!resp.isSuccess()) {
                // TODO: make a dedicated exception?
                spdlog::error("Proxy server returned {} for CONNECT", resp.statusCode);
                throw std::runtime_error{"proxy server refused"};
            }
        }

        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx_ == nullptr) {
            throw OpenSslError{"error SSL_CTX_new"};
        }

        if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION) < 1) {
            throw OpenSslError{"error SSL_CTX_set_min_proto_version"};
        }
        if (SSL_CTX_set_default_verify_paths(ssl_ctx_) < 1) {
            throw OpenSslError{"error SSL_CTX_set_default_verify_paths"};
        }

        BIO *ssl_bio = BIO_new_ssl(ssl_ctx_, /*client*/1);
        if (ssl_bio == nullptr) {
            throw OpenSslError{"error BIO_new_ssl"};
        }

        // FIXME: this works, but ugly and error-prone
        // (bio) is now (ssl_bio -> bio)
        bio_ = BIO_push(ssl_bio, bio_);

        SSL *ssl;
        if (BIO_get_ssl(ssl_bio, &ssl) < 1) {
            throw OpenSslError{"error BIO_get_ssl"};
        }

        // SNI
        if (SSL_set_tlsext_host_name(ssl, req.url.host.c_str()) < 1) {
            throw OpenSslError{"error SSL_set_tlsext_host_name"};
        }

        // this step will be done at I/O if omitted
        if (BIO_do_handshake(bio_) < 1) {
            throw OpenSslError{"error BIO_do_handshake"};
        }

        if (!noVerify_) {
            auto const error = SSL_get_verify_result(ssl);
            if (error != X509_V_OK) {
                throw std::runtime_error{X509_verify_cert_error_string(error)};
            }

            // SSL_get_verify_result returns OK when no cert is available
            auto *cert = SSL_get_peer_certificate(ssl);
            if (cert == nullptr) {
                throw std::runtime_error{"no certificate available"};
            }

            // vaild certificate, but site mismatch
            if (X509_check_host(cert, req.url.host.data(), req.url.host.size(), 0, nullptr) < 1) {
                throw std::runtime_error{"host mismatch"};
            }

            // TODO: revoked certificate
        }
    }

};

static void dumpResponse(Response const& resp)
{
    std::printf("Status: %d\n", resp.statusCode);
    std::printf("Headers:\n");
    for (auto const& e : resp.headers) {
        std::printf("\t%s = %s\n", e.first.c_str(), e.second.c_str());
    }
    std::printf("Body:\n%s", std::string{std::begin(resp.body), std::end(resp.body)}.c_str());
}

int main(int argc, char *argv[])
try {
    CLI::App app{"HTTP Client via OpenSSL"};

    std::string url;
    app.add_option("url", url, "Target URL")->required();

    HttpVersion version{HttpVersion::VERSION_1_1};
    std::map<std::string, HttpVersion> const versionMap{
        {"1.0", HttpVersion::VERSION_1_0},
        {"1.1", HttpVersion::VERSION_1_1},
    };
    app.add_option("--http-version", version, "HTTP version")
        ->transform(CLI::CheckedTransformer(versionMap, CLI::ignore_case));

    std::string httpProxy;
    app.add_option("--http-proxy", httpProxy, "The proxy server to use for HTTP")->envname("http_proxy");
    std::string httpsProxy;
    app.add_option("--https-proxy", httpsProxy, "The proxy server to use for HTTPS")->envname("https_proxy");

    bool noVerify{false};
    app.add_flag("--no-verify", noVerify, "Skip HTTPS certificate verification");

    bool isVerbose{false};
    app.add_flag("--verbose", isVerbose, "Make the operation more talkative");

    CLI11_PARSE(app, argc, argv);

    spdlog::set_level(isVerbose ? spdlog::level::debug : spdlog::level::warn);

    Proxy proxy;
    if (!httpProxy.empty()) {
        auto const& url = parseUrl(httpProxy, "http");
        if (url.scheme != "http") {
            throw std::runtime_error{"proxy server using non-http scheme not supported"};
        }
        proxy.set("http", url);
    }
    if (!httpsProxy.empty()) {
        auto const& url = parseUrl(httpsProxy, "http");
        if (url.scheme != "http") {
            throw std::runtime_error{"proxy server using non-http scheme not supported"};
        }
        proxy.set("https", url);
    }

    HttpClient client{version, proxy, noVerify};

    auto const resp = client.request("GET", url);
    dumpResponse(resp);
}
catch (std::exception const& e) {
    spdlog::error("Exception: {}", e.what());
    return EXIT_FAILURE;
}
