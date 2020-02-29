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

#include <CLI/CLI.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include <ohc/bio.hpp>
#include <ohc/exception.hpp>
#include <ohc/http.hpp>
#include <ohc/url.hpp>

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");

static std::string toLower(std::string_view view)
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::tolower(c); });
    return result;
}

static Response makeRequest(BIO *bio, Request const& req)
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

            return makeRequest(bio_, req);
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

            auto const& resp = makeRequest(bio_, proxyReq);

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
