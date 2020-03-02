#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <string_view>

#include <CLI/CLI.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include <ohc/http.hpp>
#include <ohc/url.hpp>

#include "openssl.hpp"

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

    Response request(std::string_view method, Url const& url)
    {
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

    SSL_CTX *getSslContext()
    {
        if (ssl_ctx_ == nullptr) {
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
        }
        return ssl_ctx_;
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

        if (req.proxy && req.proxy->scheme == "https") {
            this->makeHttpsPrologue(req.proxy->host);
        }

        if (req.url.scheme == "https") {
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
            this->makeHttpsPrologue(req.url.host);
        }
    }

    void makeHttpsPrologue(std::string const& hostname)
    {
        BIO *ssl_bio = BIO_new_ssl(this->getSslContext(), /*client*/1);
        if (ssl_bio == nullptr) {
            throw OpenSslError{"error BIO_new_ssl"};
        }

        SSL *ssl = nullptr;
        if (BIO_get_ssl(ssl_bio, &ssl) < 1) {
            throw OpenSslError{"error BIO_get_ssl"};
        }
        assert(ssl != nullptr);

        // SNI
        if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) < 1) {
            throw OpenSslError{"error SSL_set_tlsext_host_name"};
        }

        // FIXME: this works, but ugly and error-prone
        // (bio) is now (ssl_bio -> bio)
        bio_ = BIO_push(ssl_bio, bio_);

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
            if (X509_check_host(cert, hostname.data(), hostname.size(), 0, nullptr) < 1) {
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

    HttpVersion httpVersion{HttpVersion::VERSION_1_1};
    app.add_flag_callback("--http1.0", [&](){ httpVersion = HttpVersion::VERSION_1_0; }, "Uses HTTP 1.0");
    app.add_flag_callback("--http1.1", [&](){ httpVersion = HttpVersion::VERSION_1_1; }, "Uses HTTP 1.1");

    std::string httpProxy;
    app.add_option("--http-proxy", httpProxy, "The proxy server to use for HTTP")->envname("http_proxy");
    std::string httpsProxy;
    app.add_option("--https-proxy", httpsProxy, "The proxy server to use for HTTPS")->envname("https_proxy");

    bool noVerify{false};
    app.add_flag("--no-verify", noVerify, "Skip HTTPS certificate verification");

    bool isFollow{false};
    app.add_flag("-L,--location", isFollow, "Follow redirects");

    bool isVerbose{false};
    app.add_flag("--verbose", isVerbose, "Make the operation more talkative");

    CLI11_PARSE(app, argc, argv);

    spdlog::set_level(isVerbose ? spdlog::level::debug : spdlog::level::warn);

    Proxy proxy;
    if (!httpProxy.empty()) {
        auto const& url = parseUrl(httpProxy, "http");
        if (url.scheme != "http" && url.scheme != "https") {
            throw std::runtime_error{"proxy server scheme not supported"};
        }
        proxy.set("http", url);
    }
    if (!httpsProxy.empty()) {
        auto const& url = parseUrl(httpsProxy, "http");
        if (url.scheme != "http" && url.scheme != "https") {
            throw std::runtime_error{"proxy server scheme not supported"};
        }
        proxy.set("https", url);
    }

    HttpClient client{httpVersion, proxy, noVerify};

    Url requestUrl = parseUrl(url, "http");
    while (true) {
        auto const resp = client.request("GET", requestUrl);

        if (isFollow && (resp.statusCode == 301 || resp.statusCode == 302 || resp.statusCode == 303)) {
            // TODO: don't redirect if non-GET
            auto const location = resp.headers.at("location");
            spdlog::debug("Redirect to: {}", location);
            auto next = parseUrl(location);
            if (next.isRelative()) {
                next.scheme = requestUrl.scheme;
                next.userinfo = requestUrl.userinfo;
                next.host = requestUrl.host;
                next.port = requestUrl.port;
            }
            requestUrl = next;
            continue;
        }

        dumpResponse(resp);
        break;
    }
}
catch (std::exception const& e) {
    spdlog::error("Exception: {}", e.what());
    return EXIT_FAILURE;
}
