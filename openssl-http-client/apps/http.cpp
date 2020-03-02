#include "http.hpp"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <spdlog/spdlog.h>

#include "openssl.hpp"

struct HttpClient::Impl {
    HttpVersion version_;
    ProxyRegistry proxyRegistry_;
    bool insecure_;
    bool proxyInsecure_;

    BIO *bio_;
    SSL_CTX *ssl_ctx_;

    // scheme + host + port
    // currently, proxied http connection don't need this
    Url serverIdentity_;

    Impl(HttpVersion version, ProxyRegistry const& proxy, bool insecure, bool proxyInsecure)
        : version_{version}, proxyRegistry_{proxy}
        , insecure_{insecure}, proxyInsecure_{proxyInsecure}
        , bio_{nullptr}, ssl_ctx_{nullptr}
    {
    }

    auto get(Url const& req) -> Response;

    auto request(Request const& req) -> Response;
    void createConnection(Request const& req);
    void closeConnection();
    bool shouldChangeConnection(Request const& req) const;
    auto getSslContext() -> SSL_CTX *;
    void performHttpsPrologue(std::string const& hostname, bool verify);
};

HttpClient::HttpClient(HttpVersion version, ProxyRegistry const& proxy, bool insecure, bool proxyInsecure)
    : impl_{std::make_unique<Impl>(version, proxy, insecure, proxyInsecure)}
{
}

HttpClient::~HttpClient()
{
    impl_->closeConnection();
}

Response HttpClient::get(Url const& url)
{
    return impl_->get(url);
}

Response HttpClient::Impl::get(Url const& url)
{
    Request req;
    req.version = version_;
    req.method("GET");
    req.url = url;
    req.proxy = proxyRegistry_.get(url.scheme);

    return this->request(req);
}

auto HttpClient::Impl::request(Request const& req) -> Response
{
    if (bio_ != nullptr && this->shouldChangeConnection(req)) {
        this->closeConnection();
    }

    Response resp;

    try {
        if (bio_ == nullptr) {
            this->createConnection(req);
        }
        resp = makeRequest(bio_, req);
    }
    catch (std::exception const&) {
        // won't be able to consume the response
        this->closeConnection();
        throw;
    }

    switch (version_) {
    case HttpVersion::VERSION_1_0:
        this->closeConnection();
        break;

    case HttpVersion::VERSION_1_1:
        if (auto const iter = resp.headers.find("connection"); iter != std::end(resp.headers)) {
            if (iter->second == "close") {
                this->closeConnection();
            }
        }
        break;
    }

    return resp;
}

void HttpClient::Impl::closeConnection()
{
    serverIdentity_ = Url{};

    if (ssl_ctx_ != nullptr) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    if (bio_ != nullptr) {
        BIO_free_all(bio_);
        bio_ = nullptr;
    }
}

bool HttpClient::Impl::shouldChangeConnection(Request const& req) const
{
    // connection should be closed after each request/response, not before
    assert(version_ != HttpVersion::VERSION_1_0);

    // change of scheme
    if (serverIdentity_.scheme != req.url.scheme) {
        return true;
    }

    // once connected to a http proxy, always there
    if (req.url.scheme == "http" && req.proxy) {
        return false;
    }

    return serverIdentity_.authority() != req.url.authority();
}

SSL_CTX *HttpClient::Impl::getSslContext()
{
    if (ssl_ctx_ == nullptr) {
        ssl_ctx_ = makeSslCtx().release();
    }
    return ssl_ctx_;
}

void HttpClient::Impl::createConnection(Request const& req)
{
    Url const authority = req.proxy ? *req.proxy : req.url;
    spdlog::info("Connecting to {}:{}", authority.host, authority.port);

    assert(bio_ == nullptr);
    bio_ = makeBio(authority.host, authority.port).release();

    if (req.proxy && req.proxy->scheme == "https") {
        this->performHttpsPrologue(req.proxy->host, !proxyInsecure_);
    }

    if (req.url.scheme == "https") {
        if (req.proxy) {
            // HTTPS proxy CONNECT only available in 1.1
            Request proxyReq;
            proxyReq.version = HttpVersion::VERSION_1_1;
            proxyReq.method("CONNECT");
            proxyReq.url = *req.proxy;
            proxyReq.connectAuthority = req.url;

            auto const& resp = makeRequest(bio_, proxyReq);

            if (!resp.isSuccess()) {
                // TODO: make a dedicated exception?
                spdlog::error("Proxy server returned {} for CONNECT", resp.statusCode);
                throw std::runtime_error{"proxy server refused"};
            }
        }
        this->performHttpsPrologue(req.url.host, !insecure_);
    }

    serverIdentity_ = req.url;
}

void HttpClient::Impl::performHttpsPrologue(std::string const& hostname, bool verify)
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

    if (verify) {
        verifyCertificate(ssl, hostname);
    }
}
