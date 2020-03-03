#include "session.hpp"

#include <ohc/http.hpp>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include "buffer.hpp"
#include "exceptions.hpp"

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");

OpenSslSession::OpenSslSession(HttpVersion version, ProxyRegistry const& proxyRegistry,
                               bool insecure, bool proxyInsecure)
    : Session{version, proxyRegistry, insecure, proxyInsecure}
    , bio_{nullptr}, ssl_ctx_{nullptr}
{
}

OpenSslSession::~OpenSslSession()
{
    this->closeConnection();
}

auto OpenSslSession::getSslContext() -> SSL_CTX *
{
    if (ssl_ctx_ == nullptr) {
        // FIXME: this currently relies on that once an exception is thrown,
        // closeConnection will be called to clear ssl_ctx_
        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx_) {
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

void OpenSslSession::performHttpsPrologue(std::string const& hostname, bool verify)
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

void OpenSslSession::verifyCertificate(SSL *ssl, std::string const& hostname)
{
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

bool OpenSslSession::canReuseCurrentConnection(Request const& req)
{
    // no current connection
    if (bio_ == nullptr) {
        return false;
    }

    // connection should be closed after each request/response, not before
    if (this->version() == HttpVersion::VERSION_1_0) {
        spdlog::warn("connection not closed after a http 1.0 request");
        return false;
    }

    // change of scheme
    if (serverIdentity_.scheme != req.url.scheme) {
        return false;
    }

    // once connected to a http proxy, always there
    if (req.url.scheme == "http" && req.proxy) {
        return true;
    }

    return serverIdentity_.authority() == req.url.authority();
}

void OpenSslSession::setupConnection(Request const& req)
{
    if (this->canReuseCurrentConnection(req)) {
        return;
    }

    Url const authority = req.proxy ? *req.proxy : req.url;
    spdlog::info("Connecting to {}:{}", authority.host, authority.port);

    bio_ = BIO_new(BIO_s_connect());
    if (!bio_) {
        throw OpenSslError{"error BIO_new"};
    }

    if (BIO_set_conn_hostname(bio_, authority.host.c_str()) < 1) {
        throw OpenSslError{"error BIO_set_conn_hostname"};
    }
    BIO_set_conn_port(bio_, authority.port.c_str());

    if (BIO_do_connect(bio_) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }

    if (req.proxy && req.proxy->scheme == "https") {
        this->performHttpsPrologue(req.proxy->host, !this->proxyInsecure());
    }

    if (req.url.scheme == "https") {
        if (req.proxy) {
            // HTTPS proxy CONNECT only available in 1.1
            Request proxyReq;
            proxyReq.version = HttpVersion::VERSION_1_1;
            proxyReq.method("CONNECT");
            proxyReq.url = *req.proxy;
            proxyReq.connectAuthority = req.url;

            auto const& resp = this->makeRequest(proxyReq);

            if (!resp.isSuccess()) {
                // TODO: make a dedicated exception?
                spdlog::error("Proxy server returned {} for CONNECT", resp.statusCode);
                throw std::runtime_error{"proxy server refused"};
            }
        }
        this->performHttpsPrologue(req.url.host, !this->insecure());
    }

    serverIdentity_ = req.url;
}

void OpenSslSession::closeConnection()
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

auto OpenSslSession::makeRequest(Request const& req) -> Response
{
    BioBuffer buffer{bio_};

    auto const& message = req.makeMessage();
    spdlog::debug("Sending request:\n{}<EOM>", message);

    buffer.write(message.data(), message.size());

    return readResponseFromBuffer(req, buffer);
}
