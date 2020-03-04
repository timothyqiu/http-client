#include "session.hpp"

#include <ohc/http.hpp>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include "buffer.hpp"
#include "exceptions.hpp"

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");

bool OpenSslSession::s_registered = SessionFactory::registerCreator("openssl", OpenSslSession::create);

std::unique_ptr<Session> OpenSslSession::create(HttpVersion version, ProxyRegistry const& proxyRegistry)
{
    return std::make_unique<OpenSslSession>(version, proxyRegistry);
}

OpenSslSession::OpenSslSession(HttpVersion version, ProxyRegistry const& proxyRegistry)
    : Session{version, proxyRegistry}
{
}

auto OpenSslSession::getSslContext() -> SSL_CTX *
{
    if (!sslCtx_) {
        sslCtx_ = SslCtxPtr{SSL_CTX_new(TLS_client_method())};
        if (!sslCtx_) {
            throw OpenSslError{"error SSL_CTX_new"};
        }

        if (SSL_CTX_set_min_proto_version(sslCtx_.get(), TLS1_2_VERSION) < 1) {
            throw OpenSslError{"error SSL_CTX_set_min_proto_version"};
        }
        if (SSL_CTX_set_default_verify_paths(sslCtx_.get()) < 1) {
            throw OpenSslError{"error SSL_CTX_set_default_verify_paths"};
        }
    }
    return sslCtx_.get();
}

void OpenSslSession::performHttpsPrologue(std::string const& hostname, bool verify)
{
    BIO *ssl_bio = BIO_new_ssl(this->getSslContext(), /*client*/1);
    if (ssl_bio == nullptr) {
        throw OpenSslError{"error BIO_new_ssl"};
    }

    // (bio) is now (ssl_bio -> bio)
    bio_.reset(BIO_push(ssl_bio, bio_.release()));

    SSL *ssl = nullptr;
    if (BIO_get_ssl(ssl_bio, &ssl) < 1) {
        throw OpenSslError{"error BIO_get_ssl"};
    }
    assert(ssl != nullptr);

    // SNI
    if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) < 1) {
        throw OpenSslError{"error SSL_set_tlsext_host_name"};
    }

    // this step will be done at I/O if omitted
    if (BIO_do_handshake(bio_.get()) < 1) {
        throw OpenSslError{"error BIO_do_handshake"};
    }

    if (verify) {
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

bool OpenSslSession::isConnected() const
{
    return bool{bio_};
}

void OpenSslSession::createConnection(std::string const& host, std::string const& port)
{
    bio_ = BioPtr{BIO_new(BIO_s_connect())};
    if (!bio_) {
        throw OpenSslError{"error BIO_new"};
    }

    if (BIO_set_conn_hostname(bio_.get(), host.c_str()) < 1) {
        throw OpenSslError{"error BIO_set_conn_hostname"};
    }
    BIO_set_conn_port(bio_.get(), port.c_str());

    if (BIO_do_connect(bio_.get()) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }
}

void OpenSslSession::closeConnection()
{
    bio_.reset();
}

auto OpenSslSession::createBuffer() -> std::unique_ptr<Buffer>
{
    return std::make_unique<BioBuffer>(bio_.get());
}
