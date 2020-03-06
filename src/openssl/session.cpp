#include "session.hpp"

#include <ohc/http.hpp>
#include <openssl/x509v3.h>
#include <spdlog/spdlog.h>

#include "buffer.hpp"
#include "exceptions.hpp"

static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "Use OpenSSL version 1.0.1 or later");

std::unique_ptr<Session> OpenSslSession::create(SessionConfig const& config)
{
    spdlog::debug("Creating session with {}", OPENSSL_VERSION_TEXT);
    return std::make_unique<OpenSslSession>(config);
}

OpenSslSession::OpenSslSession(SessionConfig const& config)
    : Session{config}
{
}

auto OpenSslSession::getSslContext() -> SSL_CTX *
{
    if (!sslCtx_) {
        sslCtx_ = SslCtxPtr{SSL_CTX_new(TLS_client_method())};
        if (!sslCtx_) {
            throw OpenSslError{"error SSL_CTX_new"};
        }

        auto const& config = this->config();

        int minTlsVersion = 0;
        switch (config.minTlsVersion()) {
        case TlsVersion::VERSION_1_0:
            minTlsVersion = TLS1_VERSION;
            break;
        case TlsVersion::VERSION_1_1:
            minTlsVersion = TLS1_1_VERSION;
            break;
        case TlsVersion::VERSION_1_2:
            minTlsVersion = TLS1_2_VERSION;
            break;
        }
        assert(minTlsVersion != 0);

        if (SSL_CTX_set_min_proto_version(sslCtx_.get(), minTlsVersion) < 1) {
            throw OpenSslError{"error SSL_CTX_set_min_proto_version"};
        }

        if (config.useDefaultCa()) {

            auto const& caCert = SessionConfig::defaultCaCert();
            auto const& caPath = SessionConfig::defaultCaPath();

            auto const certFailed = SSL_CTX_load_verify_locations(sslCtx_.get(), caCert.c_str(), nullptr) < 1;
            auto const pathFailed = SSL_CTX_load_verify_locations(sslCtx_.get(), nullptr, caPath.c_str()) < 1;

            if (certFailed && pathFailed) {
                throw OpenSslError{"loadDefaultCerts"};
            }
            // TODO: cleanup openssl error code?

        } else {
            if (SSL_CTX_load_verify_locations(sslCtx_.get(),
                                              config.caCert() ? config.caCert()->c_str() : nullptr,
                                              config.caPath() ? config.caCert()->c_str() : nullptr) < 1)
            {
                throw OpenSslError{"error SSL_CTX_load_verify_locations"};
            }
        }
    }
    return sslCtx_.get();
}

void OpenSslSession::resetSslConfig()
{
    this->closeConnection();
    sslCtx_.reset();
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
            throw OhcException{X509_verify_cert_error_string(error)};
        }

        // SSL_get_verify_result returns OK when no cert is available
        auto *cert = SSL_get_peer_certificate(ssl);
        if (cert == nullptr) {
            throw OhcException{"no certificate available"};
        }

        // vaild certificate, but site mismatch
        if (X509_check_host(cert, hostname.data(), hostname.size(), 0, nullptr) < 1) {
            throw OhcException{"host mismatch"};
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
