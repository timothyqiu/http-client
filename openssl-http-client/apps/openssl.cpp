#include "openssl.hpp"

#include <cassert>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/x509v3.h>
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

auto BioBuffer::push(uint8_t const *data, size_t size) -> size_t
{
    int const n = BIO_write(bio_, data, size);
    if (n < 1) {
        throw OpenSslError{"error writing data"};
    }
    return n;
}

void BioBuffer::pull()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = BIO_read(bio_, buffer, bufferSize);
    if (n < 1) {
        if (BIO_should_retry(bio_)) {
            this->pull();
            return;
        }
        if (n == 0) {
            throw std::runtime_error{"end of stream reached"};
        }
        throw OpenSslError{"error reading data"};
    }
    this->markWritten(n);
}

Response makeRequest(BIO *bio, Request const& req)
{
    BioBuffer buffer{bio};

    auto const& message = req.makeMessage();
    spdlog::debug("Sending request:\n{}<EOM>", message);
    buffer.write(message.data(), message.size());

    return readResponseFromBuffer(req, buffer);
}

BioPtr makeBio(std::string const& host, std::string const& port)
{
    BioPtr bio{BIO_new(BIO_s_connect())};
    if (!bio) {
        throw OpenSslError{"error BIO_new"};
    }

    if (BIO_set_conn_hostname(bio.get(), host.c_str()) < 1) {
        throw OpenSslError{"error BIO_set_conn_hostname"};
    }
    BIO_set_conn_port(bio.get(), port.c_str());

    if (BIO_do_connect(bio.get()) < 1) {
        throw OpenSslError{"error BIO_do_connect"};
    }

    return bio;
}

SslCtxPtr makeSslCtx()
{
    SslCtxPtr ctx{SSL_CTX_new(TLS_client_method())};
    if (!ctx) {
        throw OpenSslError{"error SSL_CTX_new"};
    }

    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) < 1) {
        throw OpenSslError{"error SSL_CTX_set_min_proto_version"};
    }
    if (SSL_CTX_set_default_verify_paths(ctx.get()) < 1) {
        throw OpenSslError{"error SSL_CTX_set_default_verify_paths"};
    }

    return ctx;
}

void verifyCertificate(SSL *ssl, std::string_view hostname)
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
