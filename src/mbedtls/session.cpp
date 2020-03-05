#include "session.hpp"
#include <cassert>
#include <mbedtls/version.h>
#include <spdlog/spdlog.h>
#include "buffer.hpp"
#include "exceptions.hpp"

std::unique_ptr<Session> MbedTlsSession::create(HttpVersion version, ProxyRegistry const& proxyRegistry)
{
    spdlog::debug("Creating session with {}", MBEDTLS_VERSION_STRING_FULL);
    return std::make_unique<MbedTlsSession>(version, proxyRegistry);
}

MbedTlsSession::MbedTlsSession(HttpVersion version, ProxyRegistry const& proxyRegistry)
    : Session{version, proxyRegistry}
{
}

bool MbedTlsSession::isConnected() const
{
    return bool{net_};
}

void MbedTlsSession::createConnection(std::string const& host, std::string const& port)
{
    auto net = std::make_unique<NetContext>();

    if (auto const err = mbedtls_net_connect(net->get(), host.c_str(), port.c_str(), MBEDTLS_NET_PROTO_TCP); err != 0) {
        throw MbedTlsError{"mbedtls_net_connect", err};
    }

    net_ = std::move(net);
}

void MbedTlsSession::closeConnection()
{
    ssl_.reset();
    proxySsl_.reset();
    net_.reset();
}

void MbedTlsSession::resetSslConfig()
{
    this->closeConnection();
    config_.reset();
}

void MbedTlsSession::performHttpsPrologue(std::string const& hostname, bool verify)
{
    auto ssl = std::make_unique<SslContext>();

    if (auto const err = mbedtls_ssl_setup(ssl->get(), this->getSslConfig()); err != 0) {
        throw MbedTlsError{"mbedtls_ssl_setup", err};
    }
    if (auto const err = mbedtls_ssl_set_hostname(ssl->get(), hostname.c_str()); err != 0) {
        throw MbedTlsError{"mbedtls_ssl_set_hostname", err};
    }

    if (ssl_) {
        assert(!proxySsl_);
        proxySsl_.swap(ssl_);

        mbedtls_ssl_set_bio(ssl->get(), proxySsl_->get(), mbedtls_net_send, mbedtls_net_recv, nullptr);
    } else {
        mbedtls_ssl_set_bio(ssl->get(), net_->get(), mbedtls_net_send, mbedtls_net_recv, nullptr);
    }

    ssl_ = std::move(ssl);

    spdlog::debug("Performing SSL/TLS handshake");
    while (true) {
        auto const err = mbedtls_ssl_handshake(ssl_->get());

        if (err == 0) {
            break;
        }
        if (err == MBEDTLS_ERR_SSL_WANT_READ || err == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (err == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || err == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
            continue;
        }
        throw MbedTlsError{"mbedtls_ssl_handshake", err};
    }
    spdlog::debug("SSL/TLS handshake OK");

    if (verify) {
        auto const flags = mbedtls_ssl_get_verify_result(ssl_->get());
        if (flags != 0) {
            char buffer[512];
            auto const n = mbedtls_x509_crt_verify_info(buffer, sizeof(buffer), "", flags);
            if (n > 0) {
                buffer[n - 1] = '\0';  // get rid of the newline
            }
            spdlog::error("Certificate verification failed: {}", buffer);
            if (verify) {
                throw std::runtime_error{"certification verification failed"};
            }
        }
    }
}

auto MbedTlsSession::createBuffer() -> std::unique_ptr<Buffer>
{
    if (ssl_) {
        return std::make_unique<SslCtxBuffer>(ssl_->get());
    }
    assert(net_);
    return std::make_unique<NetCtxBuffer>(net_->get());
}

auto MbedTlsSession::getSslConfig() -> mbedtls_ssl_config const *
{
    if (!config_) {
        // TODO: don't use hardcoded path
        config_ = std::make_unique<SslConfig>(this->caCert(), this->caPath());
    }
    return config_->get();
}
