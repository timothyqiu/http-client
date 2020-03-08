#include "core.hpp"

#include <cassert>
#include <spdlog/spdlog.h>

#include <ohc/exceptions.hpp>
#include <ohc/session_config.hpp>
#include "exceptions.hpp"

SslConfig::SslConfig(SessionConfig const& sessionConfig)
{
    if (auto const err = mbedtls_ctr_drbg_seed(generator_.get(), mbedtls_entropy_func, entropy_.get(), nullptr, 0); err != 0) {
        throw MbedTlsError{"mbedtls_ctr_drbg_seed", err};
    }

    if (sessionConfig.useDefaultCa()) {

        auto const& caCert = SessionConfig::defaultCaCert();
        auto const& caPath = SessionConfig::defaultCaPath();

        auto const certErr = mbedtls_x509_crt_parse_file(cert_.get(), caCert.c_str());
        auto const pathErr = mbedtls_x509_crt_parse_path(cert_.get(), caPath.c_str());

        if (certErr != 0 && pathErr != 0) {
            spdlog::error("Can't load default certs from {}: {}", caCert, mbedTlsTranslateError(certErr));
            spdlog::error("Can't load default certs from {}: {}", caPath, mbedTlsTranslateError(pathErr));
            throw OhcException{"can't load default certs"};
        }

    } else {

        if (auto const& caCert = sessionConfig.caCert(); caCert) {
            if (auto const err = mbedtls_x509_crt_parse_file(cert_.get(), caCert->c_str()); err != 0) {
                // > 0 partial success
                throw MbedTlsError{"mbedtls_x509_crt_parse_file", err};
            }
        }

        if (auto const& caPath = sessionConfig.caPath(); caPath) {
            if (auto const err = mbedtls_x509_crt_parse_path(cert_.get(), caPath->c_str()); err != 0) {
                // > 0 partial success
                throw MbedTlsError{"mbedtls_x509_crt_parse_path", err};
            }
        }

    }

    mbedtls_ssl_config_init(&config_);
    if (auto const err = mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); err != 0) {
        mbedtls_ssl_config_free(&config_);
        throw MbedTlsError{"mbedtls_ssl_config_defaults", err};
    }
    mbedtls_ssl_conf_rng(&config_, mbedtls_ctr_drbg_random, generator_.get());
    mbedtls_ssl_conf_ca_chain(&config_, cert_.get(), nullptr);
    mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_OPTIONAL);

    // MbedTLS treats TLS1.0 as SSL3.1, so this has an offset
    int version = 0;
    switch (sessionConfig.minTlsVersion()) {
    case TlsVersion::VERSION_1_0:
        version = MBEDTLS_SSL_MINOR_VERSION_1;
        break;
    case TlsVersion::VERSION_1_1:
        version = MBEDTLS_SSL_MINOR_VERSION_2;
        break;
    case TlsVersion::VERSION_1_2:
        version = MBEDTLS_SSL_MINOR_VERSION_3;
        break;
    }
    assert(version != 0);

    mbedtls_ssl_conf_min_version(&config_, MBEDTLS_SSL_MAJOR_VERSION_3, version);
}

SslConfig::~SslConfig()
{
    mbedtls_ssl_config_free(&config_);
}
