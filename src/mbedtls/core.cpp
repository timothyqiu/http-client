#include "core.hpp"
#include <spdlog/spdlog.h>
#include "exceptions.hpp"

static void loadDefaultCerts(mbedtls_x509_crt *x509)
{
    // TODO: windows location?
    char const *cert = "/etc/ssl/cert.pem";
    char const *path = "/etc/ssl/certs";

    auto const certErr = mbedtls_x509_crt_parse_file(x509, cert);
    auto const pathErr = mbedtls_x509_crt_parse_path(x509, path);

    if (certErr != 0 && pathErr != 0) {
        spdlog::error("Can't load default certs from {}: {}", cert, mbedTlsTranslateError(certErr));
        spdlog::error("Can't load default certs from {}: {}", path, mbedTlsTranslateError(pathErr));
        throw std::runtime_error{"can't load default certs"};
    }
}

SslConfig::SslConfig(std::string const& cert, std::string const& path)
{
    if (auto const err = mbedtls_ctr_drbg_seed(generator_.get(), mbedtls_entropy_func, entropy_.get(), nullptr, 0); err != 0) {
        throw MbedTlsError{"mbedtls_ctr_drbg_seed", err};
    }

    if (cert.empty() && path.empty()) {

        loadDefaultCerts(cert_.get());

    } else {

        if (!cert.empty()) {
            if (auto const err = mbedtls_x509_crt_parse_file(cert_.get(), cert.c_str()); err != 0) {
                // > 0 partial success
                throw MbedTlsError{"mbedtls_x509_crt_parse_file", err};
            }
        }

        if (!path.empty()) {
            if (auto const err = mbedtls_x509_crt_parse_path(cert_.get(), path.c_str()); err != 0) {
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
}

SslConfig::~SslConfig()
{
    mbedtls_ssl_config_free(&config_);
}
