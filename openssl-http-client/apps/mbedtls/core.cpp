#include "core.hpp"
#include "exceptions.hpp"

SslConfig::SslConfig(char const *rootCertPath)
{
    if (auto const err = mbedtls_ctr_drbg_seed(generator_.get(), mbedtls_entropy_func, entropy_.get(), nullptr, 0); err != 0) {
        throw MbedTlsError{"mbedtls_ctr_drbg_seed", err};
    }

    if (auto const err = mbedtls_x509_crt_parse_file(cert_.get(), rootCertPath); err != 0) {
        // > 0 partial success
        throw MbedTlsError{"mbedtls_x509_crt_parse_file", err};
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
