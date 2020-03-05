#ifndef APPS_MBEDTLS_CORE_HPP_
#define APPS_MBEDTLS_CORE_HPP_

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

template <typename T, void (*InitFunc)(T *), void (*FreeFunc)(T *)>
class MbedTlsObject {
public:
    MbedTlsObject() { InitFunc(&object_); }
    ~MbedTlsObject() { FreeFunc(&object_); }

    MbedTlsObject(MbedTlsObject const&) = delete;
    MbedTlsObject& operator=(MbedTlsObject const&) = delete;

    T *get() { return &object_; }
    T const *get() const { return &object_; }

private:
    T object_;
};

// macro can help to remove the duplicate
using SslContext = MbedTlsObject<mbedtls_ssl_context, mbedtls_ssl_init, mbedtls_ssl_free>;
using NetContext = MbedTlsObject<mbedtls_net_context, mbedtls_net_init, mbedtls_net_free>;
using EntropyContext = MbedTlsObject<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free>;
using CtrDrbgContext = MbedTlsObject<mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free>;
using X509Cert = MbedTlsObject<mbedtls_x509_crt, mbedtls_x509_crt_init, mbedtls_x509_crt_free>;

class SslConfig {
public:
    explicit SslConfig(char const *rootCertPath);
    ~SslConfig();

    mbedtls_ssl_config const *get() const { return &config_; }

private:
    mbedtls_ssl_config config_;

    EntropyContext entropy_;
    CtrDrbgContext generator_;
    X509Cert cert_;
};

#endif  // APPS_MBEDTLS_CORE_HPP_
