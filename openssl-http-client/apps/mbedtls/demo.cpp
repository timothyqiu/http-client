#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <ohc/http.hpp>
#include <spdlog/spdlog.h>

#include "buffer.hpp"
#include "exceptions.hpp"

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
using SslConfig = MbedTlsObject<mbedtls_ssl_config, mbedtls_ssl_config_init, mbedtls_ssl_config_free>;

static void request(char const *url)
{
    spdlog::info("GET {}", url);

    Request req;
    req.version = HttpVersion::VERSION_1_0;
    req.url = parseUrl(url);
    req.method("GET");

    NetContext net;

    if (auto const err = mbedtls_net_connect(net.get(), req.url.host.c_str(), req.url.port.c_str(), MBEDTLS_NET_PROTO_TCP); err != 0) {
        throw MbedTlsError{"mbedtls_net_connect", err};
    }

    EntropyContext entropy;
    CtrDrbgContext generator;
    if (auto const err = mbedtls_ctr_drbg_seed(generator.get(), mbedtls_entropy_func, entropy.get(), nullptr, 0); err != 0) {
        throw MbedTlsError{"mbedtls_ctr_drbg_seed", err};
    }

    X509Cert cert;
    if (auto const err = mbedtls_x509_crt_parse_file(cert.get(), "/etc/ssl/cert.pem"); err != 0) {
        // > 0 partial success
        throw MbedTlsError{"mbedtls_x509_crt_parse_file", err};
    }

    SslConfig config;
    if (auto const err = mbedtls_ssl_config_defaults(config.get(), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); err != 0) {
        throw MbedTlsError{"mbedtls_ssl_config_defaults", err};
    }
    mbedtls_ssl_conf_rng(config.get(), mbedtls_ctr_drbg_random, generator.get());
    mbedtls_ssl_conf_ca_chain(config.get(), cert.get(), nullptr);
    mbedtls_ssl_conf_authmode(config.get(), MBEDTLS_SSL_VERIFY_OPTIONAL);

    SslContext ssl;
    if (auto const err = mbedtls_ssl_setup(ssl.get(), config.get()); err != 0) {
        throw MbedTlsError{"mbedtls_ssl_setup", err};
    }
    if (auto const err = mbedtls_ssl_set_hostname(ssl.get(), req.url.host.c_str()); err != 0) {
        throw MbedTlsError{"mbedtls_ssl_set_hostname", err};
    }

    std::unique_ptr<Buffer> buffer;

    if (req.url.scheme == "https") {

        mbedtls_ssl_set_bio(ssl.get(), net.get(), mbedtls_net_send, mbedtls_net_recv, nullptr);

        spdlog::debug("Performing SSL/TLS handshake");
        while (true) {
            auto const err = mbedtls_ssl_handshake(ssl.get());

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

        if (auto const flags = mbedtls_ssl_get_verify_result(ssl.get()); flags != 0) {
            char buffer[512];
            auto const n = mbedtls_x509_crt_verify_info(buffer, sizeof(buffer), "", flags);
            if (n > 0) {
                buffer[n - 1] = '\0';  // get rid of the newline
            }
            spdlog::error("Certificate verification failed: {}", buffer);
            throw std::runtime_error{"certification verification failed"};
        }

        buffer = std::make_unique<CtxBuffer>(ssl.get());

    } else {
        buffer = std::make_unique<CtxBuffer>(net.get());
    }

    auto const message = req.makeMessage();

    buffer->write(message.data(), message.size());

    auto const resp = readResponseFromBuffer(req, *buffer);

    std::printf("Status: %d\n", resp.statusCode);
    std::printf("Headers:\n");
    for (auto const& e : resp.headers) {
        std::printf("\t%s = %s\n", e.first.c_str(), e.second.c_str());
    }
    std::printf("Body:\n%s", std::string{std::begin(resp.body), std::end(resp.body)}.c_str());
}

int main(int argc, char *argv[])
try {
    spdlog::set_level(spdlog::level::debug);

    spdlog::info("MbedTLS version: {}", MBEDTLS_VERSION_STRING);

    char const *url = "https://httpbin.org/get";
    if (argc > 1) {
        url = argv[1];
    }

    request(url);
}
catch (std::exception const& e) {
    spdlog::error("Exception: {}", e.what());
}
