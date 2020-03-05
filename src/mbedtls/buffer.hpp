#ifndef APPS_MBEDTLS_BUFER_HPP_
#define APPS_MBEDTLS_BUFER_HPP_

#include <ohc/buffer.hpp>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

class NetCtxBuffer : public Buffer {
public:
    // not owning
    explicit NetCtxBuffer(mbedtls_net_context *ctx);

    auto push(uint8_t const *data, size_t size) -> size_t override;
    void pull() override;

private:
    mbedtls_net_context *ctx_;
};

class SslCtxBuffer : public Buffer {
public:
    // not owning
    explicit SslCtxBuffer(mbedtls_ssl_context *ctx);

    auto push(uint8_t const *data, size_t size) -> size_t override;
    void pull() override;

private:
    mbedtls_ssl_context *ctx_;
};

#endif  // APPS_MBEDTLS_BUFER_HPP_
