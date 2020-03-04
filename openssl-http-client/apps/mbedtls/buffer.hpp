#ifndef APPS_MBEDTLS_BUFER_HPP_
#define APPS_MBEDTLS_BUFER_HPP_

#include <ohc/buffer.hpp>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

class CtxBuffer : public Buffer {
public:
    // not owning
    explicit CtxBuffer(mbedtls_net_context *ctx);
    explicit CtxBuffer(mbedtls_ssl_context *ctx);

    auto push(uint8_t const *data, size_t size) -> size_t override;
    void pull() override;

private:
    mbedtls_net_context *netCtx_;
    mbedtls_ssl_context *sslCtx_;

    auto dispatchRead(uint8_t *buffer, size_t size) -> int;
    auto dispatchWrite(uint8_t const *data, size_t size) -> int;
};

#endif  // APPS_MBEDTLS_BUFER_HPP_
