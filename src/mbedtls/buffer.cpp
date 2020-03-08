#include "buffer.hpp"

#include <ohc/exceptions.hpp>
#include "exceptions.hpp"

NetCtxBuffer::NetCtxBuffer(mbedtls_net_context *ctx)
    : ctx_{ctx}
{
}

auto NetCtxBuffer::push(uint8_t const *data, size_t size) -> size_t
{
    int const n = mbedtls_net_send(ctx_, data, size);
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error writing data", n};
    }
    // TODO: = 0?
    return n;
}

void NetCtxBuffer::pull()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = mbedtls_net_recv(ctx_, buffer, bufferSize);
    if (n == 0) {
        throw EndOfStreamError{};
    }
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error reading data", n};
    }
    this->markWritten(n);
}

SslCtxBuffer::SslCtxBuffer(mbedtls_ssl_context *ctx)
    : ctx_{ctx}
{
}

auto SslCtxBuffer::push(uint8_t const *data, size_t size) -> size_t
{
    int const n = mbedtls_ssl_write(ctx_, data, size);
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error writing data", n};
    }
    // TODO: = 0?
    return n;
}

void SslCtxBuffer::pull()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = mbedtls_ssl_read(ctx_, buffer, bufferSize);
    if (n == 0) {
        throw EndOfStreamError{};
    }
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error reading data", n};
    }
    this->markWritten(n);
}
