#include "buffer.hpp"

#include <cassert>
#include "exceptions.hpp"

CtxBuffer::CtxBuffer(mbedtls_net_context *ctx)
    : netCtx_{ctx}, sslCtx_{nullptr}
{
}

CtxBuffer::CtxBuffer(mbedtls_ssl_context *ctx)
    : netCtx_{nullptr}, sslCtx_{ctx}
{
}

auto CtxBuffer::push(uint8_t const *data, size_t size) -> size_t
{
    int const n = this->dispatchWrite(data, size);
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error writing data", n};
    }
    // TODO: = 0?
    return n;
}

void CtxBuffer::pull()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = this->dispatchRead(buffer, bufferSize);
    if (n == 0) {
        throw std::runtime_error{"end of stream reached"};
    }
    if (n < 0) {
        // TODO: detail & dedicated exception
        throw MbedTlsError{"error reading data", n};
    }
    this->markWritten(n);
}

auto CtxBuffer::dispatchRead(uint8_t *buffer, size_t size) -> int
{
    assert((netCtx_ == nullptr) != (sslCtx_ == nullptr));

    if (netCtx_ != nullptr) {
        return mbedtls_net_recv(netCtx_, buffer, size);
    }
    if (sslCtx_ != nullptr) {
        return mbedtls_ssl_read(sslCtx_, buffer, size);
    }

    assert(false);
    return INT_MIN;
}

auto CtxBuffer::dispatchWrite(uint8_t const *data, size_t size) -> int
{
    assert((netCtx_ == nullptr) != (sslCtx_ == nullptr));

    if (netCtx_ != nullptr) {
        return mbedtls_net_send(netCtx_, data, size);
    }
    if (sslCtx_ != nullptr) {
        return mbedtls_ssl_write(sslCtx_, data, size);
    }

    assert(false);
    return INT_MIN;
}
