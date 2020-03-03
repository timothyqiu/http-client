#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/version.h>
#include <ohc/buffer.hpp>
#include <ohc/http.hpp>
#include <spdlog/spdlog.h>

class MbedTLSError : public std::runtime_error {
public:
    MbedTLSError(char const *message, int error)
        : std::runtime_error{message}
    {
        std::vector<char> buffer(256);
        mbedtls_strerror(error, buffer.data(), buffer.size());
        spdlog::error("{}: {}", message, std::string{buffer.data()});
    }
};

class NetCtxBuffer : public Buffer {
public:
    // not owning
    explicit NetCtxBuffer(mbedtls_net_context *ctx)
        : ctx_{ctx}
    {
    }

    auto push(uint8_t const *data, size_t size) -> size_t override
    {
        int const n = mbedtls_net_send(ctx_, data, size);
        if (n < 0) {
            // TODO: detail & dedicated exception
            throw MbedTLSError{"error writing data", n};
        }
        // TODO: = 0?
        return n;
    }

    void pull() override
    {
        // make sure space available
        size_t const bufferSize = 256;  // this is a relative small amount, for better testing
        uint8_t *buffer = this->getBuffer(bufferSize);

        int const n = mbedtls_net_recv(ctx_, buffer, bufferSize);
        if (n == 0) {
            throw std::runtime_error{"end of stream reached"};
        }
        if (n < 0) {
            // TODO: detail & dedicated exception
            throw MbedTLSError{"error reading data", n};
        }
        this->markWritten(n);
    }

private:
    mbedtls_net_context *ctx_;
};

static void testHttp()
{
    Request req;
    req.version = HttpVersion::VERSION_1_0;
    req.url = parseUrl("http://httpbin.org/get");
    req.method("GET");

    mbedtls_net_context netCtx;
    mbedtls_net_init(&netCtx);
    // TODO: scope guard to free netCtx here

    if (auto const err = mbedtls_net_connect(&netCtx, req.url.host.c_str(), req.url.port.c_str(), MBEDTLS_NET_PROTO_TCP); err != 0) {
        spdlog::error("mbedtls_net_connect error: {}", err);
    }

    auto const message = req.makeMessage();

    NetCtxBuffer buffer{&netCtx};

    buffer.write(message.data(), message.size());

    auto const resp = readResponseFromBuffer(req, buffer);

    std::printf("Status: %d\n", resp.statusCode);
    std::printf("Headers:\n");
    for (auto const& e : resp.headers) {
        std::printf("\t%s = %s\n", e.first.c_str(), e.second.c_str());
    }
    std::printf("Body:\n%s", std::string{std::begin(resp.body), std::end(resp.body)}.c_str());

    mbedtls_net_free(&netCtx);
}

int main()
{
    spdlog::set_level(spdlog::level::debug);

    spdlog::info("MbedTLS version: {}", MBEDTLS_VERSION_STRING);

    testHttp();

    // TODO: https
}
