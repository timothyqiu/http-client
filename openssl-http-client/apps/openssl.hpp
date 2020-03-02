#ifndef APP_OPENSSL_HPP_
#define APP_OPENSSL_HPP_

#include <memory>
#include <stdexcept>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <ohc/buffer.hpp>
#include <ohc/http.hpp>

class OpenSslError : public std::runtime_error {
public:
    explicit OpenSslError(char const *message);
};

class BioBuffer : public Buffer {
public:
    // not owning
    explicit BioBuffer(BIO *bio);

    virtual size_t push(uint8_t const *data, size_t size) override;
    virtual void pull() override;

private:
    BIO *bio_;
};

Response makeRequest(BIO *bio, Request const& req);

struct BioDeleter { void operator()(BIO *bio) { BIO_free_all(bio); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
BioPtr makeBio(std::string const& host, std::string const& port);

struct SslCtxDeleter { void operator()(SSL_CTX *ctx) { SSL_CTX_free(ctx); } };
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
SslCtxPtr makeSslCtx();

void verifyCertificate(SSL *ssl, std::string_view hostname);

#endif  // APP_OPENSSL_HPP_
