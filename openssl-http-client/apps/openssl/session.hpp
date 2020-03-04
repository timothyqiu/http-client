#ifndef APPS_OPENSSL_SESSION_HPP_
#define APPS_OPENSSL_SESSION_HPP_

#include <memory>
#include <string>
#include <ohc/session.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>

struct BioDeleter { void operator()(BIO *bio) { BIO_free_all(bio); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct SslCtxDeleter { void operator()(SSL_CTX *ctx) { SSL_CTX_free(ctx); } };
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

class OpenSslSession : public Session {
public:
    OpenSslSession(HttpVersion version, ProxyRegistry const& proxyRegistry,
                   bool insecure, bool proxyInsecure);

private:
    BioPtr bio_;
    SslCtxPtr sslCtx_;

    auto getSslContext() -> SSL_CTX *;

    bool isConnected() const override;
    void createConnection(Request const& req) override;
    void closeConnection() override;

    void performHttpsPrologue(std::string const& hostname, bool verify) override;
    auto createBuffer() -> std::unique_ptr<Buffer> override;
};

#endif  // APPS_OPENSSL_SESSION_HPP_
