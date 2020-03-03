#ifndef APPS_OPENSSL_SESSION_HPP_
#define APPS_OPENSSL_SESSION_HPP_

#include <string>
#include <ohc/session.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>

class OpenSslSession : public Session {
public:
    OpenSslSession(HttpVersion version, ProxyRegistry const& proxyRegistry,
                   bool insecure, bool proxyInsecure);
    ~OpenSslSession() override;

private:
    BIO *bio_;
    SSL_CTX *ssl_ctx_;

    Url serverIdentity_;

    auto getSslContext() -> SSL_CTX *;
    void performHttpsPrologue(std::string const& hostname, bool verify);
    void verifyCertificate(SSL *ssl, std::string const& hostname);
    bool canReuseCurrentConnection(Request const& req);

    void setupConnection(Request const& req) override;
    void closeConnection() override;
    auto makeRequest(Request const& req) -> Response override;
};

#endif  // APPS_OPENSSL_SESSION_HPP_
