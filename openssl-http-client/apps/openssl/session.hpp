#ifndef APPS_OPENSSL_SESSION_HPP_
#define APPS_OPENSSL_SESSION_HPP_

#include <string>
#include <ohc/session.hpp>
#include "core.hpp"

class OpenSslSession : public Session {
public:
    OpenSslSession(HttpVersion version, ProxyRegistry const& proxyRegistry);

private:
    static bool s_registered;

    static std::unique_ptr<Session> create(HttpVersion version, ProxyRegistry const& proxyRegistry);

    BioPtr bio_;
    SslCtxPtr sslCtx_;

    auto getSslContext() -> SSL_CTX *;

    bool isConnected() const override;
    void createConnection(std::string const& host, std::string const& port) override;
    void closeConnection() override;

    void performHttpsPrologue(std::string const& hostname, bool verify) override;
    auto createBuffer() -> std::unique_ptr<Buffer> override;
};

#endif  // APPS_OPENSSL_SESSION_HPP_
