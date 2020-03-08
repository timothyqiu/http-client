#ifndef APP_MBEDTLS_SESSION_HPP_
#define APP_MBEDTLS_SESSION_HPP_

#include <memory>
#include <ohc/session.hpp>
#include "core.hpp"

class MbedTlsSession : public Session {
public:
    static auto create(SessionConfig const& config) -> SessionPtr;

    explicit MbedTlsSession(SessionConfig const& config);

private:
    std::unique_ptr<SslConfig> sslConfig_;

    std::unique_ptr<SslContext> ssl_;
    std::unique_ptr<SslContext> proxySsl_;
    std::unique_ptr<NetContext> net_;

    auto getSslConfig() -> mbedtls_ssl_config const *;

    bool isConnected() const override;
    void createConnection(std::string const& host, std::string const& port) override;
    void closeConnection() override;

    void resetSslConfig() override;
    void performHttpsPrologue(std::string const& hostname, bool verify) override;
    auto createBuffer() -> std::unique_ptr<Buffer> override;
};

#endif  // APP_MBEDTLS_SESSION_HPP_
