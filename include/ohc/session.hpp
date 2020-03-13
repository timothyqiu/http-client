#ifndef OHC_SESSION_HPP_
#define OHC_SESSION_HPP_

#include <memory>
#include <string>
#include <string_view>

#include <ohc/http.hpp>
#include <ohc/session_config.hpp>
#include <ohc/url.hpp>

class Buffer;

class Session {
public:
    Session(SessionConfig config);
    virtual ~Session();

    auto config() const -> SessionConfig const& { return config_; }

    auto get(Url const& url) -> Response;
    auto request(Request const& req) -> Response;

private:

    SessionConfig config_;

    Url serverIdentity_;

    bool canReuseCurrentConnection(Request const& req) const;
    void setupHttps(Request const& req);
    auto makeRequest(Request const& req) -> Response;

    virtual bool isConnected() const = 0;
    virtual void createConnection(std::string const& host, std::string const& port) = 0;
    virtual void closeConnection() = 0;

    virtual void resetSslConfig() = 0;
    virtual void performHttpsPrologue(std::string const& hostname, bool verify) = 0;
    virtual auto createBuffer() -> std::unique_ptr<Buffer> = 0;
};

using SessionPtr = std::unique_ptr<Session>;

#endif  // OHC_SESSION_HPP_
