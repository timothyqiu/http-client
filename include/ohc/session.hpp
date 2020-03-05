#ifndef OHC_SESSION_HPP_
#define OHC_SESSION_HPP_

#include <memory>
#include <string>
#include <ohc/buffer.hpp>
#include <ohc/http.hpp>

class Session {
public:
    Session(HttpVersion version, ProxyRegistry const& proxyRegistry);
    virtual ~Session();

    auto version() const { return version_; }

    bool insecure() const { return insecure_; }
    void insecure(bool value) { insecure_ = value; }
    bool proxyInsecure() const { return proxyInsecure_; }
    void proxyInsecure(bool value) { proxyInsecure_ = value; }

    auto caCert() const { return caCert_; }
    void caCert(std::string value);
    auto caPath() const { return caPath_; }
    void caPath(std::string value);

    auto get(Url const& url) -> Response;
    auto request(Request const& req) -> Response;

private:

    HttpVersion version_;
    ProxyRegistry proxyRegistry_;
    bool insecure_;
    bool proxyInsecure_;
    std::string caCert_;
    std::string caPath_;

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

#endif  // OHC_SESSION_HPP_
