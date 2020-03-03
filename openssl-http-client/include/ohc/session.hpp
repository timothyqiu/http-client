#ifndef OHC_SESSION_HPP_
#define OHC_SESSION_HPP_

#include <ohc/buffer.hpp>
#include <ohc/http.hpp>

class Session {
public:
    Session(HttpVersion version, ProxyRegistry const& proxyRegistry,
            bool insecure, bool proxyInsecure);
    virtual ~Session() = default;

    auto version() const { return version_; }
    bool insecure() const { return insecure_; }
    bool proxyInsecure() const { return proxyInsecure_; }

    auto get(Url const& url) -> Response;
    auto request(Request const& req) -> Response;

private:
    HttpVersion version_;
    ProxyRegistry proxyRegistry_;
    bool insecure_;
    bool proxyInsecure_;

    virtual void setupConnection(Request const& req) = 0;
    virtual void closeConnection() = 0;
    virtual auto makeRequest(Request const& req) -> Response = 0;
};

#endif  // OHC_SESSION_HPP_
