#ifndef OHC_SESSION_HPP_
#define OHC_SESSION_HPP_

#include <map>
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

    auto get(Url const& url) -> Response;
    auto request(Request const& req) -> Response;

private:

    HttpVersion version_;
    ProxyRegistry proxyRegistry_;
    bool insecure_;
    bool proxyInsecure_;

    Url serverIdentity_;

    bool canReuseCurrentConnection(Request const& req) const;
    void setupHttps(Request const& req);
    auto makeRequest(Request const& req) -> Response;

    virtual bool isConnected() const = 0;
    virtual void createConnection(std::string const& host, std::string const& port) = 0;
    virtual void closeConnection() = 0;

    virtual void performHttpsPrologue(std::string const& hostname, bool verify) = 0;
    virtual auto createBuffer() -> std::unique_ptr<Buffer> = 0;
};

class SessionFactory {
public:
    using CreatorFunc = std::unique_ptr<Session>(*)(HttpVersion, ProxyRegistry const&);

    static bool registerCreator(std::string const& name, CreatorFunc func);
    static std::unique_ptr<Session> create(std::string const& name,
                                           HttpVersion version, ProxyRegistry const& proxyRegistry);

private:
    std::map<std::string, CreatorFunc> registry_;

    static SessionFactory& instance();

    SessionFactory() = default;
};

#endif  // OHC_SESSION_HPP_
