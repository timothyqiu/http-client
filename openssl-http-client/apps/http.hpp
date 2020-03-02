#ifndef APP_HTTP_HPP_
#define APP_HTTP_HPP_

#include <memory>
#include <string>
#include <string_view>

#include <ohc/http.hpp>
#include <ohc/url.hpp>

class HttpClient {
public:
    HttpClient(HttpVersion version, ProxyRegistry const& proxy, bool insecure, bool proxyInsecure);
    ~HttpClient();

    HttpClient(HttpClient const&) = delete;
    HttpClient& operator=(HttpClient const&) = delete;

    auto get(Url const& url) -> Response;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

#endif  // APP_HTTP_HPP_
