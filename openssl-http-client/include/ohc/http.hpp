#ifndef OHC_HTTP_HPP_
#define OHC_HTTP_HPP_

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ohc/buffer.hpp>
#include <ohc/url.hpp>

enum class HttpVersion { VERSION_1_0, VERSION_1_1 };

class ProxyRegistry {
public:
    void set(std::string_view scheme, Url const& url);
    std::optional<Url> get(std::string_view scheme) const;

private:
    std::map<std::string, Url> servers;
};

class Request {
public:
    // TODO: property setter?

    HttpVersion version;  // should this be here?

    Url url;
    Url connectAuthority;

    std::optional<Url> proxy;

    auto method() const -> std::string_view;
    void method(std::string_view value);

    auto makeMessage() const -> std::string;

private:
    auto makeRequestUri() const -> std::string;

    std::string method_;
};

struct Response {
    std::vector<uint8_t> body;
    int statusCode;
    std::map<std::string, std::string> headers;
    size_t beginOfBody;

    std::string transferEncoding;

    bool isSuccess() const;
};

Response readResponseFromBuffer(Request const& req, Buffer& buffer);

#endif  // OHC_HTTP_HPP_
