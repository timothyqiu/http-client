#ifndef OHC_HTTP_HPP_
#define OHC_HTTP_HPP_

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ohc/url.hpp>

class Buffer;

enum class HttpVersion { VERSION_1_0, VERSION_1_1 };

struct Authentication {
    std::string user;
    std::string password;
};

class Request {
public:
    // TODO: property setter?

    HttpVersion version;  // should this be here?

    Url url;  // target of most methods
    Url connectAuthority;  // target of CONNECT method

    std::optional<Url> proxy;
    std::optional<Authentication> basicAuth;

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
