#ifndef OHC_HTTP_HPP_
#define OHC_HTTP_HPP_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <ohc/url.hpp>

enum class HttpVersion { VERSION_1_0, VERSION_1_1 };

struct Request;

class Proxy {
public:
    void set(std::string_view scheme, Url const& url);
    std::optional<Url> get(std::string_view scheme) const;

private:
    std::map<std::string, Url> servers;
};

// TODO: make this a class
struct Request {
    HttpVersion version;  // should this be here?

    std::string method;

    Url url;
    Url connectAuthority;

    std::optional<Url> proxy;

    std::string makeRequestUri() const;
    std::string makeMessage() const;
};

struct Response {
    std::vector<char> raw;
    int statusCode;
    std::map<std::string, std::string> headers;
    size_t beginOfBody;
    size_t contentLength;

    bool isSuccess() const;
};

#endif  // OHC_HTTP_HPP_
