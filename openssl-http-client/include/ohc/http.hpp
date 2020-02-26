#ifndef OHC_HTTP_HPP_
#define OHC_HTTP_HPP_

#include <map>
#include <vector>

#include <ohc/url.hpp>

enum class HttpVersion { VERSION_1_0, VERSION_1_1 };

struct Request {
    HttpVersion version;  // should this be here?

    std::string method;

    Url url;
    Url httpProxy;

    // the host and port to connect to
    std::string const& connectHost() const;
    std::string const& connectPort() const;

    bool shouldUseHttpProxy() const;

    std::string makeMessage() const;
};

struct Response {
    std::vector<char> raw;
    int statusCode;
    std::map<std::string, std::string> headers;
    size_t beginOfBody;
    size_t contentLength;
};

#endif  // OHC_HTTP_HPP_
