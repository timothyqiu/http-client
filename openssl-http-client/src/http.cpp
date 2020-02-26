#include <ohc/http.hpp>

std::string const& Request::connectHost() const {
    return shouldUseHttpProxy() ? httpProxy.host : url.host;
}

std::string const& Request::connectPort() const {
    return shouldUseHttpProxy() ? httpProxy.port : url.port;
}

bool Request::shouldUseHttpProxy() const {
    return url.scheme == "http" && !httpProxy.host.empty() && !httpProxy.port.empty();
}

std::string Request::makeMessage() const
{
    auto const requestUri = shouldUseHttpProxy() ? absoluteUrlString(url) : relativeUrlString(url);

    std::string versionMark;
    std::string header;

    switch (version) {
    case HttpVersion::VERSION_1_0:
        versionMark = "HTTP/1.0";
        break;

    case HttpVersion::VERSION_1_1:
        versionMark = "HTTP/1.1";
        header = "Host: " + url.host + "\r\n";
        break;
    }

    return method + " " + requestUri + " " + versionMark +"\r\n" + header + "\r\n";
}
