#include <ohc/http.hpp>
#include <cassert>

std::string const& Request::connectHost() const {
    if (shouldUseHttpProxy()) {
        return httpProxy.host;
    }
    if (shouldUseHttpsProxy()) {
        return httpsProxy.host;
    }
    return url.host;
}

std::string const& Request::connectPort() const {
    if (shouldUseHttpProxy()) {
        return httpProxy.port;
    }
    if (shouldUseHttpsProxy()) {
        return httpsProxy.port;
    }
    return url.port;
}

bool Request::shouldUseHttpProxy() const {
    return url.scheme == "http" && !httpProxy.host.empty() && !httpProxy.port.empty();
}

bool Request::shouldUseHttpsProxy() const {
    switch (version) {
    case HttpVersion::VERSION_1_0:
        return false;
    default:
        break;
    }
    return url.scheme == "https" && !httpsProxy.host.empty() && !httpsProxy.port.empty();
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

std::string Request::makeHttpsProxyConnectMessage() const
{
    assert(version == HttpVersion::VERSION_1_1);
    return "CONNECT " + url.host + ":" + url.port + " HTTP/1.1\r\nHost: " + httpsProxy.host + "\r\n\r\n";
}

bool Response::isSuccess() const
{
    auto const category = statusCode % 100;
    return category < 4;
}
