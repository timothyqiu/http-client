#include <ohc/http.hpp>
#include <cassert>

void Proxy::set(std::string_view scheme, Url const& url)
{
    assert(scheme == "http" || scheme == "https");

    if (url.host.empty()) {
        throw std::runtime_error{std::string{scheme} + " proxy missing host"};
    }
    if (url.port.empty()) {
        throw std::runtime_error{std::string{scheme} + " proxy missing port"};
    }

    servers[std::string{scheme}] = url;
}

std::optional<Url> Proxy::get(std::string_view scheme) const
{
    auto const iter = servers.find(std::string{scheme});
    if (iter == std::end(servers)) {
        return {};
    }
    return iter->second;
}

std::string Request::makeRequestUri() const
{
    if (method == "CONNECT") {
        assert(!connectAuthority.host.empty() && !connectAuthority.port.empty());
        return connectAuthority.authority();
    }
    if (url.scheme == "http" && proxy) {
        return absoluteUrlString(url);
    }
    return relativeUrlString(url);
}

std::string Request::makeMessage() const
{
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

    return method + " " + makeRequestUri() + " " + versionMark +"\r\n" + header + "\r\n";
}

bool Response::isSuccess() const
{
    auto const category = statusCode % 100;
    return category < 4;
}
