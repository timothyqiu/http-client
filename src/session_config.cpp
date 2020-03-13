#include <ohc/session_config.hpp>
#include <ohc/exceptions.hpp>

auto SessionConfig::defaultCaCert() -> std::string
{
    // TODO: different platforms
    return "/etc/ssl/cert.pem";
}

auto SessionConfig::defaultCaPath() -> std::string
{
    // TODO: different platforms
    return "/etc/ssl/certs";
}

void SessionConfig::checkProxyUrl(Url const& url)
{
    if (url.scheme() != "http" && url.scheme() != "https") {
        throw OhcException{"proxy scheme not supported: " + url.toAbsoluteString()};
    }
}
