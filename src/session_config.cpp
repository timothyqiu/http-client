#include <ohc/session_config.hpp>

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
