#include <ohc/session_factory.hpp>

#include "mbedtls/session.hpp"
#include "openssl/session.hpp"

SessionFactory& SessionFactory::instance()
{
    static SessionFactory instance;
    return instance;
}

SessionFactory::SessionFactory()
{
    registry_["mbedtls"] = MbedTlsSession::create;
    registry_["openssl"] = OpenSslSession::create;
}

auto SessionFactory::create(std::string const& name,
                            HttpVersion version, ProxyRegistry const& proxyRegistry) -> SessionPtr
{
    auto& registry = SessionFactory::instance().registry_;

    if (auto const iter = registry.find(name); iter != std::end(registry)) {
        return iter->second(version, proxyRegistry);
    }
    return nullptr;
}