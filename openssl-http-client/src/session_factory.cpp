#include <ohc/session_factory.hpp>

SessionFactory& SessionFactory::instance()
{
    static SessionFactory instance;
    return instance;
}

SessionFactory::SessionFactory() = default;

bool SessionFactory::registerCreator(std::string const& name, CreatorFunc func)
{
    auto& registry = SessionFactory::instance().registry_;

    if (auto const iter = registry.find(name); iter != std::end(registry)) {
        return false;
    }
    registry[name] = func;
    return true;
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
