#ifndef OHC_SESSION_FACTORY_HPP_
#define OHC_SESSION_FACTORY_HPP_

#include <map>
#include <memory>
#include <ohc/session.hpp>

class SessionFactory {
public:
    using SessionPtr = std::unique_ptr<Session>;
    using CreatorFunc = SessionPtr(*)(HttpVersion, ProxyRegistry const&);

    static auto create(std::string const& name,
                       HttpVersion version, ProxyRegistry const& proxyRegistry) -> SessionPtr;

private:
    static SessionFactory& instance();

    std::map<std::string, CreatorFunc> registry_;

    SessionFactory();
};

#endif  // OHC_SESSION_FACTORY_HPP_
