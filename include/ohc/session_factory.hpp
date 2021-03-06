#ifndef OHC_SESSION_FACTORY_HPP_
#define OHC_SESSION_FACTORY_HPP_

#include <map>
#include <memory>

class Session;
class SessionConfig;

class SessionFactory {
public:
    using SessionPtr = std::unique_ptr<Session>;
    using CreatorFunc = SessionPtr(*)(SessionConfig const&);

    static auto create(std::string const& name, SessionConfig const& config) -> SessionPtr;

private:
    static SessionFactory& instance();

    std::map<std::string, CreatorFunc> registry_;

    SessionFactory();
};

#endif  // OHC_SESSION_FACTORY_HPP_
