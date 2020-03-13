#ifndef OHC_URL_HPP_
#define OHC_URL_HPP_

#include <string>
#include <string_view>

class Url {
public:
    // TODO: these fields have no strong restrictions applied currently
    std::string userinfo;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    std::string fragment;

public:
    Url() = default;

    explicit Url(std::string_view view);

    // set the default scheme if not provided
    Url(std::string_view view, std::string_view defaultScheme);

    // view should be an absolute path, or a url string
    Url(std::string_view view, Url const& baseUrl);

    auto operator==(Url const& rhs) const -> bool {
        return scheme_ == rhs.scheme_ && this->userinfo == rhs.userinfo
            && this->host == rhs.host && this->port == rhs.port
            && this->path == rhs.path && this->query == rhs.query
            && this->fragment == rhs.fragment;
    }

    auto scheme() const -> std::string const& { return scheme_; }
    void scheme(std::string_view value);

    // host[:port]
    auto authority() const -> std::string;

    auto toRelativeString(bool allowFragment=false) const -> std::string;
    auto toAbsoluteString(bool allowFragment=false) const -> std::string;

private:
    std::string scheme_;
};

#endif  // OHC_URL_HPP_
