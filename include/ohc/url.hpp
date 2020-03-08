#ifndef OHC_URL_HPP_
#define OHC_URL_HPP_

#include <string>
#include <string_view>

struct Url {
    std::string scheme;  // always lower case
    std::string userinfo;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    std::string fragment;

    auto authority() const -> std::string;  // without userinfo

    bool isRelative() const;
};

auto parseUrl(std::string_view view, std::string_view defaultScheme={}) -> Url;

// relative to root
auto relativeUrlString(Url const& url, bool allowFragment=false) -> std::string;

auto absoluteUrlString(Url const& url, bool allowFragment=false) -> std::string;

#endif  // OHC_URL_HPP_
