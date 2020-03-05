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

    std::string authority() const;  // without userinfo

    bool isRelative() const;
};

Url parseUrl(std::string_view view, std::string_view defaultScheme={});

// relative to root
std::string relativeUrlString(Url const& url, bool allowFragment=false);

std::string absoluteUrlString(Url const& url, bool allowFragment=false);

#endif  // OHC_URL_HPP_
