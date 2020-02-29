#include <ohc/url.hpp>

#include <algorithm>
#include <cctype>
#include <stdexcept>

std::string Url::authority() const
{
    if (port.empty()) {
        return host;
    }
    return host + ":" + port;
}

bool Url::isRelative() const
{
    return host.empty();
}

// TODO: some optimization? use static object?
static std::string portFromScheme(std::string_view scheme)
{
    if (scheme == "http") {
        return "80";
    }
    if (scheme == "https") {
        return "443";
    }
    return "";  // not recognized
}

Url parseUrl(std::string_view view, std::string_view defaultScheme)
{
    Url url;

    if (auto const n = view.find("://"); n != view.npos) {
        url.scheme = std::string{view.data(), n};
        std::transform(std::begin(url.scheme), std::end(url.scheme),
                       std::begin(url.scheme),
                       [](char c) { return std::tolower(c); });

        auto const offset = n + 3;
        view = std::string_view{view.data() + offset, view.size() - offset};
    } else {
        url.scheme = defaultScheme;
    }

    {
        size_t n = view.size();
        for (auto const c : "/?#") {
            n = std::min(n, view.find(c));
        }

        // netloc(userinfo@host:port)
        std::string_view netloc{view.data(), n};

        if (auto const n = netloc.find('@'); n != netloc.npos) {
            url.userinfo = std::string{netloc.data(), n};
            netloc = std::string_view{netloc.data() + (n + 1), netloc.size() - (n + 1)};
        }

        if (auto const n = netloc.find(':'); n != netloc.npos) {
            url.host = std::string{netloc.data(), n};
            url.port = std::string{netloc.data() + (n + 1), netloc.size() - (n + 1)};
        } else {
            url.host = netloc;
        }

        view = std::string_view{view.data() + n, view.size() - n};
    }

    if (url.port.empty()) {
        // url.port = url.scheme works as well
        // but to keep 'port is an integer' true...
        url.port = portFromScheme(url.scheme);
        // TODO: should port be left empty?
    }

    if (auto const n = view.find('#'); n != view.npos) {
        url.fragment = std::string{view.data() + (n + 1), view.size() - (n + 1)};
        view = std::string_view{view.data(), n};
    }

    if (auto const n = view.find('?'); n != view.npos) {
        url.query = std::string{view.data() + (n + 1), view.size() - (n + 1)};
        view = std::string_view{view.data(), n};
    }

    url.path = view.empty() ? "/" : view;

    return url;
}

std::string relativeUrlString(Url const& url, bool allowFragment)
{
    auto const& path = url.path.empty() ? "/" : url.path;
    auto const& query = url.query.empty() ? "" : "?" + url.query;
    auto const& fragment = !allowFragment || url.fragment.empty() ? "" : "#" + url.fragment;
    return path + query + fragment;
}

std::string absoluteUrlString(Url const& url, bool allowFragment)
{
    if (url.scheme.empty()) {
        throw std::runtime_error{"missing scheme"};
    }
    auto const& userinfo = url.userinfo.empty() ? "" : url.userinfo + "@";
    auto const& port = url.port.empty() || url.port == portFromScheme(url.scheme) ? "" : ":" + url.port;
    auto const& path = url.path.empty() ? "/" : url.path;
    auto const& query = url.query.empty() ? "" : "?" + url.query;
    auto const& fragment = !allowFragment || url.fragment.empty() ? "" : "#" + url.fragment;
    return url.scheme + "://" + userinfo + url.host + port + path + query + fragment;
}
