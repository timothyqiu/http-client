#include <ohc/url.hpp>

#include <algorithm>
#include <cctype>
#include <stdexcept>

Url parseUrl(std::string_view view)
{
    Url url;

    if (auto const n = view.find("://"); n != view.npos) {
        url.scheme = std::string{view.data(), n};
        std::transform(std::begin(url.scheme), std::end(url.scheme),
                       std::begin(url.scheme),
                       [](char c) { return std::tolower(c); });

        auto const offset = n + 3;
        view = std::string_view{view.data() + offset, view.size() - offset};
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
        if (url.scheme == "https") {
            url.port = "443";
        } else if (url.scheme == "http") {
            url.port = "80";
        }
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

std::string relativeUrlString(Url const& url)
{
    auto const& query = url.query.empty() ? "" : "?" + url.query;
    return url.path + query;
}
