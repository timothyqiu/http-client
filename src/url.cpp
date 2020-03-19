#include <ohc/url.hpp>

#include <algorithm>

#include <ohc/exceptions.hpp>
#include "utils.hpp"

// TODO: some optimization? use static object?
static auto portFromScheme(std::string_view scheme) -> std::string
{
    if (scheme == "http") {
        return "80";
    }
    if (scheme == "https") {
        return "443";
    }
    return "";  // not recognized
}

Url::Url(std::string_view view)
    : Url{view, ""}
{
}

Url::Url(std::string_view view, std::string_view defaultScheme)
{
    if (auto const n = view.find("://"); n != std::string_view::npos) {
        this->scheme({view.data(), n});

        auto const offset = n + 3;
        view = std::string_view{view.data() + offset, view.size() - offset};
    } else {
        this->scheme(defaultScheme);
    }

    {
        size_t endOfNetloc = view.size();
        for (auto const c : "/?#") {
            endOfNetloc = std::min(endOfNetloc, view.find(c));
        }

        // netloc(userinfo@host:port)
        std::string_view netloc{view.data(), endOfNetloc};

        if (auto const n = netloc.find('@'); n != netloc.npos) {
            this->userinfo = std::string{netloc.data(), n};
            netloc = std::string_view{netloc.data() + (n + 1), netloc.size() - (n + 1)};
        }

        if (auto const n = netloc.find(':'); n != netloc.npos) {
            this->host = std::string{netloc.data(), n};
            this->port = std::string{netloc.data() + (n + 1), netloc.size() - (n + 1)};
        } else {
            this->host = netloc;
        }

        view = std::string_view{view.data() + endOfNetloc, view.size() - endOfNetloc};
    }

    if (this->port.empty()) {
        this->port = portFromScheme(scheme_);
    }

    if (auto const n = view.find('#'); n != std::string_view::npos) {
        this->fragment = std::string{view.data() + (n + 1), view.size() - (n + 1)};
        view = std::string_view{view.data(), n};
    }

    if (auto const n = view.find('?'); n != std::string_view::npos) {
        this->query = std::string{view.data() + (n + 1), view.size() - (n + 1)};
        view = std::string_view{view.data(), n};
    }

    this->path = view.empty() ? "/" : view;
}

Url::Url(std::string_view view, Url const& baseUrl)
    : Url{view}
{
    if (scheme_.empty() && userinfo.empty() && host.empty() && port.empty()) {
        scheme_ = baseUrl.scheme_;
        this->userinfo = baseUrl.userinfo;
        this->host = baseUrl.host;
        this->port = baseUrl.port;
    }
}

void Url::scheme(std::string_view value)
{
    scheme_ = ohc::utils::toLower(value);
}

auto Url::authority() const -> std::string
{
    if (port.empty()) {
        return host;
    }
    return host + ":" + port;
}

auto Url::toRelativeString(bool allowFragment) const -> std::string
{
    auto const withoutFragment = (this->path.empty() ? "/" : this->path)
        + (this->query.empty() ? "" : "?" + this->query);

    if (!allowFragment) {
        return withoutFragment;
    }
    return withoutFragment + (this->fragment.empty() ? "" : "#" + this->fragment);
}

auto Url::toAbsoluteString(bool allowFragment) const -> std::string
{
    if (this->scheme().empty()) {
        throw OhcException{"missing scheme"};
    }

    auto const withoutFragment = this->scheme() + "://"
        + (this->userinfo.empty() ? "" : this->userinfo + "@")
        + this->host
        + (this->port.empty() || this->port == portFromScheme(this->scheme()) ? "" : ":" + this->port)
        + (this->path.empty() ? "/" : this->path)
        + (this->query.empty() ? "" : "?" + this->query);

    if (!allowFragment) {
        return withoutFragment;
    }
    return withoutFragment + (this->fragment.empty() ? "" : "#" + this->fragment);
}
