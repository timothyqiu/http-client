#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

#include <spdlog/spdlog.h>

#include <ohc/exceptions.hpp>
#include <ohc/http.hpp>
#include <ohc/session.hpp>
#include <ohc/session_config.hpp>
#include <ohc/session_factory.hpp>
#include <ohc/url.hpp>

#include "config.hpp"

int main(int argc, char *argv[])
try {
    Config config{argc, argv};

    spdlog::set_level(config.isVerbose ? spdlog::level::debug : spdlog::level::warn);

    auto configBuilder = SessionConfig::Builder()
        .httpVersion(config.httpVersion)
        .minTlsVersion(config.minTlsVersion)
        .insecure(config.insecure)
        .proxyInsecure(config.proxyInsecure);

    if (!config.caCert.empty()) {
        configBuilder.caCert(config.caCert);
    }
    if (!config.caPath.empty()) {
        configBuilder.caPath(config.caPath);
    }
    if (!config.httpProxy.empty()) {
        configBuilder.httpProxy(Url{config.httpProxy, "http"});
    }
    if (!config.httpsProxy.empty()) {
        configBuilder.httpsProxy(Url{config.httpsProxy, "http"});
    }

    std::optional<Authentication> basicAuth;
    if (!config.auth.empty()) {
        auto const n = config.auth.find(':');
        if (n == std::string::npos) {
            throw std::runtime_error{"basic auth format should be `user:pass`"};
        }
        std::string_view user{config.auth.data(), n};
        std::string_view pass{config.auth.data() + n + 1, config.auth.size() - n - 1};
        basicAuth = Authentication{std::string{user}, std::string{pass}};
    }

    auto session = SessionFactory::create(config.driver, configBuilder.build());
    if (!session) {
        throw std::runtime_error{"no such driver: " + config.driver};
    }

    int numRedirected = 0;
    Url requestUrl{config.url, "http"};
    while (true) {
        auto const resp = session->get(requestUrl, basicAuth);

        // TODO: move these to session
        if (config.isFollow && (resp.statusCode == 301 || resp.statusCode == 302 || resp.statusCode == 303)) {
            // TODO: don't redirect if non-GET
            auto const location = resp.headers.at("location");
            spdlog::debug("Redirect to: {}", location);

            numRedirected++;
            if (config.maxRedirs != -1 && numRedirected > config.maxRedirs) {
                throw std::runtime_error{"too many redirects"};
            }

            requestUrl = Url{location, requestUrl};
            continue;
        }

        std::printf("Status: %d\n", resp.statusCode);
        std::printf("Headers:\n");
        for (auto const& e : resp.headers) {
            std::printf("\t%s = %s\n", e.first.c_str(), e.second.c_str());
        }
        std::printf("Body:\n%s", std::string{std::begin(resp.body), std::end(resp.body)}.c_str());

        break;
    }
}
catch (OhcException const& e) {
    spdlog::error("OhcException: {}", e.what());
    return EXIT_FAILURE;
}
catch (std::exception const& e) {
    spdlog::error("Exception: {}", e.what());
    return EXIT_FAILURE;
}
