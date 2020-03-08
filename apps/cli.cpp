#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <ohc/exceptions.hpp>
#include <ohc/http.hpp>
#include <ohc/session.hpp>
#include <ohc/session_config.hpp>
#include <ohc/session_factory.hpp>
#include <ohc/url.hpp>

int main(int argc, char *argv[])
try {
    CLI::App app{"HTTP Client via OpenSSL"};

    std::string url;
    app.add_option("url", url, "Target URL")->required();

    std::string driver{"openssl"};
    app.add_set("--driver", driver, {"openssl", "mbedtls"});

    HttpVersion httpVersion{HttpVersion::VERSION_1_1};
    app.add_flag_callback("--http1.0", [&](){ httpVersion = HttpVersion::VERSION_1_0; }, "Uses HTTP 1.0");
    app.add_flag_callback("--http1.1", [&](){ httpVersion = HttpVersion::VERSION_1_1; }, "Uses HTTP 1.1");

    TlsVersion minTlsVersion{TlsVersion::VERSION_1_2};
    app.add_flag_callback("--tlsv1.0", [&](){ minTlsVersion = TlsVersion::VERSION_1_0; }, "Use TLSv1.0 or greater");
    app.add_flag_callback("--tlsv1.1", [&](){ minTlsVersion = TlsVersion::VERSION_1_1; }, "Use TLSv1.1 or greater");
    app.add_flag_callback("--tlsv1.2", [&](){ minTlsVersion = TlsVersion::VERSION_1_2; }, "Use TLSv1.2 or greater");

    std::string httpProxy;
    app.add_option("--http-proxy", httpProxy, "The proxy server to use for HTTP")->envname("http_proxy");
    std::string httpsProxy;
    app.add_option("--https-proxy", httpsProxy, "The proxy server to use for HTTPS")->envname("https_proxy");

    std::string caCert;
    std::string caPath;
    app.add_option("--cacert", caCert, "CA certificate to verify peer against")->check(CLI::ExistingFile);
    app.add_option("--capath", caPath, "CA directory to verify peer against")->check(CLI::ExistingDirectory);

    bool insecure{false};
    bool proxyInsecure{false};
    app.add_flag("-k,--insecure", insecure, "Allow insecure server connections when using SSL");
    app.add_flag("--proxy-insecure", proxyInsecure, "Do HTTPS proxy connections without verifying the proxy");

    bool isFollow{false};
    app.add_flag("-L,--location", isFollow, "Follow redirects");

    bool isVerbose{false};
    app.add_flag("--verbose", isVerbose, "Make the operation more talkative");

    CLI11_PARSE(app, argc, argv);

    // Preparation done

    spdlog::set_level(isVerbose ? spdlog::level::debug : spdlog::level::warn);

    auto configBuilder = SessionConfig::Builder()
        .httpVersion(httpVersion)
        .minTlsVersion(minTlsVersion)
        .insecure(insecure)
        .proxyInsecure(proxyInsecure);

    if (!caCert.empty()) {
        configBuilder.caCert(caCert);
    }
    if (!caPath.empty()) {
        configBuilder.caPath(caPath);
    }
    if (!httpProxy.empty()) {
        configBuilder.httpProxy(httpProxy);
    }
    if (!httpsProxy.empty()) {
        configBuilder.httpsProxy(httpsProxy);
    }

    auto session = SessionFactory::create(driver, configBuilder.build());
    if (!session) {
        throw std::runtime_error{"no such driver: " + driver};
    }

    Url requestUrl = parseUrl(url, "http");
    while (true) {
        auto const resp = session->get(requestUrl);

        // TODO: move these to session
        if (isFollow && (resp.statusCode == 301 || resp.statusCode == 302 || resp.statusCode == 303)) {
            // TODO: don't redirect if non-GET
            auto const location = resp.headers.at("location");
            spdlog::debug("Redirect to: {}", location);
            auto next = parseUrl(location);
            if (next.isRelative()) {
                next.scheme = requestUrl.scheme;
                next.userinfo = requestUrl.userinfo;
                next.host = requestUrl.host;
                next.port = requestUrl.port;
            }
            requestUrl = next;
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
