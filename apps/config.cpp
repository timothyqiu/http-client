#include "config.hpp"

#include <cstdlib>

#include <CLI/CLI.hpp>

Config::Config(int argc, char *argv[])
{
    CLI::App app{"Http Client Demo"};

    app.add_option("url", url, "Target URL")
        ->required();

    app.add_set("--driver", driver, {"openssl", "mbedtls"})
        ->default_val(driver);

    app.add_flag_callback("--http1.0", [&](){ httpVersion = HttpVersion::VERSION_1_0; }, "Uses HTTP 1.0");
    app.add_flag_callback("--http1.1", [&](){ httpVersion = HttpVersion::VERSION_1_1; }, "Uses HTTP 1.1");

    app.add_flag_callback("--tlsv1.0", [&](){ minTlsVersion = TlsVersion::VERSION_1_0; }, "Use TLSv1.0 or greater");
    app.add_flag_callback("--tlsv1.1", [&](){ minTlsVersion = TlsVersion::VERSION_1_1; }, "Use TLSv1.1 or greater");
    app.add_flag_callback("--tlsv1.2", [&](){ minTlsVersion = TlsVersion::VERSION_1_2; }, "Use TLSv1.2 or greater");

    app.add_option("--http-proxy", httpProxy, "The proxy server to use for HTTP")
        ->envname("http_proxy");
    app.add_option("--https-proxy", httpsProxy, "The proxy server to use for HTTPS")
        ->envname("https_proxy");

    app.add_option("--cacert", caCert, "CA certificate to verify peer against")
        ->check(CLI::ExistingFile);
    app.add_option("--capath", caPath, "CA directory to verify peer against")
        ->check(CLI::ExistingDirectory);

    app.add_flag("-k,--insecure", insecure, "Allow insecure server connections when using SSL")
        ->default_val(insecure);
    app.add_flag("--proxy-insecure", proxyInsecure, "Do HTTPS proxy connections without verifying the proxy")
        ->default_val(proxyInsecure);

    app.add_flag("-L,--location", isFollow, "Follow redirects");
    app.add_option("--max-redirs", maxRedirs, "Maximum number of redirects allowed");

    app.add_option("--auth", auth, "Basic HTTP auth credentials");

    app.add_flag("--verbose", isVerbose, "Make the operation more talkative");

    try {
        app.parse(argc, argv);
    }
    catch (CLI::ParseError const& e) {
        std::exit(app.exit(e));
    }
}
