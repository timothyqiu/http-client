#ifndef APP_CONFIG_HPP_
#define APP_CONFIG_HPP_

#include <string>

#include <ohc/http.hpp>
#include <ohc/session_config.hpp>

struct Config
{
    std::string url;

    std::string driver{"openssl"};

    HttpVersion httpVersion{HttpVersion::VERSION_1_1};
    TlsVersion minTlsVersion{TlsVersion::VERSION_1_2};

    std::string httpProxy;
    std::string httpsProxy;

    std::string caCert;
    std::string caPath;

    bool insecure{false};
    bool proxyInsecure{false};

    bool isFollow{false};
    int maxRedirs{50};  // -1 means unlimited

    std::string auth;

    bool isVerbose{false};

    Config(int argc, char *argv[]);
};

#endif  // APP_CONFIG_HPP_
