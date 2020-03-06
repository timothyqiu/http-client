#ifndef OHC_SESSION_CONFIG_HPP_
#define OHC_SESSION_CONFIG_HPP_

#include <optional>
#include <string>
#include <string_view>
#include <ohc/http.hpp>
#include <ohc/url.hpp>

enum class TlsVersion {
    VERSION_1_0,
    VERSION_1_1,
    VERSION_1_2,
};

class SessionConfig {
public:
    class Builder;

    // Should be used when caCert and caPath are both empty.
    // Loading of defaults fails if both fail, while loading of custom paths fails if any fails.
    static auto defaultCaCert() -> std::string;
    static auto defaultCaPath() -> std::string;

    SessionConfig(HttpVersion httpVersion, TlsVersion minTlsVersion,
                  std::optional<std::string> caCert, std::optional<std::string> caPath,
                  std::optional<Url> httpProxy, std::optional<Url> httpsProxy,
                  bool insecure, bool proxyInsecure)
        : httpVersion_{httpVersion}, minTlsVersion_{minTlsVersion}
        , caCert_{caCert}, caPath_{caPath}
        , httpProxy_{httpProxy}, httpsProxy_{httpsProxy}
        , insecure_{insecure}, proxyInsecure_{proxyInsecure}
    {
    }

    auto httpVersion() const { return httpVersion_; }
    auto minTlsVersion() const { return minTlsVersion_; }
    auto caCert() const { return caCert_; }
    auto caPath() const { return caPath_; }
    auto httpProxy() const { return httpProxy_; }
    auto httpsProxy() const { return httpsProxy_; }
    auto insecure() const { return insecure_; }
    auto proxyInsecure() const { return insecure_; }

    auto useDefaultCa() const { return !caCert_ && !caPath_; }

private:
    HttpVersion httpVersion_;
    TlsVersion minTlsVersion_;
    std::optional<std::string> caCert_;
    std::optional<std::string> caPath_;
    std::optional<Url> httpProxy_;
    std::optional<Url> httpsProxy_;
    bool insecure_;
    bool proxyInsecure_;
};

class SessionConfig::Builder {
public:
    auto build() const {
        return SessionConfig{
            httpVersion_, minTlsVersion_,
            caCert_, caPath_,
            httpProxy_, httpsProxy_,
            insecure_, proxyInsecure_,
        };
    }

    auto httpVersion(HttpVersion value) -> Builder& { httpVersion_ = value; return *this; }
    auto minTlsVersion(TlsVersion value) -> Builder& { minTlsVersion_ = value; return *this; }
    auto caCert(std::string value) -> Builder& { caCert_ = std::move(value); return *this; }
    auto caPath(std::string value) -> Builder& { caPath_ = std::move(value); return *this; }
    auto httpProxy(std::string_view value) -> Builder& { httpProxy_ = parseUrl(value); return *this; }
    auto httpsProxy(std::string_view value) -> Builder& { httpsProxy_ = parseUrl(value); return *this; }
    auto insecure(bool value) -> Builder& { insecure_ = value; return *this; }
    auto proxyInsecure(bool value) -> Builder& { proxyInsecure_ = value; return *this; }

private:
    HttpVersion httpVersion_{HttpVersion::VERSION_1_1};
    TlsVersion minTlsVersion_{TlsVersion::VERSION_1_2};
    std::optional<std::string> caCert_;
    std::optional<std::string> caPath_;
    std::optional<Url> httpProxy_;
    std::optional<Url> httpsProxy_;
    bool insecure_;
    bool proxyInsecure_;
};

#endif  // OHC_SESSION_CONFIG_HPP_
