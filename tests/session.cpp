#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <ohc/exceptions.hpp>
#include <ohc/session.hpp>
#include <ohc/session_factory.hpp>

using json = nlohmann::json;

TEST_CASE("direct request", "[session][network-required]") {
    auto const config = SessionConfig::Builder{}.build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get(Url{"http://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get(Url{"https://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "https");
    }
}

TEST_CASE("http proxy request", "[session][network-required][proxy-required]") {
    auto const config = SessionConfig::Builder{}
        .httpProxy(Url{"http://127.0.0.1:8123/"})
        .build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get(Url{"http://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get(Url{"https://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "https");
    }
}

TEST_CASE("https proxy request", "[session][network-required][proxy-required]") {
    auto const config = SessionConfig::Builder{}
        .httpsProxy(Url{"http://127.0.0.1:8123/"})
        .build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get(Url{"http://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get(Url{"https://httpbin.org/get"});
        REQUIRE(resp.statusCode == 200);

        auto const& url = Url{json::parse(resp.body)["url"].get<std::string>()};
        REQUIRE(url.scheme() == "https");
    }
}

TEST_CASE("bad ssl", "[session][network-required]") {

    SECTION("no-insecure") {
        auto const config = SessionConfig::Builder{}.insecure(false).build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS_AS(session->get(Url{"https://expired.badssl.com/"}), OhcException);
        REQUIRE_THROWS_AS(session->get(Url{"https://wrong.host.badssl.com/"}), OhcException);
        REQUIRE_THROWS_AS(session->get(Url{"https://self-signed.badssl.com/"}), OhcException);
        REQUIRE_THROWS_AS(session->get(Url{"https://untrusted-root.badssl.com/"}), OhcException);
    }

    SECTION("insecure") {
        auto const config = SessionConfig::Builder{}.insecure(true).build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_NOTHROW(session->get(Url{"https://expired.badssl.com/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://wrong.host.badssl.com/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://self-signed.badssl.com/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://untrusted-root.badssl.com/"}));
    }
}

TEST_CASE("min TLS version", "[session][network-required]") {

    SECTION("1.0") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_0)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-0.badssl.com:1010/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-1.badssl.com:1011/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-2.badssl.com:1012/"}));
    }

    SECTION("1.1") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_1)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS_AS(session->get(Url{"https://tls-v1-0.badssl.com:1010/"}), OhcException);
        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-1.badssl.com:1011/"}));
        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-2.badssl.com:1012/"}));
    }

    SECTION("1.2") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_2)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS_AS(session->get(Url{"https://tls-v1-0.badssl.com:1010/"}), OhcException);
        REQUIRE_THROWS_AS(session->get(Url{"https://tls-v1-1.badssl.com:1011/"}), OhcException);
        REQUIRE_NOTHROW(session->get(Url{"https://tls-v1-2.badssl.com:1012/"}));
    }
}
