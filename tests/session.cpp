#include <catch2/catch.hpp>
#include <rapidjson/document.h>

#include <ohc/session_factory.hpp>

TEST_CASE("direct request", "[session][network-required]") {
    auto const config = SessionConfig::Builder{}.build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get("http://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get("https://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "https");
    }
}

TEST_CASE("http proxy request", "[session][network-required][proxy-required]") {
    auto const config = SessionConfig::Builder{}
        .httpProxy("http://127.0.0.1:8123/")
        .build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get("http://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get("https://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "https");
    }
}

TEST_CASE("https proxy request", "[session][network-required][proxy-required]") {
    auto const config = SessionConfig::Builder{}
        .httpsProxy("http://127.0.0.1:8123/")
        .build();
    auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
    REQUIRE(session);

    SECTION("http get") {
        auto const& resp = session->get("http://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "http");
    }

    SECTION("https get") {
        auto const& resp = session->get("https://httpbin.org/get");
        REQUIRE(resp.statusCode == 200);

        rapidjson::Document doc;
        doc.Parse(reinterpret_cast<char const *>(resp.body.data()), resp.body.size());

        auto const& url = parseUrl(doc["url"].GetString());
        REQUIRE(url.scheme == "https");
    }
}

TEST_CASE("bad ssl", "[session][network-required]") {

    SECTION("no-insecure") {
        auto const config = SessionConfig::Builder{}.insecure(false).build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS(session->get("https://expired.badssl.com/"));
        REQUIRE_THROWS(session->get("https://wrong.host.badssl.com/"));
        REQUIRE_THROWS(session->get("https://self-signed.badssl.com/"));
        REQUIRE_THROWS(session->get("https://untrusted-root.badssl.com/"));
    }

    SECTION("insecure") {
        auto const config = SessionConfig::Builder{}.insecure(true).build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_NOTHROW(session->get("https://expired.badssl.com/"));
        REQUIRE_NOTHROW(session->get("https://wrong.host.badssl.com/"));
        REQUIRE_NOTHROW(session->get("https://self-signed.badssl.com/"));
        REQUIRE_NOTHROW(session->get("https://untrusted-root.badssl.com/"));
    }
}

TEST_CASE("min TLS version", "[session][network-required]") {

    SECTION("1.0") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_0)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_NOTHROW(session->get("https://tls-v1-0.badssl.com:1010/"));
        REQUIRE_NOTHROW(session->get("https://tls-v1-1.badssl.com:1011/"));
        REQUIRE_NOTHROW(session->get("https://tls-v1-2.badssl.com:1012/"));
    }

    SECTION("1.1") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_1)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS(session->get("https://tls-v1-0.badssl.com:1010/"));
        REQUIRE_NOTHROW(session->get("https://tls-v1-1.badssl.com:1011/"));
        REQUIRE_NOTHROW(session->get("https://tls-v1-2.badssl.com:1012/"));
    }

    SECTION("1.2") {
        auto const config = SessionConfig::Builder{}
            .minTlsVersion(TlsVersion::VERSION_1_2)
            .build();
        auto session = SessionFactory::create(GENERATE("openssl", "mbedtls"), config);
        REQUIRE(session);

        REQUIRE_THROWS(session->get("https://tls-v1-0.badssl.com:1010/"));
        REQUIRE_THROWS(session->get("https://tls-v1-1.badssl.com:1011/"));
        REQUIRE_NOTHROW(session->get("https://tls-v1-2.badssl.com:1012/"));
    }
}
