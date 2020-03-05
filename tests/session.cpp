#include <catch2/catch.hpp>

#include <ohc/session_factory.hpp>

TEST_CASE("direct request", "[session][network-required]") {
    auto session = SessionFactory::create(
        GENERATE("openssl", "mbedtls"),
        GENERATE(HttpVersion::VERSION_1_0, HttpVersion::VERSION_1_1),
        {});

    SECTION("http get") {
        auto const& resp = session->get(parseUrl("http://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }

    SECTION("https get") {
        auto const& resp = session->get(parseUrl("https://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }
}

TEST_CASE("http proxy request", "[session][network-required][proxy-required]") {
    ProxyRegistry proxy;
    proxy.set("http", parseUrl("http://127.0.0.1:8123/"));
    auto session = SessionFactory::create(
        GENERATE("openssl", "mbedtls"),
        GENERATE(HttpVersion::VERSION_1_0, HttpVersion::VERSION_1_1),
        proxy);

    SECTION("http get") {
        auto const& resp = session->get(parseUrl("http://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }

    SECTION("https get") {
        auto const& resp = session->get(parseUrl("https://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }
}

TEST_CASE("https proxy request", "[session][network-required][proxy-required]") {
    ProxyRegistry proxy;
    proxy.set("https", parseUrl("http://127.0.0.1:8123/"));
    auto session = SessionFactory::create(
        GENERATE("openssl", "mbedtls"),
        GENERATE(HttpVersion::VERSION_1_0, HttpVersion::VERSION_1_1),
        proxy);

    SECTION("http get") {
        auto const& resp = session->get(parseUrl("http://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }

    SECTION("https get") {
        auto const& resp = session->get(parseUrl("https://httpbin.org/get"));
        REQUIRE(resp.statusCode == 200);
    }
}
