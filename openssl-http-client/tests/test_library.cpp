#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <ohc/url.hpp>

TEST_CASE("Valid URLs", "[url]") {
    SECTION("complete URL") {
        auto const url = parseUrl("https://user:pass@httpbin.org/get?a=b&c=d#token");
        REQUIRE(url.scheme == "https");
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "443");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }
}

TEST_CASE("http_proxy URL") {
    SECTION("complete URL") {
        auto const url = parseUrl("http://localhost:8123");
        REQUIRE(url.host == "localhost");
        REQUIRE(url.port == "8123");
    }
    SECTION("protocol omitted") {
        auto const url = parseUrl("localhost:8123");
        REQUIRE(url.host == "localhost");
        REQUIRE(url.port == "8123");
    }
}

TEST_CASE("Bad URLs", "[url]") {
    SECTION("path omitted") {
        REQUIRE(parseUrl("https://httpbin.org").path == "/");
        REQUIRE(parseUrl("https://httpbin.org?a=b").path == "/");
    }
}

TEST_CASE("Relative URL", "[url]") {
    REQUIRE(relativeUrlString(parseUrl("http://httpbin.org")) == "/");
    REQUIRE(relativeUrlString(parseUrl("http://httpbin.org/get?a=b")) == "/get?a=b");
}
