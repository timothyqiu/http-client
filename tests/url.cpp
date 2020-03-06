#include <catch2/catch.hpp>

#include <ohc/url.hpp>
#include <ohc/exceptions.hpp>

TEST_CASE("parseUrl should handle valid URLs", "[url]") {
    SECTION("complete URL") {
        auto const url = parseUrl("https://user:pass@httpbin.org:443/get?a=b&c=d#token");
        REQUIRE(url.scheme == "https");
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "443");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }
    SECTION("simple URL") {
        auto const url = parseUrl("http://localhost:8123/");
        REQUIRE(url.host == "localhost");
        REQUIRE(url.port == "8123");
    }
    SECTION("port from scheme") {
        REQUIRE(parseUrl("http://localhost/").port == "80");
        REQUIRE(parseUrl("https://localhost/").port == "443");
    }
}

TEST_CASE("parseUrl should handle bad URLs", "[url]") {
    SECTION("no path specified") {
        REQUIRE(parseUrl("https://httpbin.org").path == "/");
        REQUIRE(parseUrl("https://httpbin.org?a=b").path == "/");
        REQUIRE(parseUrl("https://httpbin.org#token").path == "/");
    }
    SECTION("allow omitting scheme") {
        auto const url = parseUrl("localhost");
        REQUIRE(url.scheme.empty());
        REQUIRE(url.userinfo.empty());
        REQUIRE(url.host == "localhost");
        REQUIRE(url.port.empty());
        REQUIRE(url.path == "/");
        REQUIRE(url.query.empty());
        REQUIRE(url.fragment.empty());
    }
}

TEST_CASE("parseUrl should use default scheme parameter", "[url]") {
    SECTION("no default scheme") {
        auto const url = parseUrl("localhost");
        REQUIRE(url.scheme.empty());
        REQUIRE(url.port.empty());
    }
    SECTION("default scheme") {
        auto const url = parseUrl("localhost", "http");
        REQUIRE(url.scheme == "http");
        REQUIRE(url.port == "80");
    }
    SECTION("default scheme won't affect port") {
        auto const url = parseUrl("localhost:443", "http");
        REQUIRE(url.scheme == "http");
        REQUIRE(url.port == "443");
    }
}

TEST_CASE("relativeUrlString should work", "[url]") {
    Url url;
    url.scheme = "http";
    url.host = "localhost";
    url.path = "/path";
    url.query = "a=b";

    SECTION("basics") {
        REQUIRE(relativeUrlString(url) == "/path?a=b");
    }

    SECTION("allow_fragment parameter") {
        url.fragment = "token";

        REQUIRE(relativeUrlString(url) == relativeUrlString(url, false));
        REQUIRE(relativeUrlString(url, false) == "/path?a=b");
        REQUIRE(relativeUrlString(url, true) == "/path?a=b#token");
    }

    SECTION("default path to / if ommitted") {
        url.path = "";
        REQUIRE(relativeUrlString(url) == "/?a=b");
    }
}

TEST_CASE("absoluteUrlString should work", "[url]") {
    Url url;
    url.scheme = "http";
    url.host = "localhost";
    url.path = "/path";
    url.query = "a=b";

    SECTION("basics") {
        REQUIRE(absoluteUrlString(url) == "http://localhost/path?a=b");
    }

    SECTION("allow_fragment parameter") {
        url.fragment = "token";

        REQUIRE(absoluteUrlString(url) == absoluteUrlString(url, false));
        REQUIRE(absoluteUrlString(url, false) == "http://localhost/path?a=b");
        REQUIRE(absoluteUrlString(url, true) == "http://localhost/path?a=b#token");
    }

    SECTION("default path to / if omitted") {
        url.path = "";
        REQUIRE(absoluteUrlString(url) == "http://localhost/?a=b");
    }

    SECTION("omit port if it matches scheme") {
        url.port = "80";
        REQUIRE(absoluteUrlString(url) == "http://localhost/path?a=b");

        url.port = "8080";
        REQUIRE(absoluteUrlString(url) == "http://localhost:8080/path?a=b");
    }

    SECTION("refuse it scheme not specified") {
        url.scheme = "";
        REQUIRE_THROWS_AS(absoluteUrlString(url), OhcException);
    }
}

TEST_CASE("url authority", "[url]") {
    Url url = parseUrl("http://localhost:8080/path?a=b#token");

    SECTION("normal case") {
        REQUIRE(url.authority() == "localhost:8080");
    }

    SECTION("without port") {
        url.port = "";
        REQUIRE(url.authority() == "localhost");
    }

    SECTION("should be without no userinfo") {
        url.userinfo = "user";
        REQUIRE(url.authority() == "localhost:8080");
    }
}

