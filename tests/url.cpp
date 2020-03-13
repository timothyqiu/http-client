#include <catch2/catch.hpp>

#include <ohc/exceptions.hpp>
#include <ohc/url.hpp>

char const *RAW_URL = "https://user:pass@httpbin.org:44301/get?a=b&c=d#token";
char const *RAW_URL_WITHOUT_SCHEME = "user:pass@httpbin.org:44301/get?a=b&c=d#token";

TEST_CASE("Url/default-constructor", "[url]") {

    Url const url{};

    REQUIRE(url.scheme().empty());
    REQUIRE(url.userinfo.empty());
    REQUIRE(url.host.empty());
    REQUIRE(url.port.empty());
    REQUIRE(url.path.empty());
    REQUIRE(url.query.empty());
    REQUIRE(url.fragment.empty());

}

TEST_CASE("Url/string-constructor", "[url]") {

    SECTION("from complete string") {
        Url const url{RAW_URL};
        REQUIRE(url.scheme() == "https");
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "44301");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }

    SECTION("from string without scheme") {
        Url const url{RAW_URL_WITHOUT_SCHEME};
        REQUIRE(url.scheme().empty());
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "44301");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }

    SECTION("from string without port") {
        Url const url{"unknown://httpbin.org/"};
        REQUIRE(url.port.empty());
    }

    SECTION("from string without port, but scheme recognized") {
        Url const url{"http://httpbin.org/"};
        REQUIRE(url.port == "80");
    }

    SECTION("from string without path") {
        REQUIRE(Url{"https://httpbin.org"}.path == "/");
        REQUIRE(Url{"https://httpbin.org?a=b"}.path == "/");
        REQUIRE(Url{"https://httpbin.org#token"}.path == "/");
    }

}

TEST_CASE("Url/default-scheme-constructor", "[url]") {

    SECTION("from string with scheme") {
        Url const url{RAW_URL, "ftp"};
        REQUIRE(url.scheme() == "https");
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "44301");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }

    SECTION("from string without scheme") {
        Url const url{RAW_URL_WITHOUT_SCHEME, "http"};
        REQUIRE(url.scheme() == "http");
        REQUIRE(url.userinfo == "user:pass");
        REQUIRE(url.host == "httpbin.org");
        REQUIRE(url.port == "44301");
        REQUIRE(url.path == "/get");
        REQUIRE(url.query == "a=b&c=d");
        REQUIRE(url.fragment == "token");
    }

}

TEST_CASE("Url/relative-path-constructor", "[url]") {

    Url const base{"http://localhost/path?base=true#base-fragment"};

    SECTION("example") {
        Url const url{"/absolute/path?with=query#fragment", base};
        REQUIRE(url.scheme() == base.scheme());
        REQUIRE(url.userinfo == base.userinfo);
        REQUIRE(url.host == base.host);
        REQUIRE(url.port == base.port);
        REQUIRE(url.path == "/absolute/path");
        REQUIRE(url.query == "with=query");
        REQUIRE(url.fragment == "fragment");
    }

    SECTION("complete url") {
        char const *raw = "https://httpbin.org/get?with=query";
        REQUIRE(Url{raw, base} == Url{raw});
    }

}

TEST_CASE("Url/scheme", "[url]") {
    Url url;

    url.scheme("HeLlO");
    REQUIRE(url.scheme() == "hello");
}

TEST_CASE("Url/toRelativeString", "[url]") {
    Url url{"http://localhost/path?a=b"};

    SECTION("basics") {
        REQUIRE(url.toRelativeString() == "/path?a=b");
    }

    SECTION("allow_fragment parameter") {
        url.fragment = "token";

        REQUIRE(url.toRelativeString() == url.toRelativeString(false));
        REQUIRE(url.toRelativeString(false) == "/path?a=b");
        REQUIRE(url.toRelativeString(true) == "/path?a=b#token");
    }

    SECTION("default path to / if ommitted") {
        url.path = "";
        REQUIRE(url.toRelativeString() == "/?a=b");
    }
}

TEST_CASE("Url/toAbsoluteString", "[url]") {
    Url url{"http://localhost/path?a=b"};

    SECTION("basics") {
        REQUIRE(url.toAbsoluteString() == "http://localhost/path?a=b");
    }

    SECTION("allow_fragment parameter") {
        url.fragment = "token";

        REQUIRE(url.toAbsoluteString() == url.toAbsoluteString(false));
        REQUIRE(url.toAbsoluteString(false) == "http://localhost/path?a=b");
        REQUIRE(url.toAbsoluteString(true) == "http://localhost/path?a=b#token");
    }

    SECTION("default path to / if omitted") {
        url.path = "";
        REQUIRE(url.toAbsoluteString() == "http://localhost/?a=b");
    }

    SECTION("omit port if it matches scheme") {
        url.port = "80";
        REQUIRE(url.toAbsoluteString() == "http://localhost/path?a=b");

        url.port = "8080";
        REQUIRE(url.toAbsoluteString() == "http://localhost:8080/path?a=b");
    }

    SECTION("refuse it scheme not specified") {
        url.scheme("");
        REQUIRE_THROWS_AS(url.toAbsoluteString(), OhcException);
    }
}

TEST_CASE("url authority", "[url]") {
    Url url{"http://localhost:8080/path?a=b#token"};

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

