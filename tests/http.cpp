#include <catch2/catch.hpp>

#include <ohc/http.hpp>

TEST_CASE("Response/isSuccess", "[response]") {
    Response response;

    SECTION("info") {
        response.statusCode = GENERATE(100, 101, 102, 103);
        REQUIRE(response.isSuccess());
    }

    SECTION("success") {
        response.statusCode = GENERATE(200, 201, 204);
        REQUIRE(response.isSuccess());
    }

    SECTION("redirect") {
        response.statusCode = GENERATE(301, 303, 304);
        REQUIRE(response.isSuccess());
    }

    SECTION("client error") {
        response.statusCode = GENERATE(400, 401, 403, 422);
        REQUIRE(!response.isSuccess());
    }

    SECTION("server error") {
        response.statusCode = GENERATE(500, 502);
        REQUIRE(!response.isSuccess());
    }
}

TEST_CASE("Request/makeMessage", "[request]") {

    Request req;
    req.method("GET");
    req.url = Url{"http://localhost:8080/"};

    SECTION("1.0 request") {
        req.version = HttpVersion::VERSION_1_0;

        auto const expected = (
           "GET / HTTP/1.0\r\n"
           "\r\n"
        );
        REQUIRE(req.makeMessage() == expected);
    }

    SECTION("1.1 request") {
        req.version = HttpVersion::VERSION_1_1;

        auto const expected = (
           "GET / HTTP/1.1\r\n"
           "Host: localhost:8080\r\n"
           "\r\n"
        );
        REQUIRE(req.makeMessage() == expected);
    }
}
