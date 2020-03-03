#include <catch2/catch.hpp>

#include <ohc/http.hpp>

TEST_CASE("Response::isSuccess", "[response]") {
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
