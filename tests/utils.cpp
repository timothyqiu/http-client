#include <catch2/catch.hpp>

#include "../src/utils.hpp"
using namespace ohc::utils;

TEST_CASE("toLower", "[utils]") {
    REQUIRE(toLower("Content-Length") == "content-length");
}

TEST_CASE("toUpper", "[utils]") {
    REQUIRE(toUpper("Patch") == "PATCH");
}

TEST_CASE("base64Encode", "[utils]") {
    REQUIRE(base64Encode("") == "");
    REQUIRE(base64Encode("f") == "Zg==");
    REQUIRE(base64Encode("fo") == "Zm8=");
    REQUIRE(base64Encode("foo") == "Zm9v");
    REQUIRE(base64Encode("foob") == "Zm9vYg==");
    REQUIRE(base64Encode("fooba") == "Zm9vYmE=");
    REQUIRE(base64Encode("foobar") == "Zm9vYmFy");
}
