#include <catch2/catch.hpp>

#include "../src/utils.hpp"
using namespace ohc::utils;

TEST_CASE("toLower toUpper", "[utils]") {
    REQUIRE(toLower("Content-Length") == "content-length");
    REQUIRE(toUpper("Patch") == "PATCH");
}
