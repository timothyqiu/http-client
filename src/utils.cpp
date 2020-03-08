#include "utils.hpp"
#include <algorithm>
#include <cctype>

namespace ohc::utils {

auto toLower(std::string_view view) -> std::string
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::tolower(c); });
    return result;
}

auto toUpper(std::string_view view) -> std::string
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::toupper(c); });
    return result;
}

}  // namespace ohc
