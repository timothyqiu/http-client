#ifndef OHC_UTILS_HPP_
#define OHC_UTILS_HPP_

#include <string>
#include <string_view>

namespace ohc::utils {

auto toLower(std::string_view view) -> std::string;
auto toUpper(std::string_view view) -> std::string;

auto base64Encode(std::string_view view) -> std::string;

}  // namespace ohc::utils

#endif  // OHC_UTILS_HPP_
