#ifndef OHC_UTILS_HPP_
#define OHC_UTILS_HPP_

#include <string>
#include <string_view>

namespace ohc::utils {

std::string toLower(std::string_view view);
std::string toUpper(std::string_view view);

}  // namespace ohc

#endif  // OHC_UTILS_HPP_
