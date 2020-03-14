#include "utils.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <vector>

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

auto base64Encode(std::string_view view) -> std::string
{
    auto const *BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto const BASE64_PAD = '=';

    auto const n_orphan = view.size() % 3;
    auto const n_groups = view.size() / 3 + (n_orphan > 0 ? 1 : 0);

    std::vector<char> buffer(n_groups * 4);

    for (size_t i = 0; i < n_groups; i++) {
        auto const a_offset = i * 3 + 0;
        auto const a = a_offset < view.size() ? view[a_offset] : '\0';

        auto const b_offset = i * 3 + 1;
        auto const b = b_offset < view.size() ? view[b_offset] : '\0';

        auto const c_offset = i * 3 + 2;
        auto const c = c_offset < view.size() ? view[c_offset] : '\0';

        uint32_t const block = (a << 16 & 0xFF0000) |
                               (b <<  8 & 0x00FF00) |
                               (c <<  0 & 0x0000FF);
        auto const d_offset = i * 4;
        buffer[d_offset + 0] = BASE64_ALPHABET[(block & 0b11111100'00000000'00000000) >> 18];
        buffer[d_offset + 1] = BASE64_ALPHABET[(block & 0b00000011'11110000'00000000) >> 12];
        buffer[d_offset + 2] = BASE64_ALPHABET[(block & 0b00000000'00001111'11000000) >> 6];
        buffer[d_offset + 3] = BASE64_ALPHABET[(block & 0b00000000'00000000'00111111) >> 0];
    }

    if (n_orphan > 0) {
        for (size_t i = 0; i < (3 - n_orphan); i++) {
            buffer[buffer.size() - 1 - i] = BASE64_PAD;
        }
    }

    return std::string{std::begin(buffer), std::end(buffer)};
}

}  // namespace ohc
