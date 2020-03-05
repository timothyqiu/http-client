#ifndef OHC_BUFFER_HPP_
#define OHC_BUFFER_HPP_

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

class Buffer {
public:
    Buffer();
    virtual ~Buffer() = default;

    void write(void const *data, size_t size);

    auto peekAsString() const -> std::string_view;

    void dropLiteral(std::string_view literal);

    auto readLine() -> std::string_view;  // CRLF
    auto readAsVector(size_t size) -> std::vector<uint8_t>;

protected:
    // throws on error
    virtual auto push(uint8_t const *data, size_t size) -> size_t = 0;

    // throws on error and eof
    // TODO: dedicated exception for eof
    virtual void pull() = 0;

    auto getBuffer(size_t size) -> uint8_t *;
    void markWritten(size_t size);

    auto readableSize() const -> size_t;
    auto peekAsString(size_t size) const -> std::string_view;

private:
    std::vector<uint8_t> buffer_;
    size_t write_;
    size_t read_;
};

#endif  // OHC_BUFFER_HPP_
