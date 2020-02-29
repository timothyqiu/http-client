#ifndef OHC_BUFFER_HPP_
#define OHC_BUFFER_HPP_

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

class Buffer {
public:
    Buffer();

    size_t readableSize() const;
    std::string_view peekAsString() const;

    void dropLiteral(std::string_view literal);

    std::string_view readLine();  // CRLF
    std::vector<uint8_t> readAsVector(size_t size);

protected:
    // throws on error and eof
    // TODO: dedicated exception for eof
    virtual void fetch() = 0;

    uint8_t *getBuffer(size_t size);
    void markWritten(size_t size);

    std::string_view peekAsString(size_t size) const;

private:
    std::vector<uint8_t> buffer_;
    size_t write_;
    size_t read_;
};

#endif  // OHC_BUFFER_HPP_
