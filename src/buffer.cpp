#include <ohc/buffer.hpp>
#include <algorithm>
#include <cassert>
#include <ohc/exceptions.hpp>

Buffer::Buffer()
    : write_{0} , read_{0}
{
}

void Buffer::write(void const *data, size_t size)
{
    size_t sent = 0;
    while (sent < size) {
        sent += this->push(static_cast<uint8_t const *>(data) + sent, size - sent);
    }
}

auto Buffer::getBuffer(size_t size) -> uint8_t *
{
    while (buffer_.size() < write_ + size) {
        buffer_.resize(std::max(buffer_.size() * 2, buffer_.size() + size));
    }
    return buffer_.data() + write_;
}

void Buffer::markWritten(size_t size)
{
    assert(write_ + size <= buffer_.size());
    write_ += size;
}

auto Buffer::readableSize() const -> size_t
{
    assert(read_ <= write_);
    return write_ - read_;
}

auto Buffer::peekAsString() const -> std::string_view
{
    return this->peekAsString(this->readableSize());
}

auto Buffer::peekAsString(size_t size) const -> std::string_view
{
    assert(size <= this->readableSize());
    return {
        reinterpret_cast<char const *>(buffer_.data() + read_),
        size
    };
}

void Buffer::dropLiteral(std::string_view literal)
{
    while (this->readableSize() < literal.size()) {
        this->pull();
    }

    auto const actual = this->peekAsString(literal.size());
    if (actual != literal) {
        // TODO: a dedicated exception
        throw OhcException{"unexpected literal"};
    }
    read_ += literal.size();
}

auto Buffer::readLine() -> std::string_view
{
    std::string_view const eol{"\r\n"};
    while (true) {
        auto const view = this->peekAsString();
        auto const n = view.find(eol);
        if (n == std::string_view::npos) {
            this->pull();
            continue;
        }
        read_ += n + eol.size();
        return {view.data(), n};
    }
}

auto Buffer::readAsVector(size_t size) -> std::vector<uint8_t>
{
    while (this->readableSize() < size) {
        this->pull();
    }
    std::vector<uint8_t> result{buffer_.data() + read_, buffer_.data() + read_ + size};
    read_ += size;
    return result;
}
