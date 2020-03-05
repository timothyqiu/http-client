#include <ohc/buffer.hpp>
#include <algorithm>
#include <cassert>
#include <stdexcept>

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

uint8_t *Buffer::getBuffer(size_t size)
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

size_t Buffer::readableSize() const
{
    assert(read_ <= write_);
    return write_ - read_;
}

std::string_view Buffer::peekAsString() const
{
    return this->peekAsString(this->readableSize());
}

std::string_view Buffer::peekAsString(size_t size) const
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
        throw std::runtime_error{"unexpected literal"};
    }
    read_ += literal.size();
}

std::string_view Buffer::readLine()
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

std::vector<uint8_t> Buffer::readAsVector(size_t size)
{
    while (this->readableSize() < size) {
        this->pull();
    }
    std::vector<uint8_t> result{buffer_.data() + read_, buffer_.data() + read_ + size};
    read_ += size;
    return result;
}
