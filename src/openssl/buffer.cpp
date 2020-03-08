#include "buffer.hpp"
#include <cassert>
#include <ohc/exceptions.hpp>
#include "exceptions.hpp"

BioBuffer::BioBuffer(BIO *bio)
    : bio_{bio}
{
    assert(bio_ != nullptr);
}

auto BioBuffer::push(uint8_t const *data, size_t size) -> size_t
{
    int const n = BIO_write(bio_, data, size);
    if (n < 1) {
        throw OpenSslError{"error writing data"};
    }
    return n;
}

void BioBuffer::pull()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = BIO_read(bio_, buffer, bufferSize);
    if (n < 1) {
        if (BIO_should_retry(bio_)) {
            this->pull();
            return;
        }
        if (n == 0) {
            throw EndOfStreamError{};
        }
        throw OpenSslError{"error reading data"};
    }
    this->markWritten(n);
}
