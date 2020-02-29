#include <ohc/bio.hpp>

#include <cassert>
#include <stdexcept>

#include <ohc/exception.hpp>

BioBuffer::BioBuffer(BIO *bio)
    : bio_{bio}
{
    assert(bio_ != nullptr);
}

void BioBuffer::fetch()
{
    // make sure space available
    size_t const bufferSize = 256;  // this is a relative small amount, for better testing
    uint8_t *buffer = this->getBuffer(bufferSize);

    int const n = BIO_read(bio_, buffer, bufferSize);
    if (n < 1) {
        if (BIO_should_retry(bio_)) {
            this->fetch();
            return;
        }
        if (n == 0) {
            throw std::runtime_error{"end of stream reached"};
        }
        throw OpenSslError{"error reading data"};
    }
    this->markWritten(n);
}

void writeString(BIO *bio, std::string_view data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        int const n = BIO_write(bio, data.data() + sent, data.size() - sent);
        if (n < 1) {
            throw OpenSslError{"error writing data"};
        }
        sent += n;
    }
}
