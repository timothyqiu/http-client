#ifndef APPS_OPENSSL_BUFER_HPP_
#define APPS_OPENSSL_BUFER_HPP_

#include <cstddef>
#include <cstdint>

#include <ohc/buffer.hpp>
#include <openssl/bio.h>

class BioBuffer : public Buffer {
public:
    // not owning
    explicit BioBuffer(BIO *bio);

    auto push(uint8_t const *data, size_t size) -> size_t override;
    void pull() override;

private:
    BIO *bio_;
};

#endif  // APPS_OPENSSL_BUFER_HPP_
