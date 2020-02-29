#ifndef OHC_BIO_HPP_
#define OHC_BIO_HPP_

#include <openssl/bio.h>

#include <ohc/buffer.hpp>

class BioBuffer : public Buffer {
public:
    // not owning
    explicit BioBuffer(BIO *bio);

    virtual void fetch() override;

private:
    BIO *bio_;
};

void writeString(BIO *bio, std::string_view data);

#endif  // OHC_BIO_HPP_
