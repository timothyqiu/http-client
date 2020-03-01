#ifndef OHC_CLIENT_OPENSSL_HPP_
#define OHC_CLIENT_OPENSSL_HPP_

#include <stdexcept>
#include <openssl/bio.h>
#include <ohc/buffer.hpp>
#include <ohc/http.hpp>

class OpenSslError : public std::runtime_error {
public:
    explicit OpenSslError(char const *message);
};

class BioBuffer : public Buffer {
public:
    // not owning
    explicit BioBuffer(BIO *bio);

    virtual void fetch() override;

private:
    BIO *bio_;
};

// TODO: abstracts out BIO
Response makeRequest(BIO *bio, Request const& req);

#endif  // OHC_CLIENT_OPENSSL_HPP_
