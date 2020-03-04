#ifndef APPS_OPENSSL_CORE_HPP_
#define APPS_OPENSSL_CORE_HPP_

#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>

struct BioDeleter { void operator()(BIO *bio) { BIO_free_all(bio); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct SslCtxDeleter { void operator()(SSL_CTX *ctx) { SSL_CTX_free(ctx); } };
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

#endif  // APPS_OPENSSL_CORE_HPP_
