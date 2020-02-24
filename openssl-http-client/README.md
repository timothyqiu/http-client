# HTTP Client via OpenSSL

Sample command to build with OpenSSL installed via Homebrew:

    OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1/ cmake -S . -B /path/to/build-dir
    cmake --build /path/to/build-dir

Note: Getting the following link error means that you're linking against the system OpenSSL library. Likely that you are adding the `OPENSSL_ROOT_DIR` after a failed attempt. Clean up `/path/to/build-dir` and try again.

    ld: cannot link directly with dylib/framework, your binary is not an allowed client of /usr/lib/libcrypto.dylib for architecture x86_64

The `client` binary now supports setting basic HTTP proxy via the `http_proxy` environment variable:

    http_proxy=localhost:8080 /path/to/client

## HTTP 1.0

* One connection per request.
* No request header is mandatory.
* Response should have a `Content-Length` header if the entity body exists.
  * Missing `Content-Length` header means 0.
  * `HEAD` has no body, its `Content-Length` is the body size of a corresponding `GET` request.
* HTTP Proxy
  * Connect to proxy server instead of the target server.
  * In the request line, use absolute URL instead of relative path.
