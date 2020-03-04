# Demo HTTP Client

Attempt to implement an HTTP client in two ways: one via OpenSSL, one via MbedTLS.

OpenSSL and MbedTLS should be installed separately on the build machine. Other dependencies of the project will be downloaded by CMake.

Sample command to build with OpenSSL installed via Homebrew:

    OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1/ cmake -S . -B /path/to/build-dir
    cmake --build /path/to/build-dir

Note: Getting the following link error means that you're linking against the system OpenSSL library. Likely that you are adding the `OPENSSL_ROOT_DIR` after a failed attempt. Clean up `/path/to/build-dir` and try again.

    ld: cannot link directly with dylib/framework, your binary is not an allowed client of /usr/lib/libcrypto.dylib for architecture x86_64

The `client` binary now supports setting basic proxy via the `http_proxy` and `https_proxy` environment variables:

    https_proxy=localhost:8080 /path/to/client https://httpbin.org/ip

## HTTP 1.0

* One connection per request.
* There are only three methods: `HEAD`, `GET`, `POST`.
* No request header is mandatory.
* Response should have a `Content-Length` header if the entity body exists.
  * Missing `Content-Length` header means 0.
  * `HEAD` has no body, its `Content-Length` is the body size of a corresponding `GET` request.

## HTTP 1.1

* Allows multiple requests per connection.
* `Host` header is mandatory.
* The client must support "chunked" transfer encoding, an alternative way to determine the content length.

## Proxy

Envionment variables `http_proxy`, `https_proxy` are usually used to specifiy proxies.

The content of the environment variables is the URL `[protocol://]host[:port]`, some applications require the `protocol://` part, some defaults it to `http://`. The protocol part determines how to connect to the proxy server.

After connecting to the proxy server:

* To visit a HTTP URL: Do a normal request, but in the request line, use absolute URL instead of relative path.
* To visit a HTTPS site:
  * Issue a `CONNECT` request, the request URI in the request line should be the target server host and port.
    * The `Host` header should use the proxy server host, because this `CONNECT` request itself is sent to the proxy server.
  * Then, do normal HTTPS requests on the established connection (handshake first, then send requests etc...).
