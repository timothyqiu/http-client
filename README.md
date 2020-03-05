# Demo HTTP Client

Attempt to implement an HTTP client in two ways: one via OpenSSL, one via MbedTLS.

## Build

Build the project with [CMake](https://cmake.org/) and [Conan](https://conan.io/).

    # Install dependencies via Conan
    $ conan install -if /path/to/build-dir .

    # Configure the project via CMake
    $ cmake -B /path/to/build-dir -S .

    # Build the project
    $ cmake --build /path/to/build-dir

I used to install dependencies with CMake's [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) module. It works fine, but it's a pain to use in mainland China, as HTTPS connections to GitHub are often throttled. I have to wait for several minutes to make a fresh build. Libraries that's not modern-cmake compatible can't be installed like this anyway. So a package manager seems necessary.

## Run

The `client` binary uses similar options to `curl`.

    https_proxy=localhost:8080 /path/to/client -L https://httpbin.org/redirect/2

OpenSSL and MbedTLS can be selected with the `--driver` option. Use `-h` to see the complete option list.

To run tests:

    cmake --build /path/to/build-dir --target test

Currently, there are tests tagged `[network-required]` and `[proxy-required]` which needs special environment setup.

## Notes

### HTTP 1.0

* One connection per request.
* There are only three methods: `HEAD`, `GET`, `POST`.
* No request header is mandatory.
* Response should have a `Content-Length` header if the entity body exists.
  * Missing `Content-Length` header means 0.
  * `HEAD` has no body, its `Content-Length` is the body size of a corresponding `GET` request.

### HTTP 1.1

* Allows multiple requests per connection.
* `Host` header is mandatory.
* The client must support "chunked" transfer encoding, an alternative way to determine the content length.

### Proxy

Envionment variables `http_proxy`, `https_proxy` are usually used to specifiy proxies.

The content of the environment variables is the URL `[protocol://]host[:port]`, some applications require the `protocol://` part, some defaults it to `http://`. The protocol part determines how to connect to the proxy server.

After connecting to the proxy server:

* To visit a HTTP URL: Do a normal request, but in the request line, use absolute URL instead of relative path.
* To visit a HTTPS site:
  * Issue a `CONNECT` request, the request URI in the request line should be the target server host and port.
    * The `Host` header should use the proxy server host, because this `CONNECT` request itself is sent to the proxy server.
  * Then, do normal HTTPS requests on the established connection (handshake first, then send requests etc...).
