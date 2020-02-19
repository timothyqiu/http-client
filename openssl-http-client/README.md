# HTTP Client via OpenSSL

Sample command to build with OpenSSL installed via Homebrew:

    OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1/ cmake -S . -B /path/to/build-dir
    cmake --build /path/to/build-dir

Note: Getting the following link error means that you're linking against the system OpenSSL library. Likely that you are adding the `OPENSSL_ROOT_DIR` after a failed attempt. Clean up `/path/to/build-dir` and try again.

    ld: cannot link directly with dylib/framework, your binary is not an allowed client of /usr/lib/libcrypto.dylib for architecture x86_64
