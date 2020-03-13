#include <ohc/session.hpp>
#include <spdlog/spdlog.h>
#include <ohc/buffer.hpp>
#include <ohc/exceptions.hpp>

Session::Session(SessionConfig config)
    : config_{std::move(config)}
{
}

Session::~Session() = default;

auto Session::get(Url const& url) -> Response
{
    Request req;
    req.version = config_.httpVersion();
    req.method("GET");
    req.url = url;

    if (url.scheme() == "http") {
        req.proxy = config_.httpProxy();
    } else if (url.scheme() == "https") {
        req.proxy = config_.httpsProxy();
    }

    return this->request(req);
}

auto Session::request(Request const& req) -> Response
{
    if (!this->canReuseCurrentConnection(req)) {
        this->closeConnection();

        Url const authority = req.proxy ? *req.proxy : req.url;
        spdlog::info("Connecting to {}:{}", authority.host, authority.port);
        this->createConnection(authority.host, authority.port);
        this->setupHttps(req);

        serverIdentity_ = req.url;
    }

    Response resp;

    try {
        resp = this->makeRequest(req);
    }
    catch (std::exception const&) {
        // won't be able to consume the response
        this->closeConnection();
        throw;
    }

    switch (config_.httpVersion()) {
    case HttpVersion::VERSION_1_0:
        this->closeConnection();
        break;

    case HttpVersion::VERSION_1_1:
        if (auto const iter = resp.headers.find("connection"); iter != std::end(resp.headers)) {
            if (iter->second == "close") {
                this->closeConnection();
            }
        }
        break;
    }

    return resp;
}

bool Session::canReuseCurrentConnection(Request const& req) const
{
    // no current connection
    if (!this->isConnected()) {
        return false;
    }

    // connection should be closed after each request/response, not before
    if (config_.httpVersion() == HttpVersion::VERSION_1_0) {
        spdlog::warn("connection not closed after a http 1.0 request");
        return false;
    }

    // change of scheme
    if (serverIdentity_.scheme() != req.url.scheme()) {
        return false;
    }

    // once connected to a http proxy, always there
    if (req.url.scheme() == "http" && req.proxy) {
        return true;
    }

    return serverIdentity_.authority() == req.url.authority();
}

void Session::setupHttps(Request const& req)
{
    // proxy server setup
    if (req.proxy) {
        // the proxy server is using https
        if (req.proxy->scheme() == "https") {
            this->performHttpsPrologue(req.proxy->host, !config_.proxyInsecure());
        }

        // tunneling https connection
        if (req.url.scheme() == "https") {
            // HTTPS proxy CONNECT only available in 1.1
            Request proxyReq;
            proxyReq.version = HttpVersion::VERSION_1_1;
            proxyReq.method("CONNECT");
            proxyReq.url = *req.proxy;
            proxyReq.connectAuthority = req.url;

            auto const& resp = this->makeRequest(proxyReq);

            if (!resp.isSuccess()) {
                // TODO: make a dedicated exception?
                spdlog::error("Proxy server returned {} for CONNECT", resp.statusCode);
                throw OhcException{"proxy server refused"};
            }
        }
    }

    // target server is using https
    if (req.url.scheme() == "https") {
        this->performHttpsPrologue(req.url.host, !config_.insecure());
    }
}

auto Session::makeRequest(Request const& req) -> Response
{
    auto const& message = req.makeMessage();
    spdlog::debug("Sending request:\n{}<EOM>", message);

    auto const buffer = this->createBuffer();
    buffer->write(message.data(), message.size());
    return readResponseFromBuffer(req, *buffer);
}
