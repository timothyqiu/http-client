#include <ohc/session.hpp>
#include <spdlog/spdlog.h>

Session::Session(HttpVersion version, ProxyRegistry const& proxyRegistry,
                 bool insecure, bool proxyInsecure)
    : version_{version}, proxyRegistry_{proxyRegistry}
    , insecure_{insecure}, proxyInsecure_{proxyInsecure}
{
}

Session::~Session() = default;

Response Session::get(Url const& url)
{
    Request req;
    req.version = version_;
    req.method("GET");
    req.url = url;
    req.proxy = proxyRegistry_.get(url.scheme);

    return this->request(req);
}

Response Session::request(Request const& req)
{
    if (!this->canReuseCurrentConnection(req)) {
        this->closeConnection();
        this->createConnection(req);
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

    switch (version_) {
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
    if (this->version() == HttpVersion::VERSION_1_0) {
        spdlog::warn("connection not closed after a http 1.0 request");
        return false;
    }

    // change of scheme
    if (serverIdentity_.scheme != req.url.scheme) {
        return false;
    }

    // once connected to a http proxy, always there
    if (req.url.scheme == "http" && req.proxy) {
        return true;
    }

    return serverIdentity_.authority() == req.url.authority();
}

void Session::setupHttps(Request const& req)
{
    // proxy server setup
    if (req.proxy) {
        // the proxy server is using https
        if (req.proxy->scheme == "https") {
            this->performHttpsPrologue(req.proxy->host, !this->proxyInsecure());
        }

        // tunneling https connection
        if (req.url.scheme == "https") {
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
                throw std::runtime_error{"proxy server refused"};
            }
        }
    }

    // target server is using https
    if (req.url.scheme == "https") {
        this->performHttpsPrologue(req.url.host, !this->insecure());
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
