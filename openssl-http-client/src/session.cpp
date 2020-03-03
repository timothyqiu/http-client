#include <ohc/session.hpp>

Session::Session(HttpVersion version, ProxyRegistry const& proxyRegistry,
                 bool insecure, bool proxyInsecure)
    : version_{version}, proxyRegistry_{proxyRegistry}
    , insecure_{insecure}, proxyInsecure_{proxyInsecure}
{
}

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
    this->setupConnection(req);

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
