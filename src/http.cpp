#include <ohc/http.hpp>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <regex>

// TODO: should log be here?
#include <spdlog/spdlog.h>

static std::string toLower(std::string_view view)
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::tolower(c); });
    return result;
}

static std::string toUpper(std::string_view view)
{
    std::string result{view};
    std::transform(std::begin(result), std::end(result),
                   std::begin(result),
                   [](char c) { return std::toupper(c); });
    return result;
}

void ProxyRegistry::set(std::string_view scheme, Url const& url)
{
    assert(scheme == "http" || scheme == "https");

    if (url.scheme != "http" && url.scheme != "https") {
        throw std::runtime_error{std::string{scheme} + " proxy scheme not supported: " + std::string{url.scheme}};
    }
    if (url.host.empty()) {
        throw std::runtime_error{std::string{scheme} + " proxy missing host"};
    }
    if (url.port.empty()) {
        throw std::runtime_error{std::string{scheme} + " proxy missing port"};
    }

    servers[std::string{scheme}] = url;
}

std::optional<Url> ProxyRegistry::get(std::string_view scheme) const
{
    auto const iter = servers.find(std::string{scheme});
    if (iter == std::end(servers)) {
        return {};
    }
    return iter->second;
}

auto Request::method() const -> std::string_view
{
    return method_;
}

void Request::method(std::string_view value)
{
    method_ = toUpper(value);
}

std::string Request::makeRequestUri() const
{
    if (method_ == "CONNECT") {
        assert(!connectAuthority.host.empty() && !connectAuthority.port.empty());
        return connectAuthority.authority();
    }
    if (url.scheme == "http" && proxy) {
        return absoluteUrlString(url);
    }
    return relativeUrlString(url);
}

std::string Request::makeMessage() const
{
    std::string versionMark;
    std::string header;

    switch (version) {
    case HttpVersion::VERSION_1_0:
        versionMark = "HTTP/1.0";
        break;

    case HttpVersion::VERSION_1_1:
        versionMark = "HTTP/1.1";
        header = "Host: " + url.host + "\r\n";
        break;
    }

    return method_ + " " + makeRequestUri() + " " + versionMark +"\r\n" + header + "\r\n";
}

bool Response::isSuccess() const
{
    auto const category = statusCode / 100;
    return category < 4;
}

Response readResponseFromBuffer(Request const& req, Buffer& buffer)
{
    Response resp;

    // regex lack of string view support
    using string_view_match_result = std::match_results<std::string_view::const_iterator>;

    // first line should be status line, since http 1.0
    {
        auto const line = buffer.readLine();

        std::regex const pattern{R"regex(HTTP/\d+\.\d+\s+(\d\d\d)\s+.*)regex"};
        string_view_match_result match;
        if (!std::regex_match(std::begin(line), std::end(line),
                              match, pattern))
        {
            // TODO: make a dedicated exception, store instead of print
            spdlog::error("Bad status line: {}", line);
            throw std::runtime_error{"bad status line"};
        }
        resp.statusCode = std::stoi(match.str(1));
        spdlog::debug("Status code received: {}", resp.statusCode);
    }

    std::regex const headerPattern{R"regex(\s*([^:]*)\s*:\s*(.*)\s*)regex"};
    while (true) {
        auto const line = buffer.readLine();

        if (line.empty()) {
            break;
        }

        string_view_match_result match;
        if (!std::regex_match(std::begin(line), std::end(line),
                              match, headerPattern))
        {
            // TODO: make a dedicated exception, store instead of print
            spdlog::warn("Bad header line: {}", line);
            continue;
        }

        std::string name = toLower(match.str(1));

        // FIXME: should handle duplicated headers
        if (auto iter = resp.headers.find(name); iter != std::end(resp.headers)) {
            spdlog::warn("Dropping duplicated header: {}", line);
        } else {
            resp.headers[name] = match.str(2);
        }
    }

    if (auto const iter = resp.headers.find("transfer-encoding"); iter != std::end(resp.headers)) {
        // FIXME: should allow multiple transfer-encoding headers
        resp.transferEncoding = toLower(iter->second);
    } else {
        resp.transferEncoding = "identity";
    }

    auto const emptyBody = (resp.statusCode / 100 == 1 || resp.statusCode == 204 || resp.statusCode == 304 || req.method() == "HEAD");
    if (!emptyBody) {

        if (resp.transferEncoding == "identity") {

            size_t bodySize;
            if (auto const iter = resp.headers.find("content-length"); iter != std::end(resp.headers)) {
                bodySize = std::stoul(iter->second);
            } else {
                // should an empty value land here too?
                bodySize = 0;
            }
            resp.body = buffer.readAsVector(bodySize);

        } else if (resp.transferEncoding == "chunked") {

            std::regex const chunkHeaderPattern{R"regex(\s*([a-fA-F0-9]+)\s*(;.*)?)regex"};
            string_view_match_result match;

            while (true) {
                auto const line = buffer.readLine();

                if (!std::regex_match(std::begin(line), std::end(line),
                                      match, chunkHeaderPattern))
                {
                    // TODO: make a dedicated exception, store instead of print
                    spdlog::error("Bad chunk header: {}", line);
                    throw std::runtime_error{"bad chunk header"};
                }

                size_t const chunkSize = std::stoul(match.str(1), nullptr, 16);
                spdlog::debug("Chunk size: {}", chunkSize);

                if (chunkSize == 0) {
                    break;
                }

                auto const& chunk = buffer.readAsVector(chunkSize);

                resp.body.insert(std::end(resp.body),
                                 std::begin(chunk), std::end(chunk));

                buffer.dropLiteral("\r\n");
            }

            // TODO: make use of trailing headers
            while (true) {
                auto const line = buffer.readLine();

                if (line.empty()) {
                    break;
                }
                spdlog::debug("Trailing header: {}", line);
            }

        } else {
            throw std::runtime_error{"unsupported transfer encoding: " + resp.transferEncoding};
        }
    }

    return resp;
}
