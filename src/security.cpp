#include "ltg/security.hpp"

#include "ltg/core.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <regex>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

namespace linux_traffic_guard {

bool isValidPositiveInt(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    for (unsigned char ch : value) {
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return value != "0";
}

bool isStrictPositiveNumber(const std::string &value) {
    if (!std::regex_match(value, std::regex(R"(^[0-9]+(\.[0-9]+)?$)"))) {
        return false;
    }
    for (unsigned char ch : value) {
        if (std::isdigit(ch) && ch != '0') {
            return true;
        }
    }
    return false;
}

bool isValidPositiveNumber(const std::string &value) {
    return isStrictPositiveNumber(value);
}

bool parseTimeToSeconds(const std::string &text, long long &seconds) {
    const std::string value = trim(text);
    if (value.empty()) {
        return false;
    }
    std::smatch match;
    if (!std::regex_match(value, match, std::regex(R"(^([0-9]+)([smhdwSMHDW]?)$)"))) {
        return false;
    }
    long long number = 0;
    for (unsigned char ch : match[1].str()) {
        number = number * 10 + (ch - '0');
        if (number > 1000000000LL) {
            return false;
        }
    }
    if (number <= 0) {
        return false;
    }
    const std::string suffix = lowerCopy(match[2].str());
    long long factor = 1;
    if (suffix == "m") factor = 60;
    else if (suffix == "h") factor = 60 * 60;
    else if (suffix == "d") factor = 24 * 60 * 60;
    else if (suffix == "w") factor = 7 * 24 * 60 * 60;
    seconds = number * factor;
    return seconds > 0;
}

bool isValidTimeToken(const std::string &value) {
    long long seconds = 0;
    return parseTimeToSeconds(value, seconds);
}

namespace {

bool parsePrefixLength(const std::string &prefix, int maxBits, int &bits) {
    if (prefix.empty() || prefix.size() > 3) {
        return false;
    }
    int value = 0;
    for (unsigned char ch : prefix) {
        if (!std::isdigit(ch)) {
            return false;
        }
        value = value * 10 + (ch - '0');
    }
    if (value < 0 || value > maxBits) {
        return false;
    }
    bits = value;
    return true;
}

bool isHexHextet(const std::string &part) {
    if (part.empty() || part.size() > 4) {
        return false;
    }
    for (unsigned char ch : part) {
        if (!std::isxdigit(ch)) {
            return false;
        }
    }
    return true;
}

#ifndef _WIN32
bool ipv4InCidr(std::uint32_t ip, std::uint32_t base, int bits) {
    const std::uint32_t mask = bits == 0 ? 0 : (0xffffffffu << (32 - bits));
    return (ip & mask) == (base & mask);
}

std::uint32_t ipv4Addr(unsigned a, unsigned b, unsigned c, unsigned d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

bool isGlobalIpv4(std::uint32_t ip) {
    return !ipv4InCidr(ip, ipv4Addr(0, 0, 0, 0), 8) &&
           !ipv4InCidr(ip, ipv4Addr(10, 0, 0, 0), 8) &&
           !ipv4InCidr(ip, ipv4Addr(100, 64, 0, 0), 10) &&
           !ipv4InCidr(ip, ipv4Addr(127, 0, 0, 0), 8) &&
           !ipv4InCidr(ip, ipv4Addr(169, 254, 0, 0), 16) &&
           !ipv4InCidr(ip, ipv4Addr(172, 16, 0, 0), 12) &&
           !ipv4InCidr(ip, ipv4Addr(192, 0, 0, 0), 24) &&
           !ipv4InCidr(ip, ipv4Addr(192, 0, 2, 0), 24) &&
           !ipv4InCidr(ip, ipv4Addr(192, 168, 0, 0), 16) &&
           !ipv4InCidr(ip, ipv4Addr(198, 18, 0, 0), 15) &&
           !ipv4InCidr(ip, ipv4Addr(198, 51, 100, 0), 24) &&
           !ipv4InCidr(ip, ipv4Addr(203, 0, 113, 0), 24) &&
           !ipv4InCidr(ip, ipv4Addr(224, 0, 0, 0), 4) &&
           !ipv4InCidr(ip, ipv4Addr(240, 0, 0, 0), 4);
}

bool isIpv6MappedIpv4(const unsigned char *bytes) {
    for (int i = 0; i < 10; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

bool isGlobalIpv6(const unsigned char *bytes) {
    bool allZero = true;
    for (int i = 0; i < 16; ++i) {
        allZero = allZero && bytes[i] == 0;
    }
    if (allZero || (bytes[15] == 1 && std::all_of(bytes, bytes + 15, [](unsigned char b) { return b == 0; }))) {
        return false;
    }
    if (isIpv6MappedIpv4(bytes)) {
        const std::uint32_t mapped = (static_cast<std::uint32_t>(bytes[12]) << 24) |
                                     (static_cast<std::uint32_t>(bytes[13]) << 16) |
                                     (static_cast<std::uint32_t>(bytes[14]) << 8) |
                                     static_cast<std::uint32_t>(bytes[15]);
        return isGlobalIpv4(mapped);
    }
    if ((bytes[0] & 0xfe) == 0xfc) return false;
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return false;
    if (bytes[0] == 0xff) return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8) return false;
    return true;
}
#endif

} // namespace

bool isValidIpv4Address(const std::string &address) {
    static const std::regex ipv4(R"(^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$)");
    return std::regex_match(address, ipv4);
}

bool isValidIpv4OrCidr(const std::string &value) {
    const std::string token = trim(value);
    const std::size_t slash = token.find('/');
    const std::string address = slash == std::string::npos ? token : token.substr(0, slash);
    if (!isValidIpv4Address(address)) {
        return false;
    }
    if (slash == std::string::npos) {
        return true;
    }
    int bits = 0;
    return token.find('/', slash + 1) == std::string::npos &&
           parsePrefixLength(token.substr(slash + 1), 32, bits);
}

bool isValidIpv6Address(std::string address) {
    if (address.empty() || address.find(':') == std::string::npos ||
        address.find(":::") != std::string::npos) {
        return false;
    }

    if (address.find('.') != std::string::npos) {
        const std::size_t lastColon = address.find_last_of(':');
        if (lastColon == std::string::npos || lastColon + 1 >= address.size()) {
            return false;
        }
        const std::string ipv4Tail = address.substr(lastColon + 1);
        if (!isValidIpv4Address(ipv4Tail)) {
            return false;
        }
        address = address.substr(0, lastColon) + ":0:0";
    }

    const std::size_t compression = address.find("::");
    const bool compressed = compression != std::string::npos;
    if (compressed && address.find("::", compression + 2) != std::string::npos) {
        return false;
    }

    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= address.size()) {
        const std::size_t colon = address.find(':', start);
        parts.push_back(address.substr(start, colon == std::string::npos ? std::string::npos : colon - start));
        if (colon == std::string::npos) {
            break;
        }
        start = colon + 1;
    }

    int groups = 0;
    for (const auto &part : parts) {
        if (part.empty()) {
            continue;
        }
        if (!isHexHextet(part)) {
            return false;
        }
        ++groups;
    }
    if (compressed) {
        return groups < 8;
    }
    return groups == 8 && std::none_of(parts.begin(), parts.end(), [](const std::string &part) { return part.empty(); });
}

bool isValidIpv6OrCidr(const std::string &value) {
    const std::string token = trim(value);
    const std::size_t slash = token.find('/');
    const std::string address = slash == std::string::npos ? token : token.substr(0, slash);
    if (!isValidIpv6Address(address)) {
        return false;
    }
    if (slash == std::string::npos) {
        return true;
    }
    int bits = 0;
    return token.find('/', slash + 1) == std::string::npos &&
           parsePrefixLength(token.substr(slash + 1), 128, bits);
}

bool isValidIpOrCidr(const std::string &value) {
    const std::string token = trim(value);
    return isValidIpv4OrCidr(token) || isValidIpv6OrCidr(token);
}

bool normalizePublicIpAddress(const std::string &raw, std::string &normalized) {
    const std::string token = trim(raw);
#ifndef _WIN32
    char buffer[INET6_ADDRSTRLEN] = {};
    in_addr addr4{};
    if (inet_pton(AF_INET, token.c_str(), &addr4) == 1) {
        const std::uint32_t host = ntohl(addr4.s_addr);
        if (!isGlobalIpv4(host) || !inet_ntop(AF_INET, &addr4, buffer, sizeof(buffer))) {
            return false;
        }
        normalized = buffer;
        return true;
    }
    in6_addr addr6{};
    if (inet_pton(AF_INET6, token.c_str(), &addr6) == 1) {
        if (!isGlobalIpv6(addr6.s6_addr) || !inet_ntop(AF_INET6, &addr6, buffer, sizeof(buffer))) {
            return false;
        }
        normalized = buffer;
        return true;
    }
#else
    (void)normalized;
#endif
    return false;
}

bool isSafeIdentifier(const std::string &value) {
    if (value.empty() || value.size() > 64) {
        return false;
    }
    for (unsigned char ch : value) {
        if (!std::isalnum(ch) && ch != '_' && ch != '-') {
            return false;
        }
    }
    return true;
}

bool isSafeLogPath(const std::string &value) {
    if (value.empty() || value.size() > 240 || value[0] != '/') {
        return false;
    }
    for (unsigned char ch : value) {
        if (std::isalnum(ch) || ch == '/' || ch == '.' || ch == '_' || ch == '-' || ch == '*' || ch == '?') {
            continue;
        }
        return false;
    }
    return true;
}

} // namespace linux_traffic_guard
