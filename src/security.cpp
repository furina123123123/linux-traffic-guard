#include "ltg/security.hpp"

#include "ltg/core.hpp"
#include "ltg/protection_bootstrap.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <regex>
#include <set>
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

std::string configValueOr(const std::string &value, const std::string &fallback) {
    return trim(value).empty() ? fallback : trim(value);
}

F2bJailConfig readJailConfig(const std::string &jail) {
    IniConfig ini;
    ini.load(kJailConf);
    F2bJailConfig cfg;
    cfg.enabled = ini.get(jail, "enabled");
    cfg.maxretry = ini.get(jail, "maxretry");
    cfg.findtime = ini.get(jail, "findtime");
    cfg.bantime = ini.get(jail, "bantime");
    cfg.banaction = ini.get(jail, "banaction");
    cfg.ignoreip = ini.get(jail, "ignoreip");
    cfg.increment = ini.get(jail, "bantime.increment");
    cfg.factor = ini.get(jail, "bantime.factor");
    cfg.maxtime = ini.get(jail, "bantime.maxtime");
    return cfg;
}

std::string readJailValue(const std::string &jail, const std::string &key) {
    IniConfig ini;
    ini.load(kJailConf);
    return ini.get(jail, key);
}

bool applyJailConfigValue(const std::string &jail,
                          const std::string &key,
                          const std::string &value,
                          std::string &backupPath,
                          std::string &error) {
    ensureDirectory("/etc/fail2ban");
    IniConfig ini;
    if (!ini.load(kJailConf)) {
        error = "无法读取 " + kJailConf;
        return false;
    }
    ini.set(jail, key, value);
    if (!ini.save(backupPath)) {
        error = "无法写入 " + kJailConf;
        return false;
    }
    return true;
}

F2bJailRuntimeInfo fail2banJailRuntimeStatus(const std::string &jail) {
    if (!Shell::exists("fail2ban-client")) {
        return parseFail2banJailStatus(jail, "", false);
    }
    const CommandResult result = Shell::capture("fail2ban-client status " + shellQuote(jail) + " 2>&1");
    return parseFail2banJailStatus(jail, result.output, true);
}

std::set<std::string> bannedSetForJail(const std::string &jail) {
    return fail2banJailRuntimeStatus(jail).bannedIps;
}

std::string fail2banJailStatusLine(const std::string &jail) {
    const F2bJailRuntimeInfo info = fail2banJailRuntimeStatus(jail);
    if (info.raw.empty()) {
        return info.label;
    }
    std::string firstLine = splitLines(info.raw).empty() ? info.raw : splitLines(info.raw).front();
    if (firstLine.size() > 160) {
        firstLine = firstLine.substr(0, 157) + "...";
    }
    return info.label + ": " + firstLine;
}

std::string recentBanLineForJail(const std::string &jail) {
    const std::string cmd =
        "(grep -h '\\[" + jail + "\\].* Ban ' /var/log/fail2ban.log* 2>/dev/null || "
        "journalctl -u fail2ban --no-pager 2>/dev/null | grep '\\[" + jail + "\\].* Ban ') | tail -1";
    return trim(Shell::capture(cmd).output);
}

std::string policyRoleForJail(const std::string &jail) {
    if (jail == kRule1Jail) {
        return "默认策略: SSH 登录防护";
    }
    if (jail == kRule2Jail) {
        return "默认策略: UFW 慢扫升级";
    }
    return "自定义策略";
}

std::set<std::string> configuredFail2banJails() {
    std::set<std::string> out;
    out.insert(kRule1Jail);
    out.insert(kRule2Jail);
    IniConfig ini;
    ini.load(kJailConf);
    for (const auto &section : ini.sections()) {
        if (section != "DEFAULT" && !section.empty()) {
            out.insert(section);
        }
    }
    return out;
}

std::set<std::string> runningFail2banJails() {
    std::set<std::string> out;
    if (!Shell::exists("fail2ban-client")) {
        return out;
    }
    const std::string output = Shell::capture("fail2ban-client status 2>/dev/null || true").output;
    for (const auto &line : splitLines(output)) {
        const std::size_t pos = line.find("Jail list:");
        if (pos == std::string::npos) {
            continue;
        }
        std::string list = line.substr(pos + std::string("Jail list:").size());
        std::replace(list.begin(), list.end(), ',', ' ');
        for (const auto &name : splitWords(list)) {
            if (isSafeIdentifier(name)) {
                out.insert(name);
            }
        }
    }
    return out;
}

std::vector<F2bPolicyInfo> collectFail2banPolicies(bool includeRuntimeStatus) {
    std::set<std::string> names = configuredFail2banJails();
    const std::set<std::string> running = runningFail2banJails();
    names.insert(running.begin(), running.end());
    IniConfig ini;
    ini.load(kJailConf);
    const std::vector<std::string> sections = ini.sections();
    const std::set<std::string> configuredSections(sections.begin(), sections.end());

    std::vector<F2bPolicyInfo> policies;
    for (const auto &name : names) {
        F2bPolicyInfo info;
        info.name = name;
        info.role = policyRoleForJail(name);
        info.managedDefault = name == kRule1Jail || name == kRule2Jail;
        info.configured = configuredSections.count(name) > 0;
        info.config = readJailConfig(name);
        info.filter = readJailValue(name, "filter");
        info.backend = readJailValue(name, "backend");
        info.logpath = readJailValue(name, "logpath");
        info.port = readJailValue(name, "port");
        const F2bJailRuntimeInfo runtime = includeRuntimeStatus ? fail2banJailRuntimeStatus(name) : F2bJailRuntimeInfo{};
        info.jailLoaded = includeRuntimeStatus ? runtime.loaded() : running.count(name) > 0;
        info.runtimeDetail = includeRuntimeStatus ? runtime.label : (running.count(name) ? "已加载" : "-");
        const bool configuredEnabled = lowerCopy(configValueOr(info.config.enabled, running.count(name) ? "true" : "false")) == "true";
        if (includeRuntimeStatus) {
            info.state = runtime.label;
            info.bannedCount = runtime.bannedIps.size();
            info.recentBan = recentBanLineForJail(name).empty() ? "-" : "有";
        } else {
            info.state = running.count(name) ? "运行中" : (configuredEnabled ? "已配置/待重载" : "未启用");
        }
        policies.push_back(info);
    }
    std::sort(policies.begin(), policies.end(), [](const F2bPolicyInfo &a, const F2bPolicyInfo &b) {
        if (a.managedDefault != b.managedDefault) {
            return a.managedDefault > b.managedDefault;
        }
        return a.name < b.name;
    });
    return policies;
}

std::vector<F2bPolicyInfo> collectDefaultFail2banPolicies(bool includeRuntimeStatus) {
    std::vector<F2bPolicyInfo> defaults;
    for (const auto &policy : collectFail2banPolicies(includeRuntimeStatus)) {
        if (policy.name == kRule1Jail || policy.name == kRule2Jail) {
            defaults.push_back(policy);
        }
    }
    return defaults;
}

std::vector<std::string> customFail2banJailNames() {
    std::vector<std::string> out;
    for (const auto &policy : collectFail2banPolicies(false)) {
        if (!policy.managedDefault && policy.name != "DEFAULT") {
            out.push_back(policy.name);
        }
    }
    return out;
}

} // namespace linux_traffic_guard
