#ifndef LINUX_TRAFFIC_GUARD_HPP
#define LINUX_TRAFFIC_GUARD_HPP

/*
 * Linux Traffic Guard / Linux 流量守卫
 *
 * A single-header C++17 server traffic and security operations TUI for Ubuntu.
 * It combines nftables IP traffic accounting, UFW source analysis, fail2ban
 * policy management, and diagnostic workflows without external shell/Python
 * scripts.
 *
 * SPDX-License-Identifier: MIT
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <future>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <csignal>
#include <deque>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <io.h>
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#endif

#ifndef _WIN32
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#endif

#ifndef LTG_FORCE_NO_SQLITE
#define LTG_FORCE_NO_SQLITE 0
#endif

#if !LTG_FORCE_NO_SQLITE && __has_include(<sqlite3.h>)
#include <sqlite3.h>
#define LTG_HAS_SQLITE 1
#else
#define LTG_HAS_SQLITE 0
#endif

namespace linux_traffic_guard {

namespace ansi {
inline const std::string red = "\033[31m";
inline const std::string green = "\033[32m";
inline const std::string yellow = "\033[33m";
inline const std::string blue = "\033[36m";
inline const std::string cyan = "\033[36m";
inline const std::string gray = "\033[90m";
inline const std::string bold = "\033[1m";
inline const std::string inverse = "\033[7m";
inline const std::string plain = "\033[0m";
} // namespace ansi

inline const std::string kVersion = "4.12.1";
inline const std::string kName = "Linux 流量守卫";
inline const std::string kIpTrafficTable = "usp_ip_traffic";
inline const std::string kRule1Jail = "sshd";
inline const std::string kRule2Jail = "ufw-slowscan-global";
inline const std::string kJailConf = "/etc/fail2ban/jail.local";
inline const std::string kRule2FilterFile = "/etc/fail2ban/filter.d/ufw-slowscan-global.conf";
inline const std::string kUfwDropActionFile = "/etc/fail2ban/action.d/ufw-drop.conf";
inline const std::string kUfwCacheDir = "/var/tmp/linux_traffic_guard_ufw_cache_v1";
inline const std::string kFail2banDb = "/var/lib/fail2ban/fail2ban.sqlite3";
inline constexpr int kUfwCacheIdleDays = 14;

inline std::string nowStamp();
inline bool parseTimeToSeconds(const std::string &text, long long &seconds);

struct CommandResult {
    int exitCode = 1;
    std::string output;

    bool ok() const {
        return exitCode == 0;
    }
};

struct MenuItem {
    std::string key;
    std::string title;
    std::string detail;
    bool needsRoot = false;
    std::function<void()> run;
};

struct TrafficRow {
    std::string ip;
    std::string port;
    std::string direction;
    std::string family;
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
};

struct TrafficSummaryRow {
    std::string ip;
    std::string port;
    std::uint64_t downloadBytes = 0;
    std::uint64_t uploadBytes = 0;
    std::uint64_t downloadPackets = 0;
    std::uint64_t uploadPackets = 0;

    std::uint64_t totalBytes() const {
        return downloadBytes + uploadBytes;
    }

    std::uint64_t totalPackets() const {
        return downloadPackets + uploadPackets;
    }
};

struct UfwHit {
    std::string value;
    std::uint64_t count = 0;
    std::string topPort;
    std::uint64_t topPortCount = 0;
    std::string risk;
    std::string suggestion;
};

struct F2bJailConfig {
    std::string enabled;
    std::string maxretry;
    std::string findtime;
    std::string bantime;
    std::string banaction;
    std::string ignoreip;
    std::string increment;
    std::string factor;
    std::string maxtime;
};

struct F2bPolicyInfo {
    std::string name;
    std::string role;
    F2bJailConfig config;
    std::string filter;
    std::string backend;
    std::string logpath;
    std::string port;
    std::string state;
    std::size_t bannedCount = 0;
    bool managedDefault = false;
};

struct UfwLogEvent {
    std::time_t ts = 0;
    std::string day;
    std::string action;
    std::string src;
    std::string dpt;
};

struct UfwAnalysisReport {
    std::string title;
    std::time_t start = 0;
    std::time_t end = 0;
    std::size_t validLines = 0;
    std::string sourceNote;
    std::map<std::string, std::map<std::string, int>> ipDaily;
    std::map<std::string, std::map<std::string, int>> portDaily;
    std::map<std::string, std::map<std::string, std::map<std::string, int>>> ipPortDaily;
    std::vector<std::pair<std::string, std::time_t>> allowRecent;
};

struct DualAuditRow {
    std::string ip;
    int ufwHits = 0;
    bool rule1Banned = false;
    bool rule2Banned = false;
    bool banLogged = false;
    std::string conclusion;
};

struct DashboardSnapshot {
    bool tableEnabled = false;
    std::vector<TrafficRow> trafficRows;
    std::vector<TrafficSummaryRow> totalRows;
    std::vector<UfwHit> ufwHits;
    std::string fail2banState = "未知";
    std::string ufwState = "未知";
    std::chrono::steady_clock::time_point loadedAt{};
};

struct UfwDeleteCandidate {
    int number = 0;
    std::string ip;
    std::string line;
    std::string reason;
};

struct UfwSshExposure {
    std::vector<std::string> sshPorts;
    std::vector<std::string> allowRules;

    bool hasAllowRule() const {
        return !allowRules.empty();
    }
};

enum class InputKind {
    None,
    Character,
    Escape,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    MouseUp,
    MouseDown,
    CtrlC
};

struct InputEvent {
    InputKind kind = InputKind::None;
    char ch = 0;
};

inline bool &pauseEnabled() {
    static bool enabled = true;
    return enabled;
}

inline bool &alternateScreenActive() {
    static bool active = false;
    return active;
}

inline std::map<std::string, bool> &toolExistsCache() {
    static std::map<std::string, bool> cache;
    return cache;
}

inline std::mutex &toolExistsCacheMutex() {
    static std::mutex mutex;
    return mutex;
}

inline bool shouldUseColor(int fd = STDOUT_FILENO) {
    if (std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
#ifdef _WIN32
    return _isatty(fd) != 0;
#else
    return isatty(fd) != 0;
#endif
}

inline std::string stripAnsi(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size();) {
        if (value[i] != '\033') {
            out.push_back(value[i++]);
            continue;
        }
        ++i;
        if (i < value.size() && value[i] == '[') {
            ++i;
            while (i < value.size()) {
                const unsigned char ch = static_cast<unsigned char>(value[i++]);
                if (ch >= 0x40 && ch <= 0x7e) {
                    break;
                }
            }
        }
    }
    return out;
}

inline std::string colorIf(const std::string &text, const std::string &color, int fd = STDOUT_FILENO) {
    return shouldUseColor(fd) ? color + text + ansi::plain : text;
}

#ifndef _WIN32
inline termios &savedTerminalMode() {
    static termios mode{};
    return mode;
}

inline bool &savedTerminalModeValid() {
    static bool valid = false;
    return valid;
}

inline bool &promptModeActive() {
    static bool active = false;
    return active;
}
#endif

inline void restoreTerminalDisplay() {
#ifndef _WIN32
    if (promptModeActive() && savedTerminalModeValid()) {
        tcsetattr(STDIN_FILENO, TCSANOW, &savedTerminalMode());
        promptModeActive() = false;
    }
#endif
    if (alternateScreenActive()) {
#ifndef _WIN32
        const char seq[] = "\033[?25h\033[?7h\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1049l";
        const ssize_t written = write(STDOUT_FILENO, seq, sizeof(seq) - 1);
        (void)written;
#else
        std::cout << "\033[?25h\033[?7h\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1049l";
        std::cout.flush();
#endif
        alternateScreenActive() = false;
    }
}

inline void signalExitHandler(int sig) {
    restoreTerminalDisplay();
#ifndef _WIN32
    _exit(128 + sig);
#else
    std::exit(128 + sig);
#endif
}

inline void installSignalHandlers() {
    std::signal(SIGINT, signalExitHandler);
    std::signal(SIGTERM, signalExitHandler);
#ifdef SIGHUP
    std::signal(SIGHUP, signalExitHandler);
#endif
#ifdef SIGQUIT
    std::signal(SIGQUIT, signalExitHandler);
#endif
    std::atexit(restoreTerminalDisplay);
}

inline std::string trim(std::string value) {
    const char *spaces = " \t\r\n";
    const auto first = value.find_first_not_of(spaces);
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(spaces);
    return value.substr(first, last - first + 1);
}

inline std::string removeSpaces(const std::string &value) {
    std::string out;
    for (unsigned char ch : value) {
        if (!std::isspace(ch)) {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

inline std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

inline bool startsWith(const std::string &value, const std::string &prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

inline std::vector<std::string> splitWords(const std::string &text) {
    std::vector<std::string> out;
    std::istringstream input(text);
    std::string word;
    while (input >> word) {
        out.push_back(word);
    }
    return out;
}

inline std::vector<std::string> splitByChar(const std::string &text, char sep) {
    std::vector<std::string> out;
    std::string item;
    std::istringstream input(text);
    while (std::getline(input, item, sep)) {
        out.push_back(item);
    }
    return out;
}

inline std::string joinWords(const std::vector<std::string> &words, const std::string &sep = " ") {
    std::ostringstream out;
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i != 0) {
            out << sep;
        }
        out << words[i];
    }
    return out.str();
}

inline bool isRoot() {
#ifdef _WIN32
    return false;
#else
    return geteuid() == 0;
#endif
}

inline std::string shellQuote(const std::string &value) {
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') {
            out += "'\\''";
        } else {
            out += ch;
        }
    }
    out += "'";
    return out;
}

inline bool readTextFile(const std::string &path, std::string &content) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    std::ostringstream out;
    out << input.rdbuf();
    content = out.str();
    return true;
}

inline bool writeTextFile(const std::string &path, const std::string &content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output << content;
    return static_cast<bool>(output);
}

inline bool backupFileIfExists(const std::string &path, std::string &backupPath) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        backupPath.clear();
        return true;
    }
    backupPath = path + ".ltg." + nowStamp() + ".bak";
    std::ofstream output(backupPath, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output << input.rdbuf();
    return static_cast<bool>(output);
}

inline bool ensureDirectory(const std::string &path) {
#ifdef _WIN32
    return std::system(("mkdir " + shellQuote(path) + " >NUL 2>NUL").c_str()) == 0;
#else
    return std::system(("mkdir -p " + shellQuote(path) + " >/dev/null 2>&1").c_str()) == 0;
#endif
}

inline bool isSafePortList(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t comma = value.find(',', start);
        const std::string item = value.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (item.empty()) {
            return false;
        }
        const std::size_t dash = item.find('-');
        if (dash != std::string::npos && item.find('-', dash + 1) != std::string::npos) {
            return false;
        }
        const std::string first = dash == std::string::npos ? item : item.substr(0, dash);
        const std::string second = dash == std::string::npos ? "" : item.substr(dash + 1);
        const auto parsePort = [](const std::string &text, int &port) {
            if (text.empty()) {
                return false;
            }
            int value = 0;
            for (unsigned char ch : text) {
                if (!std::isdigit(ch)) {
                    return false;
                }
                value = value * 10 + (ch - '0');
                if (value > 65535) {
                    return false;
                }
            }
            if (value < 1) {
                return false;
            }
            port = value;
            return true;
        };
        int firstPort = 0;
        int secondPort = 0;
        if (!parsePort(first, firstPort) ||
            (dash != std::string::npos && !parsePort(second, secondPort))) {
            return false;
        }
        if (second.empty()) {
            secondPort = firstPort;
        }
        if (firstPort > secondPort) {
            return false;
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return true;
}

inline bool isSafeSinglePort(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    int port = 0;
    for (unsigned char ch : value) {
        if (!std::isdigit(ch)) {
            return false;
        }
        port = port * 10 + (ch - '0');
        if (port > 65535) {
            return false;
        }
    }
    return port >= 1;
}

inline bool isSafePortOrEmpty(const std::string &value) {
    return value.empty() || isSafePortList(value);
}

inline bool isValidPositiveInt(const std::string &value) {
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

inline bool isStrictPositiveNumber(const std::string &value) {
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

inline bool isValidPositiveNumber(const std::string &value) {
    return isStrictPositiveNumber(value);
}

inline bool isValidTimeToken(const std::string &value) {
    long long seconds = 0;
    return parseTimeToSeconds(value, seconds);
}

inline bool parsePrefixLength(const std::string &prefix, int maxBits, int &bits) {
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

inline bool isValidIpv4Address(const std::string &address) {
    static const std::regex ipv4(R"(^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$)");
    return std::regex_match(address, ipv4);
}

inline bool isValidIpv4OrCidr(const std::string &value) {
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

inline bool isHexHextet(const std::string &part) {
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

inline bool isValidIpv6Address(std::string address) {
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

inline bool isValidIpv6OrCidr(const std::string &value) {
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

inline bool isValidIpOrCidr(const std::string &value) {
    const std::string token = trim(value);
    return isValidIpv4OrCidr(token) || isValidIpv6OrCidr(token);
}

inline bool isSafeIdentifier(const std::string &value) {
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

inline bool isSafeLogPath(const std::string &value) {
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

inline std::string nowStamp() {
    const auto now = std::chrono::system_clock::now();
    const auto sec = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &sec);
#else
    localtime_r(&sec, &tm);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &tm);
    return buf;
}

inline std::string dateStamp(std::time_t value) {
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &value);
#else
    localtime_r(&value, &tm);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
    return buf;
}

inline std::string dateTimeStamp(std::time_t value) {
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &value);
#else
    localtime_r(&value, &tm);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

inline std::time_t makeLocalTime(std::tm tm) {
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

inline bool isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

inline bool isValidCalendarDateParts(int year, int month, int day) {
    if (year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1) {
        return false;
    }
    static const int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int limit = daysInMonth[month - 1];
    if (month == 2 && isLeapYear(year)) {
        limit = 29;
    }
    return day <= limit;
}

inline bool parseYmdDate(const std::string &text, bool endOfDay, std::time_t &out) {
    std::smatch match;
    const std::string value = trim(text);
    std::tm tm{};
    const std::time_t now = std::time(nullptr);
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    int year = tm.tm_year + 1900;
    int month = tm.tm_mon + 1;
    int day = tm.tm_mday;
    if (std::regex_match(value, match, std::regex(R"((\d{4})[-/ ](\d{1,2})[-/ ](\d{1,2}))"))) {
        year = std::stoi(match[1].str());
        month = std::stoi(match[2].str());
        day = std::stoi(match[3].str());
    } else if (std::regex_match(value, match, std::regex(R"((\d{1,2})[-/ ](\d{1,2}))"))) {
        month = std::stoi(match[1].str());
        day = std::stoi(match[2].str());
    } else {
        return false;
    }
    if (!isValidCalendarDateParts(year, month, day)) {
        return false;
    }
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = endOfDay ? 23 : 0;
    tm.tm_min = endOfDay ? 59 : 0;
    tm.tm_sec = endOfDay ? 59 : 0;
    tm.tm_isdst = -1;
    out = makeLocalTime(tm);
    if (out == static_cast<std::time_t>(-1)) {
        return false;
    }
    std::tm roundTrip{};
#ifdef _WIN32
    localtime_s(&roundTrip, &out);
#else
    localtime_r(&out, &roundTrip);
#endif
    return roundTrip.tm_year == year - 1900 &&
           roundTrip.tm_mon == month - 1 &&
           roundTrip.tm_mday == day;
}

inline bool parseTimeToSeconds(const std::string &text, long long &seconds) {
    const std::string value = trim(text);
    if (value.empty()) {
        return false;
    }
    std::smatch match;
    if (!std::regex_match(value, match, std::regex(R"(^([0-9]+)([smhdwSMHDW]?)$)"))) {
        return false;
    }
    long long n = 0;
    for (unsigned char ch : match[1].str()) {
        n = n * 10 + (ch - '0');
        if (n > 1000000000LL) {
            return false;
        }
    }
    const std::string suffix = lowerCopy(match[2].str());
    long long mul = 1;
    if (suffix == "m") mul = 60;
    else if (suffix == "h") mul = 3600;
    else if (suffix == "d") mul = 86400;
    else if (suffix == "w") mul = 604800;
    seconds = n * mul;
    return seconds > 0;
}

inline std::vector<std::string> splitLines(const std::string &text) {
    std::vector<std::string> lines;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return lines;
}

inline std::string truncateText(const std::string &value, std::size_t width) {
    if (value.size() <= width) {
        return value;
    }
    if (width <= 3) {
        return value.substr(0, width);
    }
    return value.substr(0, width - 3) + "...";
}

inline std::string humanBytes(std::uint64_t bytes) {
    static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    if (unit == 0) {
        out << static_cast<std::uint64_t>(value) << " " << units[unit];
    } else {
        out << std::fixed << std::setprecision(2) << value << " " << units[unit];
    }
    return out.str();
}

inline int normalizedExitCode(int raw) {
#ifdef _WIN32
    return raw;
#else
    if (raw == -1) {
        return 1;
    }
    if (WIFEXITED(raw)) {
        return WEXITSTATUS(raw);
    }
    return raw;
#endif
}

class Shell {
public:
    static CommandResult capture(const std::string &command) {
        std::array<char, 4096> buffer{};
        CommandResult result;
#ifdef _WIN32
        const std::string wrapped = "(" + command + ") <NUL 2>&1";
        FILE *pipe = _popen(wrapped.c_str(), "r");
#else
        const std::string wrapped = "{ " + command + "; } </dev/null 2>&1";
        FILE *pipe = popen(wrapped.c_str(), "r");
#endif
        if (!pipe) {
            result.output = "无法执行命令: " + command + "\n";
            return result;
        }
        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
            result.output += buffer.data();
        }
#ifdef _WIN32
        result.exitCode = normalizedExitCode(_pclose(pipe));
#else
        result.exitCode = normalizedExitCode(pclose(pipe));
#endif
        return result;
    }

    static CommandResult run(const std::string &command) {
        std::cout << colorIf("$ " + command, ansi::gray) << "\n";
        const int raw = std::system(command.c_str());
        return {normalizedExitCode(raw), ""};
    }

    static bool exists(const std::string &name) {
        {
            std::lock_guard<std::mutex> lock(toolExistsCacheMutex());
            auto &cache = toolExistsCache();
            const auto found = cache.find(name);
            if (found != cache.end()) {
                return found->second;
            }
        }
#ifdef _WIN32
        const bool ok = std::system(("where " + name + " >NUL 2>NUL").c_str()) == 0;
#else
        const bool ok = std::system(("command -v " + shellQuote(name) + " >/dev/null 2>&1").c_str()) == 0;
#endif
        {
            std::lock_guard<std::mutex> lock(toolExistsCacheMutex());
            toolExistsCache()[name] = ok;
        }
        return ok;
    }

    static void clearExistsCache() {
        std::lock_guard<std::mutex> lock(toolExistsCacheMutex());
        toolExistsCache().clear();
    }
};

class IniConfig {
public:
    bool load(const std::string &path) {
        path_ = path;
        lines_.clear();
        std::string content;
        if (!readTextFile(path, content)) {
            return true;
        }
        lines_ = splitLines(content);
        return true;
    }

    void loadString(const std::string &content, const std::string &virtualPath = "") {
        path_ = virtualPath;
        lines_ = splitLines(content);
    }

    std::string toString() const {
        return joinWords(lines_, "\n") + (lines_.empty() ? "" : "\n");
    }

    std::string get(const std::string &section, const std::string &key) const {
        bool inSection = false;
        const std::regex sectionPattern(R"(^\s*\[([^\]]+)\]\s*$)");
        const std::regex keyPattern(R"(^\s*([^#;=\s][^=]*?)\s*=\s*(.*?)\s*$)");
        for (const auto &line : lines_) {
            std::smatch match;
            if (std::regex_match(line, match, sectionPattern)) {
                inSection = trim(match[1].str()) == section;
                continue;
            }
            if (!inSection || !std::regex_match(line, match, keyPattern)) {
                continue;
            }
            if (trim(match[1].str()) == key) {
                return trim(match[2].str());
            }
        }
        return "";
    }

    std::vector<std::string> sections() const {
        std::vector<std::string> out;
        const std::regex sectionPattern(R"(^\s*\[([^\]]+)\]\s*$)");
        for (const auto &line : lines_) {
            std::smatch match;
            if (std::regex_match(line, match, sectionPattern)) {
                out.push_back(trim(match[1].str()));
            }
        }
        return out;
    }

    void set(const std::string &section, const std::string &key, const std::string &value) {
        const std::regex sectionPattern(R"(^\s*\[([^\]]+)\]\s*$)");
        const std::regex keyPattern(R"(^\s*([^#;=\s][^=]*?)\s*=\s*(.*?)\s*$)");
        int sectionStart = -1;
        int sectionEnd = static_cast<int>(lines_.size());
        for (int i = 0; i < static_cast<int>(lines_.size()); ++i) {
            std::smatch match;
            if (!std::regex_match(lines_[static_cast<std::size_t>(i)], match, sectionPattern)) {
                continue;
            }
            if (sectionStart >= 0) {
                sectionEnd = i;
                break;
            }
            if (trim(match[1].str()) == section) {
                sectionStart = i;
            }
        }
        if (sectionStart < 0) {
            if (!lines_.empty() && !trim(lines_.back()).empty()) {
                lines_.push_back("");
            }
            lines_.push_back("[" + section + "]");
            lines_.push_back(key + " = " + value);
            return;
        }
        for (int i = sectionStart + 1; i < sectionEnd; ++i) {
            std::smatch match;
            if (std::regex_match(lines_[static_cast<std::size_t>(i)], match, keyPattern) &&
                trim(match[1].str()) == key) {
                lines_[static_cast<std::size_t>(i)] = key + " = " + value;
                return;
            }
        }
        lines_.insert(lines_.begin() + sectionEnd, key + " = " + value);
    }

    bool save(std::string &backupPath) const {
        if (!backupFileIfExists(path_, backupPath)) {
            return false;
        }
        return writeTextFile(path_, toString());
    }

private:
    std::string path_;
    std::vector<std::string> lines_;
};

inline F2bJailConfig readJailConfig(const std::string &jail) {
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

inline std::string readJailValue(const std::string &jail, const std::string &key) {
    IniConfig ini;
    ini.load(kJailConf);
    return ini.get(jail, key);
}

inline std::string configValueOr(const std::string &value, const std::string &fallback) {
    return trim(value).empty() ? fallback : trim(value);
}

inline bool applyJailConfigValue(const std::string &jail,
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

inline std::string renderRule2FilterFile() {
    return "[Definition]\n"
           "failregex = ^.*\\[UFW (BLOCK|AUDIT)\\].*SRC=<HOST>.*$\n"
           "ignoreregex =\n";
}

inline std::string renderUfwDropActionFile() {
    return "[Definition]\n"
           "actionstart =\n"
           "actionstop =\n"
           "actioncheck = ufw status >/dev/null\n"
           "actionban = ufw deny from <ip> to any comment 'f2b:<name> ip:<ip>'\n"
           "actionunban = ufw --force delete deny from <ip> to any\n"
           "\n[Init]\n";
}

inline bool writeManagedFileWithBackup(const std::string &path,
                                       const std::string &content,
                                       std::string &backupPath,
                                       std::string &error) {
    const std::size_t slash = path.find_last_of('/');
    if (slash != std::string::npos) {
        ensureDirectory(path.substr(0, slash));
    }
    if (!backupFileIfExists(path, backupPath)) {
        error = "无法备份 " + path;
        return false;
    }
    if (!writeTextFile(path, content)) {
        error = "无法写入 " + path;
        return false;
    }
    return true;
}

inline std::vector<std::string> ensureFail2banBaselineCommands() {
    std::vector<std::string> commands;
    commands.push_back("systemctl enable --now fail2ban || true");
    commands.push_back("fail2ban-client reload || systemctl restart fail2ban");
    commands.push_back("ufw reload || true");
    return commands;
}

inline std::string fail2banSetIpCommand(const std::string &jail, const std::string &verb, const std::string &ip) {
    return "fail2ban-client set " + shellQuote(jail) + " " + verb + " " + shellQuote(ip) + " || true";
}

inline std::string ufwDenyFromCommand(const std::string &source, const std::string &comment = "") {
    std::string command = "ufw deny from " + shellQuote(source);
    if (!comment.empty()) {
        command += " to any comment " + shellQuote(comment);
    }
    return command;
}

inline std::string ufwAllowFromCommand(const std::string &source) {
    return "ufw allow from " + shellQuote(source);
}

inline std::string ufwDeleteDenyFromCommand(const std::string &source) {
    return "ufw --force delete deny from " + shellQuote(source) + " 2>/dev/null || true";
}

inline std::string ufwPortRuleCommand(const std::string &verb, const std::string &target) {
    return "ufw " + verb + " " + shellQuote(target);
}

inline std::string ufwDeletePortRuleCommand(const std::string &verb, const std::string &target) {
    return "ufw --force delete " + verb + " " + shellQuote(target);
}

inline std::string bannedListForJail(const std::string &jail) {
    const std::string cmd =
        "fail2ban-client status " + shellQuote(jail) +
        " 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' || true";
    return trim(Shell::capture(cmd).output);
}

inline std::set<std::string> bannedSetForJail(const std::string &jail) {
    std::set<std::string> out;
    for (const auto &ip : splitWords(bannedListForJail(jail))) {
        if (!ip.empty()) {
            out.insert(ip);
        }
    }
    return out;
}

inline std::string fail2banJailStatusLine(const std::string &jail) {
    const CommandResult result = Shell::capture("fail2ban-client status " + shellQuote(jail) + " 2>/dev/null || true");
    const std::string output = trim(result.output);
    return output.empty() ? "不可用或未启用" : output;
}

inline std::time_t parseFail2banDbTime(const std::string &text) {
    std::smatch match;
    if (!std::regex_search(text, match, std::regex(R"(([0-9]{10,}))"))) {
        return 0;
    }
    return static_cast<std::time_t>(std::stoll(match[1].str()));
}

inline std::time_t lastBanTimestamp(const std::string &jail, const std::string &ip) {
    if (Shell::exists("sqlite3")) {
        const std::string query =
            "select timeofban from bans where jail=" + shellQuote(jail) +
            " and ip=" + shellQuote(ip) + " order by timeofban desc limit 1;";
        const CommandResult db = Shell::capture("sqlite3 " + shellQuote(kFail2banDb) + " " + shellQuote(query) + " 2>/dev/null || true");
        const std::time_t ts = parseFail2banDbTime(db.output);
        if (ts > 0) {
            return ts;
        }
    }
    const std::string cmd =
        "(grep -h ' Ban " + ip + "' /var/log/fail2ban.log* 2>/dev/null || "
        "journalctl -u fail2ban --no-pager 2>/dev/null | grep ' Ban " + ip + "') | tail -1";
    const std::string line = trim(Shell::capture(cmd).output);
    std::smatch match;
    if (std::regex_search(line, match, std::regex(R"(^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2}))"))) {
        std::tm tm{};
        tm.tm_year = std::stoi(match[1].str()) - 1900;
        tm.tm_mon = std::stoi(match[2].str()) - 1;
        tm.tm_mday = std::stoi(match[3].str());
        tm.tm_hour = std::stoi(match[4].str());
        tm.tm_min = std::stoi(match[5].str());
        tm.tm_sec = std::stoi(match[6].str());
        return makeLocalTime(tm);
    }
    return 0;
}

inline long long resolveBantimeSeconds(const std::string &jail) {
    const F2bJailConfig cfg = readJailConfig(jail);
    long long seconds = 0;
    if (parseTimeToSeconds(configValueOr(cfg.bantime, jail == kRule2Jail ? "1d" : "600"), seconds)) {
        return seconds;
    }
    return jail == kRule2Jail ? 86400 : 600;
}

inline std::string remainingBanTime(const std::string &jail, const std::string &ip) {
    const std::time_t start = lastBanTimestamp(jail, ip);
    if (start <= 0) {
        return "未知";
    }
    const long long duration = resolveBantimeSeconds(jail);
    const long long left = start + duration - std::time(nullptr);
    if (left <= 0) {
        return "可能已到期";
    }
    std::ostringstream out;
    long long value = left;
    const long long days = value / 86400;
    value %= 86400;
    const long long hours = value / 3600;
    value %= 3600;
    const long long mins = value / 60;
    if (days > 0) out << days << "d ";
    if (hours > 0) out << hours << "h ";
    out << mins << "m";
    return out.str();
}

inline std::string policyRoleForJail(const std::string &jail) {
    if (jail == kRule1Jail) {
        return "默认策略: SSH 登录防护";
    }
    if (jail == kRule2Jail) {
        return "默认策略: UFW 慢扫升级";
    }
    return "自定义策略";
}

inline std::set<std::string> configuredFail2banJails() {
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

inline std::set<std::string> runningFail2banJails() {
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

inline std::vector<F2bPolicyInfo> collectFail2banPolicies(bool includeRuntimeStatus) {
    std::set<std::string> names = configuredFail2banJails();
    const std::set<std::string> running = runningFail2banJails();
    names.insert(running.begin(), running.end());

    std::vector<F2bPolicyInfo> policies;
    for (const auto &name : names) {
        F2bPolicyInfo info;
        info.name = name;
        info.role = policyRoleForJail(name);
        info.managedDefault = name == kRule1Jail || name == kRule2Jail;
        info.config = readJailConfig(name);
        info.filter = readJailValue(name, "filter");
        info.backend = readJailValue(name, "backend");
        info.logpath = readJailValue(name, "logpath");
        info.port = readJailValue(name, "port");
        const bool configuredEnabled = lowerCopy(configValueOr(info.config.enabled, running.count(name) ? "true" : "false")) == "true";
        info.state = running.count(name) ? "运行中" : (configuredEnabled ? "已配置/待重载" : "未启用");
        if (includeRuntimeStatus && running.count(name)) {
            info.bannedCount = bannedSetForJail(name).size();
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

inline std::vector<std::string> customFail2banJailNames() {
    std::vector<std::string> out;
    for (const auto &policy : collectFail2banPolicies(false)) {
        if (!policy.managedDefault && policy.name != "DEFAULT") {
            out.push_back(policy.name);
        }
    }
    return out;
}

inline std::map<std::string, std::string> listeningProcesses() {
    std::map<std::string, std::string> out;
    const CommandResult result = Shell::capture("ss -lntupH 2>/dev/null || true");
    static const std::regex portPattern(R"(:([0-9]+)\s)");
    static const std::regex procPattern(R"(users:\(\(\"([^\"]+)\".*pid=([0-9]+))");
    for (const auto &line : splitLines(result.output)) {
        std::smatch portMatch;
        if (!std::regex_search(line, portMatch, portPattern)) {
            continue;
        }
        std::string proc = "-";
        std::smatch procMatch;
        if (std::regex_search(line, procMatch, procPattern)) {
            proc = procMatch[1].str() + "(" + procMatch[2].str() + ")";
        }
        out[portMatch[1].str()] = proc;
    }
    return out;
}

inline std::string serviceNameForPort(const std::string &port) {
    static const std::map<std::string, std::string> common = {
        {"20", "FTP data"}, {"21", "FTP"}, {"22", "SSH"}, {"23", "Telnet"},
        {"25", "SMTP"}, {"53", "DNS"}, {"67", "DHCP"}, {"68", "DHCP"},
        {"80", "HTTP"}, {"110", "POP3"}, {"123", "NTP"}, {"143", "IMAP"},
        {"161", "SNMP"}, {"389", "LDAP"}, {"443", "HTTPS"}, {"445", "SMB"},
        {"465", "SMTPS"}, {"587", "SMTP submit"}, {"993", "IMAPS"},
        {"995", "POP3S"}, {"1433", "MSSQL"}, {"1521", "Oracle"},
        {"2049", "NFS"}, {"2375", "Docker"}, {"2376", "Docker TLS"},
        {"3306", "MySQL"}, {"3389", "RDP"}, {"5432", "PostgreSQL"},
        {"5900", "VNC"}, {"6379", "Redis"}, {"8080", "HTTP alt"},
        {"8443", "HTTPS alt"}, {"9200", "Elasticsearch"},
        {"11211", "Memcached"}, {"27017", "MongoDB"}};
    const auto found = common.find(port);
    return found == common.end() ? "-" : found->second;
}

inline bool parseIsoLogTime(const std::string &line, std::time_t &ts) {
    std::smatch match;
    static const std::regex isoPattern(R"(^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2}))");
    if (!std::regex_search(line, match, isoPattern)) {
        return false;
    }
    std::tm tm{};
    tm.tm_year = std::stoi(match[1].str()) - 1900;
    tm.tm_mon = std::stoi(match[2].str()) - 1;
    tm.tm_mday = std::stoi(match[3].str());
    tm.tm_hour = std::stoi(match[4].str());
    tm.tm_min = std::stoi(match[5].str());
    tm.tm_sec = std::stoi(match[6].str());
    ts = makeLocalTime(tm);
    return ts != static_cast<std::time_t>(-1);
}

inline int monthIndex(const std::string &mon) {
    static const std::vector<std::string> months = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (std::size_t i = 0; i < months.size(); ++i) {
        if (mon == months[i]) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

inline bool parseSyslogTime(const std::string &line, std::time_t &ts) {
    std::smatch match;
    static const std::regex syslogPattern(R"(^([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}):([0-9]{2}):([0-9]{2}))");
    if (!std::regex_search(line, match, syslogPattern)) {
        return false;
    }
    const int mon = monthIndex(match[1].str());
    if (mon < 0) {
        return false;
    }
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    tm.tm_mon = mon;
    tm.tm_mday = std::stoi(match[2].str());
    tm.tm_hour = std::stoi(match[3].str());
    tm.tm_min = std::stoi(match[4].str());
    tm.tm_sec = std::stoi(match[5].str());
    ts = makeLocalTime(tm);
    if (ts > now + 86400 * 7) {
        tm.tm_year -= 1;
        ts = makeLocalTime(tm);
    }
    return ts != static_cast<std::time_t>(-1);
}

inline bool parseUfwLogEvent(const std::string &line, UfwLogEvent &event) {
    std::smatch match;
    static const std::regex actionPattern(R"(\[UFW (BLOCK|AUDIT|ALLOW)\])");
    static const std::regex srcPattern(R"(\bSRC=([0-9A-Fa-f:.]+)\b)");
    static const std::regex dptPattern(R"(\bDPT=([0-9]+)\b)");
    if (!std::regex_search(line, match, actionPattern)) {
        return false;
    }
    event = {};
    event.action = match[1].str();
    if (!parseIsoLogTime(line, event.ts)) {
        parseSyslogTime(line, event.ts);
    }
    if (event.ts <= 0) {
        event.ts = std::time(nullptr);
    }
    event.day = dateStamp(event.ts);
    if (!std::regex_search(line, match, srcPattern)) {
        return false;
    }
    event.src = match[1].str();
    if (!isValidIpOrCidr(event.src) || event.src.find('/') != std::string::npos) {
        return false;
    }
    if (std::regex_search(line, match, dptPattern)) {
        event.dpt = match[1].str();
    }
    return !event.src.empty();
}

inline std::string ufwEventKey(const UfwLogEvent &event) {
    return std::to_string(static_cast<long long>(event.ts)) + "|" + event.action + "|" + event.src + "|" + event.dpt;
}

inline std::vector<std::pair<std::time_t, std::time_t>> readUfwCacheRanges() {
    std::vector<std::pair<std::time_t, std::time_t>> ranges;
    std::ifstream input(kUfwCacheDir + "/ranges.tsv", std::ios::binary);
    if (!input) {
        return ranges;
    }
    std::string line;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 2) {
            continue;
        }
        try {
            ranges.push_back({static_cast<std::time_t>(std::stoll(parts[0])),
                              static_cast<std::time_t>(std::stoll(parts[1]))});
        } catch (...) {
            continue;
        }
    }
    std::sort(ranges.begin(), ranges.end());
    return ranges;
}

inline bool rangeCovered(std::time_t start, std::time_t end, const std::vector<std::pair<std::time_t, std::time_t>> &ranges) {
    std::time_t cursor = start;
    for (const auto &range : ranges) {
        if (range.second < cursor) {
            continue;
        }
        if (range.first > cursor) {
            return false;
        }
        cursor = std::max(cursor, range.second);
        if (cursor >= end) {
            return true;
        }
    }
    return cursor >= end;
}

inline std::vector<std::pair<std::time_t, std::time_t>> mergeRanges(std::vector<std::pair<std::time_t, std::time_t>> ranges) {
    if (ranges.empty()) {
        return {};
    }
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<std::time_t, std::time_t>> merged;
    for (const auto &range : ranges) {
        if (range.first >= range.second) {
            continue;
        }
        if (merged.empty() || range.first > merged.back().second + 1) {
            merged.push_back(range);
        } else {
            merged.back().second = std::max(merged.back().second, range.second);
        }
    }
    return merged;
}

inline std::vector<std::pair<std::time_t, std::time_t>> missingRanges(std::time_t start,
                                                                       std::time_t end,
                                                                       std::vector<std::pair<std::time_t, std::time_t>> ranges) {
    std::vector<std::pair<std::time_t, std::time_t>> missing;
    if (start >= end) {
        return missing;
    }
    std::sort(ranges.begin(), ranges.end());
    std::time_t cursor = start;
    for (const auto &range : ranges) {
        if (range.second <= cursor) {
            continue;
        }
        if (range.first > cursor) {
            missing.push_back({cursor, std::min(range.first, end)});
        }
        cursor = std::max(cursor, range.second);
        if (cursor >= end) {
            break;
        }
    }
    if (cursor < end) {
        missing.push_back({cursor, end});
    }
    return missing;
}

inline void writeUfwCacheRanges(std::vector<std::pair<std::time_t, std::time_t>> ranges) {
    if (ranges.empty()) {
        return;
    }
    const auto merged = mergeRanges(std::move(ranges));
    std::ostringstream out;
    for (const auto &range : merged) {
        out << static_cast<long long>(range.first) << "\t" << static_cast<long long>(range.second) << "\n";
    }
    writeTextFile(kUfwCacheDir + "/ranges.tsv", out.str());
}

inline std::vector<UfwLogEvent> readUfwCacheEvents(std::time_t start, std::time_t end) {
    std::vector<UfwLogEvent> events;
    std::ifstream input(kUfwCacheDir + "/events.tsv", std::ios::binary);
    if (!input) {
        return events;
    }
    std::string line;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() < 5) {
            continue;
        }
        UfwLogEvent event;
        try {
            event.ts = static_cast<std::time_t>(std::stoll(parts[0]));
        } catch (...) {
            continue;
        }
        if (event.ts < start || event.ts > end) {
            continue;
        }
        event.day = parts[1];
        event.action = parts[2];
        event.src = parts[3];
        event.dpt = parts[4];
        events.push_back(event);
    }
    return events;
}

inline std::string ufwCacheActivityPath() {
    return kUfwCacheDir + "/last_activity";
}

inline std::time_t readUfwCacheActivity() {
    std::string content;
    if (!readTextFile(ufwCacheActivityPath(), content)) {
        return 0;
    }
    content = trim(content);
    if (content.empty()) {
        return 0;
    }
    for (unsigned char ch : content) {
        if (!std::isdigit(ch)) {
            return 0;
        }
    }
    return static_cast<std::time_t>(std::stoll(content));
}

inline void touchUfwCacheActivity() {
    ensureDirectory(kUfwCacheDir);
    writeTextFile(ufwCacheActivityPath(), std::to_string(static_cast<long long>(std::time(nullptr))) + "\n");
}

inline void clearUfwAnalysisCacheFiles() {
    std::remove((kUfwCacheDir + "/events.tsv").c_str());
    std::remove((kUfwCacheDir + "/ranges.tsv").c_str());
}

inline void pruneIdleUfwCacheIfNeeded() {
    ensureDirectory(kUfwCacheDir);
    const std::time_t last = readUfwCacheActivity();
    if (last <= 0) {
        return;
    }
    const std::time_t now = std::time(nullptr);
    if (now - last > static_cast<std::time_t>(kUfwCacheIdleDays) * 86400) {
        clearUfwAnalysisCacheFiles();
    }
}

inline std::size_t countFileLines(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return 0;
    }
    std::size_t count = 0;
    std::string line;
    while (std::getline(input, line)) {
        ++count;
    }
    return count;
}

inline std::uint64_t fileSizeBytes(const std::string &path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        return 0;
    }
    return static_cast<std::uint64_t>(std::max<std::streamoff>(0, input.tellg()));
}

inline void writeUfwCacheEvents(const std::vector<UfwLogEvent> &newEvents) {
    ensureDirectory(kUfwCacheDir);
    std::set<std::string> seen;
    {
        std::ifstream input(kUfwCacheDir + "/events.tsv", std::ios::binary);
        std::string line;
        while (std::getline(input, line)) {
            const auto parts = splitByChar(line, '\t');
            if (parts.size() < 5) {
                continue;
            }
            seen.insert(parts[0] + "|" + parts[2] + "|" + parts[3] + "|" + parts[4]);
        }
    }
    std::ofstream output(kUfwCacheDir + "/events.tsv", std::ios::binary | std::ios::app);
    if (!output) {
        return;
    }
    for (const auto &event : newEvents) {
        if (seen.insert(ufwEventKey(event)).second) {
            output << static_cast<long long>(event.ts) << "\t" << event.day << "\t"
                   << event.action << "\t" << event.src << "\t" << event.dpt << "\n";
        }
    }
}

inline std::vector<UfwLogEvent> loadLiveUfwEvents(std::time_t start, std::time_t end, std::string &sourceNote);

#if LTG_HAS_SQLITE
inline std::string ufwCacheDbPath() {
    return kUfwCacheDir + "/events.sqlite3";
}

inline bool sqliteExec(sqlite3 *db, const std::string &sql) {
    char *error = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &error);
    if (error) {
        sqlite3_free(error);
    }
    return rc == SQLITE_OK;
}

inline sqlite3 *openUfwCacheDb() {
    ensureDirectory(kUfwCacheDir);
    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(ufwCacheDbPath().c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        return nullptr;
    }
    sqlite3_busy_timeout(db, 1500);
    sqliteExec(db, "PRAGMA journal_mode=WAL;");
    sqliteExec(db, "PRAGMA synchronous=NORMAL;");
    sqliteExec(db,
               "CREATE TABLE IF NOT EXISTS events("
               "ts INTEGER NOT NULL,"
               "day TEXT NOT NULL,"
               "action TEXT NOT NULL,"
               "src TEXT NOT NULL,"
               "dpt TEXT NOT NULL DEFAULT '',"
               "UNIQUE(ts, action, src, dpt));"
               "CREATE TABLE IF NOT EXISTS loaded_ranges("
               "start_ts INTEGER NOT NULL,"
               "end_ts INTEGER NOT NULL);"
               "CREATE TABLE IF NOT EXISTS meta("
               "key TEXT PRIMARY KEY,"
               "value TEXT NOT NULL);"
               "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"
               "CREATE INDEX IF NOT EXISTS idx_events_src_ts ON events(src, ts);"
               "CREATE INDEX IF NOT EXISTS idx_events_dpt_ts ON events(dpt, ts);"
               "CREATE INDEX IF NOT EXISTS idx_events_action_ts ON events(action, ts);"
               "CREATE INDEX IF NOT EXISTS idx_events_src_dpt_ts ON events(src, dpt, ts);");
    return db;
}

inline std::vector<std::pair<std::time_t, std::time_t>> sqliteReadUfwRanges(sqlite3 *db) {
    std::vector<std::pair<std::time_t, std::time_t>> ranges;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT start_ts, end_ts FROM loaded_ranges ORDER BY start_ts;", -1, &stmt, nullptr) != SQLITE_OK) {
        return ranges;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ranges.push_back({static_cast<std::time_t>(sqlite3_column_int64(stmt, 0)),
                          static_cast<std::time_t>(sqlite3_column_int64(stmt, 1))});
    }
    sqlite3_finalize(stmt);
    return ranges;
}

inline void sqliteWriteUfwRanges(sqlite3 *db, std::vector<std::pair<std::time_t, std::time_t>> ranges) {
    if (ranges.empty()) {
        return;
    }
    const auto merged = mergeRanges(std::move(ranges));
    sqliteExec(db, "BEGIN IMMEDIATE;");
    sqliteExec(db, "DELETE FROM loaded_ranges;");
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "INSERT INTO loaded_ranges(start_ts, end_ts) VALUES(?, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
        for (const auto &range : merged) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(range.first));
            sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(range.second));
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        }
    }
    sqlite3_finalize(stmt);
    sqliteExec(db, "COMMIT;");
}

inline void sqliteTouchUfwCache(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "INSERT INTO meta(key, value) VALUES('last_activity', ?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(std::time(nullptr)));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

inline std::time_t sqliteReadUfwActivity(sqlite3 *db) {
    sqlite3_stmt *stmt = nullptr;
    std::time_t out = 0;
    if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='last_activity';", -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        out = static_cast<std::time_t>(sqlite3_column_int64(stmt, 0));
    }
    sqlite3_finalize(stmt);
    return out;
}

inline void sqliteClearUfwCache(sqlite3 *db) {
    sqliteExec(db, "DELETE FROM events;");
    sqliteExec(db, "DELETE FROM loaded_ranges;");
    sqliteExec(db, "VACUUM;");
}

inline void sqlitePruneIdleUfwCache(sqlite3 *db) {
    const std::time_t last = sqliteReadUfwActivity(db);
    if (last > 0 && std::time(nullptr) - last > static_cast<std::time_t>(kUfwCacheIdleDays) * 86400) {
        sqliteClearUfwCache(db);
    }
}

inline void sqliteInsertUfwEvents(sqlite3 *db, const std::vector<UfwLogEvent> &events) {
    sqliteExec(db, "BEGIN IMMEDIATE;");
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           "INSERT OR IGNORE INTO events(ts, day, action, src, dpt) VALUES(?, ?, ?, ?, ?);",
                           -1, &stmt, nullptr) == SQLITE_OK) {
        for (const auto &event : events) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(event.ts));
            sqlite3_bind_text(stmt, 2, event.day.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, event.action.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, event.src.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, event.dpt.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        }
    }
    sqlite3_finalize(stmt);
    sqliteExec(db, "COMMIT;");
}

inline std::int64_t sqliteCountScalar(sqlite3 *db, const std::string &sql, std::time_t start, std::time_t end) {
    sqlite3_stmt *stmt = nullptr;
    std::int64_t out = 0;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out = sqlite3_column_int64(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return out;
}

inline std::int64_t sqliteSimpleCount(sqlite3 *db, const std::string &sql) {
    sqlite3_stmt *stmt = nullptr;
    std::int64_t out = 0;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return out;
}

inline UfwAnalysisReport sqliteBuildUfwReport(sqlite3 *db,
                                              const std::string &title,
                                              std::time_t start,
                                              std::time_t end,
                                              const std::string &sourceNote) {
    UfwAnalysisReport report;
    report.title = title;
    report.start = start;
    report.end = end;
    report.sourceNote = sourceNote;
    report.validLines = static_cast<std::size_t>(
        sqliteCountScalar(db, "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ?;", start, end));

    auto run3 = [&](const std::string &sql, const std::function<void(const char *, const char *, int)> &fn) {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *a = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            const char *b = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            const int c = sqlite3_column_int(stmt, 2);
            fn(a ? a : "", b ? b : "", c);
        }
        sqlite3_finalize(stmt);
    };

    run3("SELECT src, day, count(*) FROM events "
         "WHERE ts BETWEEN ? AND ? AND action IN ('BLOCK','AUDIT') "
         "GROUP BY src, day;",
         [&](const char *src, const char *day, int count) {
             report.ipDaily[src][day] += count;
         });
    run3("SELECT dpt, day, count(*) FROM events "
         "WHERE ts BETWEEN ? AND ? AND action IN ('BLOCK','AUDIT') AND dpt != '' "
         "GROUP BY dpt, day;",
         [&](const char *dpt, const char *day, int count) {
             report.portDaily[dpt][day] += count;
         });

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           "SELECT src, dpt, day, count(*) FROM events "
                           "WHERE ts BETWEEN ? AND ? AND action IN ('BLOCK','AUDIT') AND dpt != '' "
                           "GROUP BY src, dpt, day;",
                           -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *src = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            const char *dpt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            const char *day = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            const int count = sqlite3_column_int(stmt, 3);
            report.ipPortDaily[src ? src : ""][dpt ? dpt : ""][day ? day : ""] += count;
        }
    }
    sqlite3_finalize(stmt);

    const std::time_t allowCutoff = std::time(nullptr) - 3 * 86400;
    if (sqlite3_prepare_v2(db,
                           "SELECT src, ts FROM events WHERE ts BETWEEN ? AND ? AND action='ALLOW' AND ts >= ? ORDER BY ts DESC LIMIT 200;",
                           -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
        sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(allowCutoff));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *src = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            report.allowRecent.push_back({src ? src : "", static_cast<std::time_t>(sqlite3_column_int64(stmt, 1))});
        }
    }
    sqlite3_finalize(stmt);
    return report;
}

inline UfwAnalysisReport analyzeUfwEventsSqlite(const std::string &title,
                                                std::time_t start,
                                                std::time_t end,
                                                bool forceRefresh = false) {
    sqlite3 *db = openUfwCacheDb();
    if (!db) {
        UfwAnalysisReport report;
        report.title = title;
        report.start = start;
        report.end = end;
        report.sourceNote = "SQLite 打开失败";
        return report;
    }
    sqlitePruneIdleUfwCache(db);
    auto ranges = sqliteReadUfwRanges(db);
    std::string sourceNote = "SQLite 缓存";
    if (forceRefresh) {
        sqliteClearUfwCache(db);
        ranges.clear();
    }
    const auto gaps = missingRanges(start, end, ranges);
    if (!gaps.empty()) {
        std::vector<UfwLogEvent> loaded;
        std::string liveNote;
        for (const auto &gap : gaps) {
            std::string note;
            auto part = loadLiveUfwEvents(gap.first, gap.second, note);
            if (!note.empty() && liveNote.empty()) {
                liveNote = note;
            }
            loaded.insert(loaded.end(), part.begin(), part.end());
            ranges.push_back(gap);
        }
        sqliteInsertUfwEvents(db, loaded);
        sqliteWriteUfwRanges(db, ranges);
        sourceNote = liveNote.empty() ? "SQLite 缓存(补缺口)" : liveNote + " -> SQLite";
    }
    sqliteTouchUfwCache(db);
    UfwAnalysisReport report = sqliteBuildUfwReport(db, title, start, end, sourceNote);
    sqlite3_close(db);
    return report;
}
#endif

inline std::vector<UfwLogEvent> loadLiveUfwEvents(std::time_t start, std::time_t end, std::string &sourceNote) {
    std::vector<UfwLogEvent> events;
    const std::string since = dateTimeStamp(start);
    const std::string until = dateTimeStamp(end);
    std::string output;
    if (Shell::exists("journalctl")) {
        const std::string command = "journalctl -k --no-pager -o short-iso --since " + shellQuote(since) +
                                    " --until " + shellQuote(until) +
                                    " 2>/dev/null | grep -E '\\[UFW (BLOCK|AUDIT|ALLOW)\\]' || true";
        output = Shell::capture(command).output;
        if (!trim(output).empty()) {
            sourceNote = "journalctl -k";
        }
    }
    if (trim(output).empty()) {
        const std::string command =
            "(zgrep -h -E '\\[UFW (BLOCK|AUDIT|ALLOW)\\]' /var/log/ufw.log* /var/log/kern.log* /var/log/syslog* /var/log/messages* 2>/dev/null || "
            "grep -h -E '\\[UFW (BLOCK|AUDIT|ALLOW)\\]' /var/log/ufw.log /var/log/kern.log /var/log/syslog /var/log/messages 2>/dev/null || true)";
        output = Shell::capture(command).output;
        sourceNote = trim(output).empty() ? "无可用 UFW 日志" : "文件日志";
    }
    for (const auto &line : splitLines(output)) {
        UfwLogEvent event;
        if (!parseUfwLogEvent(line, event)) {
            continue;
        }
        if (event.ts < start || event.ts > end) {
            continue;
        }
        events.push_back(event);
    }
    return events;
}

inline UfwAnalysisReport analyzeUfwEvents(const std::string &title,
                                          std::time_t start,
                                          std::time_t end,
                                          bool forceRefresh = false) {
    const std::time_t now = std::time(nullptr);
    if (end > now - 120 && end > start) {
        const std::time_t span = end - start;
        end = end - (end % 60);
        start = std::max<std::time_t>(0, end - span);
    }
#if LTG_HAS_SQLITE
    return analyzeUfwEventsSqlite(title, start, end, forceRefresh);
#else
    ensureDirectory(kUfwCacheDir);
    pruneIdleUfwCacheIfNeeded();
    UfwAnalysisReport report;
    report.title = title;
    report.start = start;
    report.end = end;
    std::vector<std::pair<std::time_t, std::time_t>> ranges = readUfwCacheRanges();
    std::vector<UfwLogEvent> events;
    if (!forceRefresh && rangeCovered(start, end, ranges)) {
        events = readUfwCacheEvents(start, end);
        report.sourceNote = "文本缓存";
    } else {
        events = loadLiveUfwEvents(start, end, report.sourceNote);
        writeUfwCacheEvents(events);
        ranges.push_back({start, end});
        writeUfwCacheRanges(ranges);
    }
    touchUfwCacheActivity();
    report.validLines = events.size();
    const std::time_t allowCutoff = std::time(nullptr) - 3 * 86400;
    for (const auto &event : events) {
        if (event.action == "ALLOW") {
            if (event.ts >= allowCutoff) {
                report.allowRecent.push_back({event.src, event.ts});
            }
            continue;
        }
        report.ipDaily[event.src][event.day] += 1;
        if (!event.dpt.empty()) {
            report.portDaily[event.dpt][event.day] += 1;
            report.ipPortDaily[event.src][event.dpt][event.day] += 1;
        }
    }
    return report;
#endif
}

inline std::vector<std::pair<std::string, int>> sortedCounter(const std::map<std::string, int> &counter) {
    std::vector<std::pair<std::string, int>> rows(counter.begin(), counter.end());
    std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });
    return rows;
}

inline std::vector<DualAuditRow> buildDualAuditRows(std::time_t start, std::time_t end, int limit = 30) {
    std::string sourceNote;
    const auto events = loadLiveUfwEvents(start, end, sourceNote);
    std::map<std::string, int> hits;
    for (const auto &event : events) {
        if (event.action == "BLOCK" || event.action == "AUDIT") {
            hits[event.src] += 1;
        }
    }
    const std::set<std::string> rule1 = bannedSetForJail(kRule1Jail);
    const std::set<std::string> rule2 = bannedSetForJail(kRule2Jail);
    const F2bJailConfig cfg = readJailConfig(kRule2Jail);
    int threshold = 50;
    if (isValidPositiveInt(configValueOr(cfg.maxretry, "50"))) {
        threshold = std::stoi(configValueOr(cfg.maxretry, "50"));
    }
    std::string banLog = Shell::capture("journalctl -u fail2ban --no-pager --since " + shellQuote(dateTimeStamp(start)) +
                                        " 2>/dev/null | grep ' Ban ' || grep -h ' Ban ' /var/log/fail2ban.log* 2>/dev/null || true").output;
    std::vector<DualAuditRow> rows;
    for (const auto &item : sortedCounter(hits)) {
        if (static_cast<int>(rows.size()) >= limit) {
            break;
        }
        DualAuditRow row;
        row.ip = item.first;
        row.ufwHits = item.second;
        row.rule1Banned = rule1.count(item.first) > 0;
        row.rule2Banned = rule2.count(item.first) > 0;
        row.banLogged = banLog.find(item.first) != std::string::npos;
        if (row.rule2Banned) {
            row.conclusion = "已升级全端口封禁";
        } else if (row.rule1Banned) {
            row.conclusion = "已被规则1封禁";
        } else if (row.ufwHits >= threshold) {
            row.conclusion = "达到规则2阈值但未封禁";
        } else if (row.banLogged) {
            row.conclusion = "窗口内曾封禁";
        } else {
            row.conclusion = "仅 UFW 拦截";
        }
        rows.push_back(row);
    }
    return rows;
}

inline std::vector<std::string> dualAuditCandidateIps(const std::vector<DualAuditRow> &rows) {
    std::vector<std::string> out;
    for (const auto &row : rows) {
        if (row.conclusion == "达到规则2阈值但未封禁") {
            out.push_back(row.ip);
        }
    }
    return out;
}

inline UfwSshExposure inspectUfwSshExposure() {
    UfwSshExposure exposure;
    const std::string listeners = Shell::capture("ss -lntpH 2>/dev/null | grep -Ei 'sshd|ssh' || true").output;
    const std::regex portPattern(R"(:([0-9]+)\s)");
    for (const auto &line : splitLines(listeners)) {
        std::smatch match;
        if (std::regex_search(line, match, portPattern)) {
            const std::string port = match[1].str();
            if (std::find(exposure.sshPorts.begin(), exposure.sshPorts.end(), port) == exposure.sshPorts.end()) {
                exposure.sshPorts.push_back(port);
            }
        }
    }
    if (exposure.sshPorts.empty()) {
        exposure.sshPorts.push_back("22");
    }

    const std::string ufw = Shell::capture("ufw status numbered 2>/dev/null || true").output;
    for (const auto &line : splitLines(ufw)) {
        const std::string lower = lowerCopy(line);
        if (lower.find("allow") == std::string::npos) {
            continue;
        }
        bool matches = lower.find("openssh") != std::string::npos;
        for (const auto &port : exposure.sshPorts) {
            const std::regex portRule("(^|[^0-9])" + port + "(/tcp|/udp)?([^0-9]|$)");
            if (std::regex_search(line, portRule)) {
                matches = true;
                break;
            }
        }
        if (!matches) {
            const std::regex port22("(^|[^0-9])22(/tcp|/udp)?([^0-9]|$)");
            matches = std::regex_search(line, port22);
        }
        if (matches) {
            exposure.allowRules.push_back(line);
        }
    }
    return exposure;
}

inline std::vector<UfwDeleteCandidate> findUfwAnomalyDeleteCandidates() {
    const std::string status = Shell::capture("ufw status numbered 2>/dev/null || true").output;
    std::set<std::string> banned;
    for (const auto &ip : bannedSetForJail(kRule1Jail)) banned.insert(ip);
    for (const auto &ip : bannedSetForJail(kRule2Jail)) banned.insert(ip);

    std::map<std::string, std::vector<UfwDeleteCandidate>> byIp;
    const std::regex linePattern(R"(\[\s*([0-9]+)\].*DENY.*from\s+([0-9A-Fa-f:./]+).*(f2b:|f2b-))");
    for (const auto &line : splitLines(status)) {
        std::smatch match;
        if (std::regex_search(line, match, linePattern)) {
            UfwDeleteCandidate candidate;
            candidate.number = std::stoi(match[1].str());
            candidate.ip = match[2].str();
            candidate.line = line;
            byIp[candidate.ip].push_back(candidate);
        }
    }

    std::vector<UfwDeleteCandidate> out;
    for (auto &item : byIp) {
        auto &rules = item.second;
        std::sort(rules.begin(), rules.end(), [](const UfwDeleteCandidate &a, const UfwDeleteCandidate &b) {
            return a.number < b.number;
        });
        if (banned.count(item.first) == 0) {
            for (auto candidate : rules) {
                candidate.reason = "fail2ban 当前封禁列表中不存在该 IP";
                out.push_back(candidate);
            }
        } else if (rules.size() > 1) {
            for (std::size_t i = 1; i < rules.size(); ++i) {
                UfwDeleteCandidate candidate = rules[i];
                candidate.reason = "重复 f2b deny，保留编号 " + std::to_string(rules.front().number);
                out.push_back(candidate);
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const UfwDeleteCandidate &a, const UfwDeleteCandidate &b) {
        return a.number < b.number;
    });
    return out;
}

class Table {
public:
    Table(std::vector<std::string> headers, std::vector<std::size_t> widths)
        : headers_(std::move(headers)), widths_(std::move(widths)) {}

    void add(std::vector<std::string> row) {
        rows_.push_back(std::move(row));
    }

    bool empty() const {
        return rows_.empty();
    }

    void print(const std::string &emptyMessage = "暂无数据") const {
        printRow(headers_, true);
        printRule();
        if (rows_.empty()) {
            std::cout << "  " << colorIf("- " + emptyMessage, ansi::gray) << "\n";
        } else {
            for (const auto &row : rows_) {
                printRow(row, false);
            }
        }
    }

private:
    std::vector<std::string> headers_;
    std::vector<std::size_t> widths_;
    std::vector<std::vector<std::string>> rows_;

    std::size_t contentWidth() const {
        std::size_t width = 0;
        for (auto column : widths_) {
            width += column + 3;
        }
        return width > 1 ? width - 1 : width;
    }

    void printRule() const {
        const std::size_t width = std::min<std::size_t>(contentWidth(), 86);
        std::cout << "  " << colorIf(std::string(width, '-'), ansi::gray) << "\n";
    }

    void printRow(const std::vector<std::string> &row, bool strong) const {
        std::cout << "  ";
        for (std::size_t i = 0; i < widths_.size(); ++i) {
            const std::string value = i < row.size() ? truncateText(row[i], widths_[i]) : "";
            if (strong && shouldUseColor()) {
                std::cout << ansi::bold;
            }
            std::cout << std::left << std::setw(static_cast<int>(widths_[i])) << value;
            if (strong && shouldUseColor()) {
                std::cout << ansi::plain;
            }
            if (i + 1 < widths_.size()) {
                std::cout << "  ";
            }
        }
        std::cout << "\n";
    }
};

class Ui {
public:
    static std::string badge(const std::string &label, const std::string &color) {
        return color + "[" + label + "]" + ansi::plain;
    }

    static std::string statusBadge(bool ok, const std::string &okText = "可用", const std::string &badText = "缺失") {
        return ok ? badge(okText, ansi::green) : badge(badText, ansi::yellow);
    }
};

inline void activateTerminalDisplay() {
    if (!pauseEnabled()) {
        return;
    }
#ifndef _WIN32
    if (isatty(STDIN_FILENO)) {
        termios current{};
        if (tcgetattr(STDIN_FILENO, &current) == 0) {
            savedTerminalMode() = current;
            savedTerminalModeValid() = true;
            current.c_lflag &= static_cast<unsigned long>(~(ICANON | ECHO | ECHOCTL));
            current.c_cc[VMIN] = 1;
            current.c_cc[VTIME] = 0;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &current) == 0) {
                promptModeActive() = true;
            }
        }
    }
#endif
    alternateScreenActive() = true;
    std::cout << "\033[?1049h\033[?7l\033[?1000h\033[?1006h\033[?25h\033[2J\033[H";
    std::cout.flush();
}

class TerminalGuard {
public:
    TerminalGuard() {
        installSignalHandlers();
        activateTerminalDisplay();
    }

    ~TerminalGuard() {
        restoreTerminalDisplay();
    }

    TerminalGuard(const TerminalGuard &) = delete;
    TerminalGuard &operator=(const TerminalGuard &) = delete;
};

inline int terminalRows() {
#ifndef _WIN32
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 8) {
        return ws.ws_row;
    }
#endif
    return 28;
}

inline int terminalCols() {
#ifndef _WIN32
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 40) {
        return ws.ws_col;
    }
#endif
    return 100;
}

class InputReader {
public:
    InputEvent readEvent(int timeoutMs) {
        fill(timeoutMs);
        if (buffer_.empty()) {
            return {InputKind::None, 0};
        }
        const unsigned char ch = pop();
        if (ch == 3) {
            return {InputKind::CtrlC, 0};
        }
        if (ch == '\r' || ch == '\n') {
            return {InputKind::Character, '\n'};
        }
        if (ch == 27) {
            return parseEscape();
        }
        return {InputKind::Character, static_cast<char>(ch)};
    }

    void drain() {
        buffer_.clear();
        fill(0);
        buffer_.clear();
    }

private:
    std::deque<unsigned char> buffer_;

    unsigned char pop() {
        const unsigned char ch = buffer_.front();
        buffer_.pop_front();
        return ch;
    }

    void fill(int timeoutMs) {
#ifdef _WIN32
        (void)timeoutMs;
        if (buffer_.empty()) {
            char ch = 0;
            if (std::cin.get(ch)) {
                buffer_.push_back(static_cast<unsigned char>(ch));
            }
        }
#else
        fd_set set;
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        timeval timeout{};
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;
        const int ready = select(STDIN_FILENO + 1, &set, nullptr, nullptr, &timeout);
        if (ready <= 0) {
            return;
        }
        unsigned char bytes[128]{};
        const ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
        if (count <= 0) {
            return;
        }
        for (ssize_t i = 0; i < count; ++i) {
            buffer_.push_back(bytes[i]);
        }
#endif
    }

    bool needMoreEscapeBytes(const std::string &seq) const {
        if (seq.empty()) {
            return true;
        }
        if (seq[0] == '[') {
            if (seq.size() == 1) {
                return true;
            }
            if (seq[1] == '<') {
                const char last = seq.back();
                return last != 'M' && last != 'm';
            }
            const unsigned char last = static_cast<unsigned char>(seq.back());
            return !(last >= 0x40 && last <= 0x7e);
        }
        if (seq[0] == 'O') {
            return seq.size() < 2;
        }
        return false;
    }

    InputEvent parseEscape() {
        std::string seq;
        const auto start = std::chrono::steady_clock::now();
        while (seq.size() < 96) {
            if (buffer_.empty()) {
                fill(18);
                if (buffer_.empty()) {
                    break;
                }
            }
            seq.push_back(static_cast<char>(pop()));
            if (!needMoreEscapeBytes(seq)) {
                break;
            }
            if (std::chrono::steady_clock::now() - start > std::chrono::milliseconds(90)) {
                break;
            }
        }
        if (seq.empty()) {
            return {InputKind::Escape, 0};
        }
        if (seq == "[A" || seq == "OA") return {InputKind::Up, 0};
        if (seq == "[B" || seq == "OB") return {InputKind::Down, 0};
        if (seq == "[5~") return {InputKind::PageUp, 0};
        if (seq == "[6~") return {InputKind::PageDown, 0};
        if (seq == "[H" || seq == "[1~" || seq == "OH") return {InputKind::Home, 0};
        if (seq == "[F" || seq == "[4~" || seq == "OF") return {InputKind::End, 0};
        if (!seq.empty() && seq[0] == '[') {
            const char last = seq.back();
            if (last == 'A') return {InputKind::Up, 0};
            if (last == 'B') return {InputKind::Down, 0};
            if (last == 'H') return {InputKind::Home, 0};
            if (last == 'F') return {InputKind::End, 0};
            if (last == '~' && seq.size() >= 2 && seq[1] == '5') return {InputKind::PageUp, 0};
            if (last == '~' && seq.size() >= 2 && seq[1] == '6') return {InputKind::PageDown, 0};
        }

        std::smatch match;
        const std::regex mousePattern(R"(\[<([0-9]+);([0-9]+);([0-9]+)([Mm]))");
        if (std::regex_match(seq, match, mousePattern)) {
            int button = 0;
            for (unsigned char ch : match[1].str()) {
                button = button * 10 + (ch - '0');
                if (button > 1000) {
                    return {InputKind::None, 0};
                }
            }
            if (button == 64) return {InputKind::MouseUp, 0};
            if (button == 65) return {InputKind::MouseDown, 0};
        }
        return {InputKind::None, 0};
    }
};

inline InputReader &inputReader() {
    static InputReader reader;
    return reader;
}

inline InputEvent readInputEvent(int timeoutMs) {
    return inputReader().readEvent(timeoutMs);
}

class ScreenBuffer {
public:
    void add(const std::string &line = "") {
        lines_.push_back(line);
    }

    void addAll(const std::vector<std::string> &lines) {
        for (const auto &line : lines) {
            add(line);
        }
    }

    const std::vector<std::string> &lines() const {
        return lines_;
    }

    std::size_t size() const {
        return lines_.size();
    }

private:
    std::vector<std::string> lines_;
};

inline bool readAnsiSequence(const std::string &value, std::size_t &index, std::string &sequence) {
    if (index >= value.size() || value[index] != '\033') {
        return false;
    }
    sequence.clear();
    sequence.push_back(value[index++]);
    if (index >= value.size()) {
        return true;
    }
    sequence.push_back(value[index++]);
    while (index < value.size()) {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        sequence.push_back(static_cast<char>(ch));
        ++index;
        if (ch >= 0x40 && ch <= 0x7e) {
            break;
        }
    }
    return true;
}

inline bool readUtf8Char(const std::string &value, std::size_t &index, std::string &bytes, std::uint32_t &codepoint) {
    if (index >= value.size()) {
        return false;
    }
    const unsigned char lead = static_cast<unsigned char>(value[index]);
    std::size_t len = 1;
    codepoint = lead;
    if ((lead & 0x80) == 0) {
        len = 1;
        codepoint = lead;
    } else if ((lead & 0xe0) == 0xc0) {
        len = 2;
        codepoint = lead & 0x1f;
    } else if ((lead & 0xf0) == 0xe0) {
        len = 3;
        codepoint = lead & 0x0f;
    } else if ((lead & 0xf8) == 0xf0) {
        len = 4;
        codepoint = lead & 0x07;
    }
    if (index + len > value.size()) {
        len = 1;
        codepoint = lead;
    }
    bytes = value.substr(index, len);
    for (std::size_t i = 1; i < len; ++i) {
        const unsigned char ch = static_cast<unsigned char>(value[index + i]);
        if ((ch & 0xc0) != 0x80) {
            bytes = value.substr(index, 1);
            codepoint = lead;
            len = 1;
            break;
        }
        codepoint = (codepoint << 6) | (ch & 0x3f);
    }
    index += len;
    return true;
}

inline int codepointWidth(std::uint32_t cp) {
    if (cp == 0 || cp < 32 || (cp >= 0x7f && cp < 0xa0)) {
        return 0;
    }
    if ((cp >= 0x0300 && cp <= 0x036f) ||
        (cp >= 0x1ab0 && cp <= 0x1aff) ||
        (cp >= 0x1dc0 && cp <= 0x1dff) ||
        (cp >= 0x20d0 && cp <= 0x20ff) ||
        (cp >= 0xfe20 && cp <= 0xfe2f)) {
        return 0;
    }
    if ((cp >= 0x1100 && cp <= 0x115f) ||
        (cp >= 0x2e80 && cp <= 0xa4cf) ||
        (cp >= 0xac00 && cp <= 0xd7a3) ||
        (cp >= 0xf900 && cp <= 0xfaff) ||
        (cp >= 0xfe10 && cp <= 0xfe19) ||
        (cp >= 0xfe30 && cp <= 0xfe6f) ||
        (cp >= 0xff00 && cp <= 0xff60) ||
        (cp >= 0xffe0 && cp <= 0xffe6) ||
        (cp >= 0x20000 && cp <= 0x3fffd)) {
        return 2;
    }
    return 1;
}

inline int visibleWidth(const std::string &value) {
    int width = 0;
    for (std::size_t i = 0; i < value.size();) {
        if (value[i] == '\033') {
            std::string sequence;
            readAnsiSequence(value, i, sequence);
            continue;
        }
        std::string bytes;
        std::uint32_t cp = 0;
        if (!readUtf8Char(value, i, bytes, cp)) {
            break;
        }
        width += codepointWidth(cp);
    }
    return width;
}

inline std::string fitLine(const std::string &line, int width);

inline std::string padRightCells(const std::string &value, int width) {
    const int current = visibleWidth(value);
    if (current >= width) {
        return fitLine(value, width);
    }
    return value + std::string(static_cast<std::size_t>(width - current), ' ');
}

inline std::string fitLine(const std::string &line, int width) {
    if (width <= 0) {
        return "";
    }
    if (visibleWidth(line) <= width) {
        return line;
    }
    std::string out;
    bool inColor = false;
    int visible = 0;
    for (std::size_t i = 0; i < line.size();) {
        if (line[i] == '\033') {
            std::string sequence;
            readAnsiSequence(line, i, sequence);
            out += sequence;
            if (!sequence.empty() && sequence.back() == 'm') {
                inColor = sequence != ansi::plain && sequence != "\033[0m";
            }
            continue;
        }
        std::string bytes;
        std::uint32_t cp = 0;
        if (!readUtf8Char(line, i, bytes, cp)) {
            break;
        }
        const int cellWidth = codepointWidth(cp);
        if (visible + cellWidth > width) {
            break;
        }
        out += bytes;
        visible += cellWidth;
    }
    if (inColor) {
        out += ansi::plain;
    }
    return out;
}

class Viewport {
public:
    void render(const std::string &title,
                const ScreenBuffer &buffer,
                int scrollOffset,
                const std::string &footer) const {
        const int rows = terminalRows();
        const int cols = terminalCols();
        const int bodyRows = std::max(3, rows - 4);
        const auto &lines = buffer.lines();
        const int maxOffset = std::max(0, static_cast<int>(lines.size()) - bodyRows);
        scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
        const int totalPages = std::max(1, (static_cast<int>(lines.size()) + bodyRows - 1) / bodyRows);
        const int currentPage = std::min(totalPages, scrollOffset / bodyRows + 1);
        const int fromLine = lines.empty() ? 0 : scrollOffset + 1;
        const int toLine = lines.empty() ? 0 : std::min(static_cast<int>(lines.size()), scrollOffset + bodyRows);
        std::ostringstream footerLine;
        footerLine << footer << "  |  页 " << currentPage << "/" << totalPages
                   << "  行 " << fromLine << "-" << toLine << "/" << lines.size();

        const auto draw = [&](int row, const std::string &text) {
            std::cout << "\033[" << row << ";1H\033[2K" << fitLine(text, cols);
        };

        std::cout << "\033[?25h\033[H";
        draw(1, ansi::bold + title + ansi::plain);
        draw(2, ansi::gray + std::string(std::max(1, std::min(cols, 140)), '-') + ansi::plain);
        for (int i = 0; i < bodyRows; ++i) {
            const int idx = scrollOffset + i;
            if (idx >= 0 && idx < static_cast<int>(lines.size())) {
                draw(3 + i, lines[static_cast<std::size_t>(idx)]);
            } else {
                draw(3 + i, "");
            }
        }
        draw(rows - 1, ansi::gray + std::string(std::max(1, std::min(cols, 140)), '-') + ansi::plain);
        draw(rows, footerLine.str());
        std::cout.flush();
    }
};

inline void adjustScroll(InputKind kind, int &scrollOffset, std::size_t lineCount) {
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    if (kind == InputKind::Up || kind == InputKind::MouseUp) scrollOffset -= 3;
    else if (kind == InputKind::Down || kind == InputKind::MouseDown) scrollOffset += 3;
    else if (kind == InputKind::PageUp) scrollOffset -= bodyRows;
    else if (kind == InputKind::PageDown) scrollOffset += bodyRows;
    else if (kind == InputKind::Home) scrollOffset = 0;
    else if (kind == InputKind::End) scrollOffset = maxOffset;
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
}

inline void adjustSelection(InputKind kind, int &selected, int count) {
    if (count <= 0) {
        selected = 0;
        return;
    }
    if (kind == InputKind::Up || kind == InputKind::MouseUp) {
        selected = (selected + count - 1) % count;
    } else if (kind == InputKind::Down || kind == InputKind::MouseDown) {
        selected = (selected + 1) % count;
    } else if (kind == InputKind::Home) {
        selected = 0;
    } else if (kind == InputKind::End) {
        selected = count - 1;
    }
}

inline void ensureLineVisible(int line, int &scrollOffset, std::size_t lineCount) {
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    if (line < scrollOffset) {
        scrollOffset = line;
    } else if (line >= scrollOffset + bodyRows) {
        scrollOffset = line - bodyRows + 1;
    }
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
}

inline std::string menuLine(const std::string &key,
                            const std::string &title,
                            const std::string &detail,
                            bool selected) {
    std::ostringstream row;
    row << (selected ? "> " : "  ")
        << padRightCells(key, 4)
        << padRightCells(title, 24)
        << detail;
    if (!selected) {
        return row.str();
    }
    return ansi::inverse + ansi::cyan + row.str() + ansi::plain;
}

inline std::string bufferCell(const std::string &value, int width) {
    return padRightCells(fitLine(value, width), width);
}

inline std::string bufferTableRule(const std::vector<int> &widths) {
    int total = 2;
    for (int width : widths) {
        total += width + 2;
    }
    return ansi::gray + std::string(static_cast<std::size_t>(std::max(8, total)), '-') + ansi::plain;
}

inline std::string bufferTableRow(const std::vector<std::string> &values, const std::vector<int> &widths, bool strong = false) {
    std::ostringstream out;
    out << "  ";
    for (std::size_t i = 0; i < widths.size(); ++i) {
        const std::string value = i < values.size() ? values[i] : "";
        if (strong) {
            out << ansi::bold;
        }
        out << bufferCell(value, widths[i]);
        if (strong) {
            out << ansi::plain;
        }
        out << "  ";
    }
    return out.str();
}

inline int dailyTotal(const std::map<std::string, int> &daily) {
    int total = 0;
    for (const auto &item : daily) {
        total += item.second;
    }
    return total;
}

inline int dailyPeak(const std::map<std::string, int> &daily) {
    int peak = 0;
    for (const auto &item : daily) {
        peak = std::max(peak, item.second);
    }
    return peak;
}

inline std::string topPortsText(const UfwAnalysisReport &report, const std::string &ip, std::size_t topN = 5) {
    std::vector<std::pair<std::string, int>> ports;
    const auto ipFound = report.ipPortDaily.find(ip);
    if (ipFound == report.ipPortDaily.end()) {
        return "-";
    }
    for (const auto &port : ipFound->second) {
        ports.push_back({port.first, dailyTotal(port.second)});
    }
    std::sort(ports.begin(), ports.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });
    std::ostringstream out;
    for (std::size_t i = 0; i < ports.size() && i < topN; ++i) {
        if (i != 0) {
            out << " ";
        }
        out << "(" << ports[i].first << "," << ports[i].second << ")";
    }
    return out.str().empty() ? "-" : out.str();
}

inline void addUfwAnalysisToBuffer(ScreenBuffer &buffer, const UfwAnalysisReport &report, const std::string &traceIp = "") {
    buffer.add("> UFW 安全日志分析");
    buffer.add("范围: " + dateTimeStamp(report.start) + " ~ " + dateTimeStamp(report.end));
    buffer.add("来源: " + report.sourceNote + "  有效记录: " + std::to_string(report.validLines));
    buffer.add("");

    struct IpRisk {
        std::string ip;
        int peak = 0;
        int total = 0;
    };
    std::vector<IpRisk> high;
    std::vector<IpRisk> med;
    int lowCount = 0;
    int lowTotal = 0;
    std::map<int, int> lowHist;
    for (const auto &item : report.ipDaily) {
        const int peak = dailyPeak(item.second);
        const int total = dailyTotal(item.second);
        if (peak >= 100) high.push_back({item.first, peak, total});
        else if (peak >= 10) med.push_back({item.first, peak, total});
        else if (total > 0) {
            ++lowCount;
            lowTotal += total;
            lowHist[total] += 1;
        }
    }
    const auto riskSort = [](const IpRisk &a, const IpRisk &b) {
        if (a.peak != b.peak) return a.peak > b.peak;
        return a.total > b.total;
    };
    std::sort(high.begin(), high.end(), riskSort);
    std::sort(med.begin(), med.end(), riskSort);
    buffer.add("统计概览: " + ansi::red + "高危 " + std::to_string(high.size()) + ansi::plain +
               " | " + ansi::yellow + "中危 " + std::to_string(med.size()) + ansi::plain +
               " | " + ansi::green + "低危 " + std::to_string(lowCount) + ansi::plain);
    buffer.add("");

    const auto allowText = [&](const std::string &ip) {
        std::vector<std::string> times;
        for (const auto &item : report.allowRecent) {
            if (item.first == ip) {
                times.push_back(dateTimeStamp(item.second).substr(5, 8));
            }
        }
        return times.empty() ? "-" : joinWords(times, ",");
    };
    const std::vector<int> ipWidths = {34, 10, 10, 18, 34};
    buffer.add(ansi::red + std::string("> TOP 高危 IP (单日峰值 >= 100)") + ansi::plain);
    buffer.add(bufferTableRow({"IP", "单日峰值", "时段总计", "最近3天ALLOW", "扫描端口TOP5"}, ipWidths, true));
    buffer.add(bufferTableRule(ipWidths));
    if (high.empty()) {
        buffer.add("  " + ansi::gray + "- 暂无高危 IP" + ansi::plain);
    }
    for (std::size_t i = 0; i < high.size() && i < 15; ++i) {
        buffer.add(bufferTableRow({high[i].ip, std::to_string(high[i].peak), std::to_string(high[i].total),
                                   allowText(high[i].ip), topPortsText(report, high[i].ip)}, ipWidths));
    }
    buffer.add("");
    buffer.add(ansi::yellow + std::string("> TOP 中危 IP (10 <= 单日峰值 < 100)") + ansi::plain);
    buffer.add(bufferTableRow({"IP", "单日峰值", "时段总计"}, {34, 10, 10}, true));
    buffer.add(bufferTableRule({34, 10, 10}));
    if (med.empty()) {
        buffer.add("  " + ansi::gray + "- 暂无中危 IP" + ansi::plain);
    }
    for (std::size_t i = 0; i < med.size() && i < 10; ++i) {
        buffer.add(bufferTableRow({med[i].ip, std::to_string(med[i].peak), std::to_string(med[i].total)}, {34, 10, 10}));
    }
    buffer.add("");
    buffer.add(ansi::green + std::string("> 低危 IP 整体统计") + ansi::plain);
    buffer.add(bufferTableRow({"分组", "IP数", "时段总计"}, {18, 10, 12}, true));
    buffer.add(bufferTableRule({18, 10, 12}));
    buffer.add(bufferTableRow({"低危IP整体", std::to_string(lowCount), std::to_string(lowTotal)}, {18, 10, 12}));
    buffer.add("");

    std::vector<std::pair<std::string, int>> portCounts;
    int lowPortCount = 0;
    int lowPortTotal = 0;
    int exactTenCount = 0;
    int exactTenTotal = 0;
    for (const auto &item : report.portDaily) {
        const int total = dailyTotal(item.second);
        if (total > 10) portCounts.push_back({item.first, total});
        else if (total == 10) {
            ++exactTenCount;
            exactTenTotal += total;
        } else if (total > 0) {
            ++lowPortCount;
            lowPortTotal += total;
        }
    }
    std::sort(portCounts.begin(), portCounts.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    const auto listeners = listeningProcesses();
    buffer.add(ansi::cyan + std::string("> 端口扫描分析 (时段内被阻断次数 > 10)") + ansi::plain);
    const std::vector<int> portWidths = {10, 12, 20, 30};
    buffer.add(bufferTableRow({"端口", "阻断次数", "服务描述", "本地活跃进程"}, portWidths, true));
    buffer.add(bufferTableRule(portWidths));
    if (portCounts.empty()) {
        buffer.add("  " + ansi::gray + "- 该时段内无高频被扫端口" + ansi::plain);
    }
    for (std::size_t i = 0; i < portCounts.size() && i < 15; ++i) {
        const auto proc = listeners.find(portCounts[i].first);
        buffer.add(bufferTableRow({portCounts[i].first, std::to_string(portCounts[i].second),
                                   serviceNameForPort(portCounts[i].first),
                                   proc == listeners.end() ? "-" : proc->second}, portWidths));
    }
    buffer.add("");
    buffer.add("> 端口/IP 汇总一致性");
    const int ipTotal = [&] {
        int total = 0;
        for (const auto &item : report.ipDaily) total += dailyTotal(item.second);
        return total;
    }();
    const int highPortTotal = [&] {
        int total = 0;
        for (const auto &item : portCounts) total += item.second;
        return total;
    }();
    buffer.add(bufferTableRow({"时段IP总拦截", "高频端口拦截", "低频端口", "端口=10次补充", "差值"}, {14, 14, 14, 18, 10}, true));
    buffer.add(bufferTableRule({14, 14, 14, 18, 10}));
    buffer.add(bufferTableRow({std::to_string(ipTotal), std::to_string(highPortTotal),
                               std::to_string(lowPortCount) + "个/" + std::to_string(lowPortTotal) + "次",
                               std::to_string(exactTenCount) + "个/" + std::to_string(exactTenTotal) + "次",
                               std::to_string(ipTotal - highPortTotal - lowPortTotal - exactTenTotal)}, {14, 14, 14, 18, 10}));

    if (!traceIp.empty()) {
        buffer.add("");
        buffer.add(ansi::cyan + std::string("> IP 追查: ") + traceIp + ansi::plain);
        buffer.add(bufferTableRow({"端口", "次数", "服务描述", "本地活跃进程"}, portWidths, true));
        buffer.add(bufferTableRule(portWidths));
        const auto ipFound = report.ipPortDaily.find(traceIp);
        if (ipFound == report.ipPortDaily.end()) {
            buffer.add("  " + ansi::gray + "- 该时段无该 IP 端口访问记录" + ansi::plain);
        } else {
            std::vector<std::pair<std::string, int>> tracePorts;
            for (const auto &item : ipFound->second) {
                tracePorts.push_back({item.first, dailyTotal(item.second)});
            }
            std::sort(tracePorts.begin(), tracePorts.end(), [](const auto &a, const auto &b) {
                return a.second > b.second;
            });
            for (const auto &item : tracePorts) {
                const auto proc = listeners.find(item.first);
                buffer.add(bufferTableRow({item.first, std::to_string(item.second), serviceNameForPort(item.first),
                                           proc == listeners.end() ? "-" : proc->second}, portWidths));
            }
        }
    }
}

inline std::string nftCommand(const std::string &body) {
    return "nft " + shellQuote(body);
}

inline std::string serviceState(const std::string &name) {
    if (!Shell::exists("systemctl")) {
        return "未知";
    }
    const CommandResult result = Shell::capture("systemctl is-active " + shellQuote(name) + " 2>/dev/null || true");
    const std::string value = trim(result.output);
    return value.empty() ? "未知" : value;
}

inline std::string ufwState() {
    if (!Shell::exists("ufw")) {
        return "缺失";
    }
    const std::string value = trim(Shell::capture("ufw status 2>/dev/null | head -1 || true").output);
    return value.empty() ? "未知" : value;
}

inline std::string normalizedServiceState(const std::string &state) {
    const std::string lower = lowerCopy(state);
    if (lower.find("active") != std::string::npos || lower.find("status: active") != std::string::npos) {
        return "运行";
    }
    if (lower.find("inactive") != std::string::npos || lower.find("status: inactive") != std::string::npos) {
        return "未启用";
    }
    if (lower.find("failed") != std::string::npos) {
        return "异常";
    }
    if (lower.find("not loaded") != std::string::npos || lower.find("缺失") != std::string::npos) {
        return "缺失";
    }
    return "未知";
}

inline std::string serviceMeaning(const std::string &name, const std::string &rawState) {
    const std::string state = normalizedServiceState(rawState);
    if (name == "fail2ban") {
        if (state == "运行") return "正在执行封禁策略";
        if (state == "未启用") return "不会自动封禁攻击源";
        if (state == "异常") return "策略可能未生效";
        if (state == "缺失") return "未安装封禁服务";
        return "无法确认封禁状态";
    }
    if (name == "ufw") {
        if (state == "运行") return "防火墙规则正在生效";
        if (state == "未启用") return "UFW 规则不会拦截流量";
        if (state == "异常") return "防火墙状态异常";
        if (state == "缺失") return "未安装 UFW";
        return "无法确认防火墙状态";
    }
    return state;
}

inline std::string serviceSuggestion(const std::string &name, const std::string &rawState) {
    const std::string state = normalizedServiceState(rawState);
    if (state == "运行") {
        return name == "fail2ban" ? "一致性核验" : "查看规则";
    }
    if (state == "未启用") {
        return name == "fail2ban" ? "服务诊断->启动" : "服务诊断->启用";
    }
    if (state == "异常") {
        return "服务诊断->日志";
    }
    if (state == "缺失") {
        return "服务诊断->安装";
    }
    return "服务诊断";
}

inline bool trafficTableEnabled() {
    return Shell::exists("nft") && Shell::capture("nft list table inet " + kIpTrafficTable).ok();
}

inline bool parseU64(const std::string &text, std::uint64_t &value) {
    if (text.empty()) {
        return false;
    }
    std::uint64_t out = 0;
    for (unsigned char ch : text) {
        if (!std::isdigit(ch)) {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if (out > (UINT64_MAX - digit) / 10) {
            return false;
        }
        out = out * 10 + digit;
    }
    value = out;
    return true;
}

inline std::vector<TrafficRow> parseTrafficSetOutput(const std::string &output,
                                                     const std::string &direction,
                                                     const std::string &family) {
    std::vector<TrafficRow> rows;
    std::string normalized = output;
    std::replace(normalized.begin(), normalized.end(), ',', '\n');
    const std::regex pattern(R"(([0-9A-Fa-f:.]+)\s*\.\s*([0-9]+).*?packets\s+([0-9]+)\s+bytes\s+([0-9]+))");
    for (const auto &line : splitLines(normalized)) {
        std::smatch match;
        if (!std::regex_search(line, match, pattern)) {
            continue;
        }
        TrafficRow row;
        row.ip = match[1].str();
        row.port = match[2].str();
        if (!parseU64(match[3].str(), row.packets) || !parseU64(match[4].str(), row.bytes)) {
            continue;
        }
        row.direction = direction;
        row.family = family;
        rows.push_back(row);
    }
    return rows;
}

inline std::vector<TrafficRow> parseTrafficSet(const std::string &setName,
                                               const std::string &direction,
                                               const std::string &family) {
    if (!Shell::exists("nft")) {
        return {};
    }

    CommandResult result = Shell::capture("nft list set inet " + kIpTrafficTable + " " + setName);
    if (!result.ok()) {
        return {};
    }
    return parseTrafficSetOutput(result.output, direction, family);
}

inline std::vector<TrafficRow> collectTrafficRows() {
    std::vector<TrafficRow> rows;
    auto ipv4DownFuture = std::async(std::launch::async, [] { return parseTrafficSet("ipv4_download", "下载", "IPv4"); });
    auto ipv4UpFuture = std::async(std::launch::async, [] { return parseTrafficSet("ipv4_upload", "上传", "IPv4"); });
    auto ipv6DownFuture = std::async(std::launch::async, [] { return parseTrafficSet("ipv6_download", "下载", "IPv6"); });
    auto ipv6UpFuture = std::async(std::launch::async, [] { return parseTrafficSet("ipv6_upload", "上传", "IPv6"); });
    const std::vector<TrafficRow> ipv4Down = ipv4DownFuture.get();
    const std::vector<TrafficRow> ipv4Up = ipv4UpFuture.get();
    const std::vector<TrafficRow> ipv6Down = ipv6DownFuture.get();
    const std::vector<TrafficRow> ipv6Up = ipv6UpFuture.get();
    rows.insert(rows.end(), ipv4Down.begin(), ipv4Down.end());
    rows.insert(rows.end(), ipv4Up.begin(), ipv4Up.end());
    rows.insert(rows.end(), ipv6Down.begin(), ipv6Down.end());
    rows.insert(rows.end(), ipv6Up.begin(), ipv6Up.end());
    std::sort(rows.begin(), rows.end(), [](const TrafficRow &a, const TrafficRow &b) {
        return a.bytes > b.bytes;
    });
    return rows;
}

inline std::vector<TrafficSummaryRow> aggregateTraffic(const std::vector<TrafficRow> &rows, bool includePort) {
    std::map<std::string, TrafficSummaryRow> grouped;
    for (const auto &row : rows) {
        const std::string key = includePort ? row.ip + "\n" + row.port : row.ip;
        auto &slot = grouped[key];
        slot.ip = row.ip;
        slot.port = includePort ? row.port : "*";
        if (row.direction == "上传") {
            slot.uploadBytes += row.bytes;
            slot.uploadPackets += row.packets;
        } else {
            slot.downloadBytes += row.bytes;
            slot.downloadPackets += row.packets;
        }
    }
    std::vector<TrafficSummaryRow> out;
    for (const auto &entry : grouped) {
        out.push_back(entry.second);
    }
    std::sort(out.begin(), out.end(), [](const TrafficSummaryRow &a, const TrafficSummaryRow &b) {
        if (a.totalBytes() != b.totalBytes()) {
            return a.totalBytes() > b.totalBytes();
        }
        if (a.ip != b.ip) {
            return a.ip < b.ip;
        }
        return a.port < b.port;
    });
    return out;
}

inline std::vector<TrafficSummaryRow> aggregateTrafficByIp(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, false);
}

inline std::vector<TrafficSummaryRow> aggregateTrafficByIpPort(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, true);
}

inline Table trafficSummaryTable(const std::vector<TrafficSummaryRow> &rows, std::size_t limit, bool includePort) {
    Table table(includePort ? std::vector<std::string>{"序号", "IP", "端口", "下载", "上传", "合计", "包数"}
                            : std::vector<std::string>{"序号", "IP", "下载", "上传", "合计", "包数"},
                includePort ? std::vector<std::size_t>{6, 28, 8, 12, 12, 12, 10}
                            : std::vector<std::size_t>{6, 28, 12, 12, 12, 10});
    for (std::size_t i = 0; i < rows.size() && i < limit; ++i) {
        std::vector<std::string> cells = {std::to_string(i + 1), rows[i].ip};
        if (includePort) {
            cells.push_back(rows[i].port);
        }
        cells.push_back(humanBytes(rows[i].downloadBytes));
        cells.push_back(humanBytes(rows[i].uploadBytes));
        cells.push_back(humanBytes(rows[i].totalBytes()));
        cells.push_back(std::to_string(rows[i].totalPackets()));
        table.add(std::move(cells));
    }
    return table;
}

inline void enrichUfwHit(UfwHit &hit) {
    if (hit.count >= 100) {
        hit.risk = "高";
        hit.suggestion = "分析追查/处置";
    } else if (hit.count >= 10) {
        hit.risk = "中";
        hit.suggestion = "观察或追查";
    } else {
        hit.risk = "低";
        hit.suggestion = "持续观察";
    }
    if (hit.topPort.empty()) {
        hit.topPort = "-";
    }
}

inline std::vector<UfwHit> parseTopHits(const std::string &output) {
    std::vector<UfwHit> hits;
    for (const auto &line : splitLines(output)) {
        std::istringstream input(line);
        UfwHit hit;
        input >> hit.count >> hit.value;
        if (!hit.value.empty()) {
            enrichUfwHit(hit);
            hits.push_back(hit);
        }
    }
    return hits;
}

#if LTG_HAS_SQLITE
inline bool collectUfwSourceTopSqlite(std::time_t start, std::time_t end, std::vector<UfwHit> &hits) {
    sqlite3 *db = openUfwCacheDb();
    if (!db) {
        return false;
    }
    const auto ranges = sqliteReadUfwRanges(db);
    if (!rangeCovered(start, end, ranges)) {
        sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           "SELECT src, count(*) AS c FROM events "
                           "WHERE ts BETWEEN ? AND ? AND action IN ('BLOCK','AUDIT') "
                           "GROUP BY src ORDER BY c DESC LIMIT 10;",
                           -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *src = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            UfwHit hit;
            hit.value = src ? src : "";
            hit.count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
            hits.push_back(hit);
        }
    }
    sqlite3_finalize(stmt);
    if (sqlite3_prepare_v2(db,
                           "SELECT dpt, count(*) FROM events "
                           "WHERE ts BETWEEN ? AND ? AND action IN ('BLOCK','AUDIT') AND src=? AND dpt!='' "
                           "GROUP BY dpt ORDER BY count(*) DESC LIMIT 1;",
                           -1, &stmt, nullptr) == SQLITE_OK) {
        for (auto &hit : hits) {
            sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(start));
            sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(end));
            sqlite3_bind_text(stmt, 3, hit.value.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *port = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
                hit.topPort = port ? port : "";
                hit.topPortCount = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
            }
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            enrichUfwHit(hit);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}
#endif

inline std::vector<UfwHit> collectUfwSourceTop() {
#if LTG_HAS_SQLITE
    const std::time_t end = std::time(nullptr);
    const std::time_t roundedEnd = end - (end % 60);
    std::vector<UfwHit> cached;
    if (collectUfwSourceTopSqlite(roundedEnd - 86400, roundedEnd, cached)) {
        return cached;
    }
#endif
    if (!Shell::exists("journalctl")) {
        return {};
    }
    const std::string prefix = Shell::exists("timeout") ? "timeout 1s " : "";
    const std::string command = prefix + "journalctl -k --no-pager -n 360 -o short-iso 2>/dev/null || true";
    std::map<std::string, UfwHit> grouped;
    std::map<std::string, std::map<std::string, std::uint64_t>> portsByIp;
    for (const auto &line : splitLines(Shell::capture(command).output)) {
        UfwLogEvent event;
        if (!parseUfwLogEvent(line, event) || (event.action != "BLOCK" && event.action != "AUDIT")) {
            continue;
        }
        auto &hit = grouped[event.src];
        hit.value = event.src;
        hit.count += 1;
        if (!event.dpt.empty()) {
            portsByIp[event.src][event.dpt] += 1;
        }
    }
    std::vector<UfwHit> hits;
    for (auto &entry : grouped) {
        const auto portFound = portsByIp.find(entry.first);
        if (portFound != portsByIp.end()) {
            auto best = std::max_element(portFound->second.begin(), portFound->second.end(),
                                         [](const auto &a, const auto &b) {
                                             if (a.second != b.second) {
                                                 return a.second < b.second;
                                             }
                                             return a.first > b.first;
                                         });
            if (best != portFound->second.end()) {
                entry.second.topPort = best->first;
                entry.second.topPortCount = best->second;
            }
        }
        enrichUfwHit(entry.second);
        hits.push_back(entry.second);
    }
    std::sort(hits.begin(), hits.end(), [](const UfwHit &a, const UfwHit &b) {
        if (a.count != b.count) {
            return a.count > b.count;
        }
        return a.value < b.value;
    });
    if (hits.size() > 10) {
        hits.resize(10);
    }
    return hits;
}

inline Table ufwHitsTable(const std::vector<UfwHit> &hits) {
    Table table({"序号", "来源IP", "命中", "首要端口", "风险", "建议"}, {6, 34, 10, 12, 8, 18});
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const std::string port = hits[i].topPort == "-" || hits[i].topPort.empty()
                                     ? "-"
                                     : hits[i].topPort + "(" + std::to_string(hits[i].topPortCount) + ")";
        table.add({std::to_string(i + 1), hits[i].value, std::to_string(hits[i].count),
                   port, hits[i].risk, hits[i].suggestion});
    }
    return table;
}

inline DashboardSnapshot loadDashboardSnapshot() {
    DashboardSnapshot snapshot;
    auto tableFuture = std::async(std::launch::async, [] { return trafficTableEnabled(); });
    auto ufwHitsFuture = std::async(std::launch::async, [] { return collectUfwSourceTop(); });
    auto fail2banStateFuture = std::async(std::launch::async, [] { return serviceState("fail2ban"); });
    auto ufwStateFuture = std::async(std::launch::async, [] { return ufwState(); });

    snapshot.tableEnabled = tableFuture.get();
    if (snapshot.tableEnabled) {
        snapshot.trafficRows = collectTrafficRows();
        snapshot.totalRows = aggregateTrafficByIp(snapshot.trafficRows);
    }
    snapshot.ufwHits = ufwHitsFuture.get();
    snapshot.fail2banState = fail2banStateFuture.get();
    snapshot.ufwState = ufwStateFuture.get();
    snapshot.loadedAt = std::chrono::steady_clock::now();
    return snapshot;
}

inline DashboardSnapshot &cachedDashboardSnapshot() {
    static DashboardSnapshot snapshot;
    return snapshot;
}

inline bool &cachedDashboardValid() {
    static bool valid = false;
    return valid;
}

inline bool dashboardCacheFresh() {
    if (!cachedDashboardValid()) {
        return false;
    }
    const auto age = std::chrono::steady_clock::now() - cachedDashboardSnapshot().loadedAt;
    return age < std::chrono::seconds(5);
}

inline std::vector<std::string> tableLines(const Table &table, const std::string &emptyMessage = "暂无数据") {
    std::ostringstream out;
    auto *old = std::cout.rdbuf(out.rdbuf());
    table.print(emptyMessage);
    std::cout.rdbuf(old);
    return splitLines(out.str());
}

inline ScreenBuffer buildDashboardBuffer(const DashboardSnapshot *snapshot,
                                         bool loading,
                                         char spinner) {
    ScreenBuffer buffer;
    buffer.add("  流量/IP 优先的服务器防护仪表盘");
    buffer.add("");
    std::ostringstream deps;
    deps << "权限 " << (isRoot() ? Ui::badge("root", ansi::green) : Ui::badge("非 root", ansi::yellow)) << "  ";
    const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl"};
    for (const auto &tool : tools) {
        deps << tool << " " << Ui::statusBadge(Shell::exists(tool), "可用", "缺失") << "  ";
    }
    buffer.add(deps.str());
    buffer.add("");
    if (loading || snapshot == nullptr) {
        buffer.add(std::string("> 流量 / IP 概览  加载中 ") + spinner);
        buffer.add("  正在读取 nft、UFW、fail2ban 数据。你可以先用 ↑↓/滚轮查看页面，按 q 返回。");
        buffer.add("");
        buffer.add("> 近期来源态势  加载中");
        buffer.add("");
        buffer.add("> 防护组件状态  加载中");
        return buffer;
    }

    buffer.add("> 流量 / IP 概览");
    buffer.add(std::string("统计表: ") + (snapshot->tableEnabled ? "[已启用]" : "[未启用]") + "  nft=inet " + kIpTrafficTable);
    if (!snapshot->tableEnabled) {
        buffer.add("IP 精细流量统计未启用。进入“流量统计 -> 开启统计”启用。");
    }
    buffer.addAll(tableLines(trafficSummaryTable(snapshot->totalRows, 8, false), snapshot->tableEnabled ? "暂无匹配流量" : "统计表未启用"));
    buffer.add("");
    buffer.add("> 近期来源态势");
    buffer.addAll(tableLines(ufwHitsTable(snapshot->ufwHits), "暂无来源日志。可进入“安全中心 -> 分析追查”读取更长时间段。"));
    buffer.add("");
    buffer.add("> 防护组件状态");
    Table services({"组件", "状态", "含义", "建议"}, {18, 12, 30, 18});
    services.add({"fail2ban", normalizedServiceState(snapshot->fail2banState),
                  serviceMeaning("fail2ban", snapshot->fail2banState),
                  serviceSuggestion("fail2ban", snapshot->fail2banState)});
    services.add({"ufw", normalizedServiceState(snapshot->ufwState),
                  serviceMeaning("ufw", snapshot->ufwState),
                  serviceSuggestion("ufw", snapshot->ufwState)});
    buffer.addAll(tableLines(services));
    return buffer;
}

class TuiApp {
public:
    void run() {
        pages_.clear();
        pushMainMenu();
        pushDashboard();
        bool dirty = true;
        while (!exit_ && !pages_.empty()) {
            Page &page = pages_.back();
            const bool changed = updateAsync(page);
            const bool animated = page.kind == PageKind::Dashboard && page.loading;
            if (dirty || changed || animated) {
                ScreenBuffer buffer = renderPage(page);
                viewport_.render(page.title, buffer, page.scrollOffset, footerFor(page, buffer.size()));
                dirty = false;
            }
            const InputEvent event = inputReader().readEvent(animated ? 120 : 500);
            if (event.kind == InputKind::None) {
                continue;
            }
            dispatch(event);
            dirty = true;
        }
    }

private:
    struct LoaderState {
        std::atomic<bool> done{false};
        DashboardSnapshot snapshot;
        std::mutex mutex;
    };

    struct PromptAnswer {
        bool ok = false;
        std::string value;
    };

    struct ActionItem {
        std::string key;
        std::string title;
        std::string detail;
        bool needsRoot = false;
        std::function<void()> run;
    };

    enum class PageKind {
        Menu,
        Dashboard,
        Result
    };

    struct Page {
        PageKind kind = PageKind::Menu;
        std::string title;
        std::string subtitle;
        std::vector<ActionItem> items;
        std::vector<std::string> lines;
        int selected = 0;
        int scrollOffset = 0;
        bool root = false;
        bool loading = false;
        std::shared_ptr<LoaderState> loader;
        std::chrono::steady_clock::time_point started{};
        std::size_t frame = 0;
    };

    Viewport viewport_;
    std::vector<Page> pages_;
    bool exit_ = false;

    static std::string cell(const std::string &value, int width) {
        return padRightCells(fitLine(value, width), width);
    }

    static std::string tableRule(const std::vector<int> &widths) {
        int total = 2;
        for (int width : widths) {
            total += width + 2;
        }
        return ansi::gray + std::string(static_cast<std::size_t>(std::max(8, total)), '-') + ansi::plain;
    }

    static std::string tableRow(const std::vector<std::string> &values, const std::vector<int> &widths, bool strong = false) {
        std::ostringstream out;
        out << "  ";
        for (std::size_t i = 0; i < widths.size(); ++i) {
            const std::string value = i < values.size() ? values[i] : "";
            if (strong) {
                out << ansi::bold;
            }
            out << cell(value, widths[i]);
            if (strong) {
                out << ansi::plain;
            }
            out << "  ";
        }
        return out.str();
    }

    static void addTrafficSummaryTable(ScreenBuffer &buffer,
                                       const std::vector<TrafficSummaryRow> &rows,
                                       std::size_t limit,
                                       const std::string &emptyMessage,
                                       bool includePort) {
        const std::vector<int> widths = includePort ? std::vector<int>{6, 30, 8, 14, 14, 14, 10}
                                                    : std::vector<int>{6, 30, 14, 14, 14, 10};
        buffer.add(includePort ? tableRow({"序号", "IP", "端口", "下载", "上传", "合计", "包数"}, widths, true)
                               : tableRow({"序号", "IP", "下载", "上传", "合计", "包数"}, widths, true));
        buffer.add(tableRule(widths));
        if (rows.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (std::size_t i = 0; i < rows.size() && i < limit; ++i) {
            std::vector<std::string> cells = {std::to_string(i + 1), rows[i].ip};
            if (includePort) {
                cells.push_back(rows[i].port);
            }
            cells.push_back(humanBytes(rows[i].downloadBytes));
            cells.push_back(humanBytes(rows[i].uploadBytes));
            cells.push_back(humanBytes(rows[i].totalBytes()));
            cells.push_back(std::to_string(rows[i].totalPackets()));
            buffer.add(tableRow(cells, widths));
        }
    }

    static void addUfwTable(ScreenBuffer &buffer, const std::vector<UfwHit> &hits, const std::string &emptyMessage) {
        const std::vector<int> widths = {6, 34, 10, 12, 8, 18};
        buffer.add(tableRow({"序号", "来源IP", "命中", "首要端口", "风险", "建议"}, widths, true));
        buffer.add(tableRule(widths));
        if (hits.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (std::size_t i = 0; i < hits.size(); ++i) {
            const std::string risk = hits[i].risk == "高" ? ansi::red + hits[i].risk + ansi::plain
                                   : hits[i].risk == "中" ? ansi::yellow + hits[i].risk + ansi::plain
                                                           : ansi::green + hits[i].risk + ansi::plain;
            const std::string port = hits[i].topPort == "-" || hits[i].topPort.empty()
                                         ? "-"
                                         : hits[i].topPort + "(" + std::to_string(hits[i].topPortCount) + ")";
            buffer.add(tableRow({std::to_string(i + 1), hits[i].value, std::to_string(hits[i].count),
                                 port, risk, hits[i].suggestion}, widths));
        }
    }

    static void addKeyValueTable(ScreenBuffer &buffer,
                                 const std::vector<std::pair<std::string, std::string>> &rows,
                                 const std::string &emptyMessage = "暂无数据") {
        const std::vector<int> widths = {24, 58};
        buffer.add(tableRow({"项目", "值"}, widths, true));
        buffer.add(tableRule(widths));
        if (rows.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (const auto &row : rows) {
            buffer.add(tableRow({row.first, row.second}, widths));
        }
    }

    static void addF2bPolicyTable(ScreenBuffer &buffer,
                                  const std::vector<F2bPolicyInfo> &policies,
                                  const std::string &emptyMessage = "暂无策略") {
        const std::vector<int> widths = {22, 18, 12, 8, 9, 9, 9, 15, 9};
        buffer.add(tableRow({"策略", "定位", "状态", "阈值", "窗口", "封禁", "动作", "过滤器", "封禁IP"}, widths, true));
        buffer.add(tableRule(widths));
        if (policies.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (const auto &policy : policies) {
            buffer.add(tableRow({
                policy.name,
                policy.role,
                policy.state,
                configValueOr(policy.config.maxretry, policy.name == kRule2Jail ? "50" : "5"),
                configValueOr(policy.config.findtime, "3600"),
                configValueOr(policy.config.bantime, policy.name == kRule2Jail ? "1d" : "600"),
                configValueOr(policy.config.banaction, policy.name == kRule2Jail ? "ufw-drop" : "默认"),
                configValueOr(policy.filter, policy.name),
                std::to_string(policy.bannedCount),
            }, widths));
        }
    }

    void pushMainMenu() {
        Page page;
        page.kind = PageKind::Menu;
        page.title = kName + " v" + kVersion;
        page.subtitle = "选择一个页面进入。用上下键移动高亮，Enter 打开。";
        page.root = true;
        page.items = {
            {"1", "仪表盘", "刷新当前概览", false, [this] { pushDashboard(); }},
            {"2", "流量统计", "IP/端口流量统计", false, [this] { pushTrafficMenu(); }},
            {"3", "安全中心", "威胁分析、策略、处置、核验", false, [this] { pushSecurityMenu(); }},
            {"4", "下钻检查", "端口/IP 下钻和原始详情", false, [this] { pushInspectMenu(); }},
            {"5", "诊断", "依赖、日志、报告", false, [this] { pushDiagnoseMenu(); }},
        };
        pages_.push_back(std::move(page));
    }

    void pushDashboard(bool forceRefresh = false) {
        Page page;
        page.kind = PageKind::Dashboard;
        page.title = kName + " v" + kVersion;
        page.subtitle = "流量/IP 优先的服务器防护仪表盘";
        page.started = std::chrono::steady_clock::now();
        if (forceRefresh) {
            cachedDashboardValid() = false;
        }
        page.loading = !dashboardCacheFresh();
        if (page.loading) {
            startDashboardLoad(page);
        }
        pages_.push_back(std::move(page));
    }

    void startDashboardLoad(Page &page) {
        page.loading = true;
        page.loader = std::make_shared<LoaderState>();
        page.started = std::chrono::steady_clock::now();
        auto state = page.loader;
        std::thread([state] {
            DashboardSnapshot snapshot = loadDashboardSnapshot();
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->snapshot = std::move(snapshot);
            }
            state->done = true;
        }).detach();
    }

    void pushMenu(const std::string &title, const std::string &subtitle, std::vector<ActionItem> items) {
        Page page;
        page.kind = PageKind::Menu;
        page.title = title;
        page.subtitle = subtitle;
        page.items = std::move(items);
        pages_.push_back(std::move(page));
    }

    void pushTrafficMenu() {
        pushMenu("流量统计", "结构化 IP 与端口流量统计",
                 {
                     {"1", "开启统计", "向导创建 nft 动态计数集合", true, [this] { actionInstallTraffic(false); }},
                     {"2", "查看排行", "IP 总量与 IP+端口明细", false, [this] { actionShowTrafficRanking(); }},
                     {"3", "重置统计", "按选择端口重建统计表", true, [this] { actionInstallTraffic(true); }},
                     {"4", "删除统计", "删除 nft 表与计数", true, [this] { actionRemoveTrafficAccounting(); }},
                     {"5", "原始 nft 表", "查看底层统计表", false, [this] { actionRawNftTable(); }},
                 });
    }

    void pushSecurityMenu() {
        pushMenu("安全中心", "总览、分析、策略、处置、诊断按同一条防护链路组织",
                 {
                     {"1", "安全总览", "一屏看服务、策略、封禁和下一步", false, [this] { actionSecurityStatus(); }},
                     {"2", "分析追查", "来源 Top、端口扫描、IP 下钻、缓存", false, [this] { pushUfwAnalyzeMenu(); }},
                     {"3", "策略配置", "SSH 防护、扫描升级、白名单", true, [this] { pushFail2banPanel(); }},
                     {"4", "处置修复", "封禁/解封、端口规则、核验、同步", true, [this] { pushSecurityOpsMenu(); }},
                     {"5", "服务诊断", "服务控制、依赖、日志和报告", false, [this] { pushSecurityServiceMenu(); }},
                 });
    }

    void pushFail2banPanel() {
        pushMenu("防护策略", "把 fail2ban 规则和 UFW 落地动作作为一套策略维护",
                 {
                     {"1", "策略总览", "默认两策略 + 自定义 jail 一屏看清", false, [this] { actionF2bPolicyOverview(); }},
                     {"2", "SSH 防护规则", "登录失败阈值、封禁时间、指数惩罚", true, [this] { pushRule1Menu(); }},
                     {"3", "扫描升级规则", "UFW 慢扫阈值、窗口、全端口封禁", true, [this] { pushRule2Menu(); }},
                     {"4", "自定义策略", "新增、编辑、停用用户 jail", true, [this] { pushCustomF2bMenu(); }},
                     {"5", "白名单策略", "规则白名单与 DEFAULT 全局白名单", true, [this] { pushF2bIpMenu(); }},
                     {"6", "全局同步", "双规则同步 bantime/findtime/maxretry", true, [this] { pushF2bGlobalMenu(); }},
                     {"7", "策略安装/修复", "创建 jail/filter/action 并重载服务", true, [this] { actionEnsureFail2banStack(); }},
                 });
    }

    void pushCustomF2bMenu() {
        pushMenu("自定义策略", "把用户新增 jail 纳入统一策略模型，而不是散落在配置文件里",
                 {
                     {"1", "新增策略", "向导创建 jail.local section，可选生成 filter", true, [this] { actionCreateCustomJail(); }},
                     {"2", "编辑策略参数", "选择任意 jail 修改 enabled/maxretry/findtime/bantime/action 等", true, [this] { actionEditAnyJailParam(); }},
                     {"3", "停用自定义策略", "把自定义 jail enabled=false，保留配置备份", true, [this] { actionDisableCustomJail(); }},
                     {"4", "策略总览", "查看所有默认与自定义策略", false, [this] { actionF2bPolicyOverview(); }},
                 });
    }

    void pushRule1Menu() {
        pushMenu("SSH 防护规则", "面向登录失败的即时封禁与重复违规惩罚",
                 {
                     {"1", "最大重试次数", "修改 maxretry", true, [this] { actionChangeJailParam(kRule1Jail, "maxretry", "int", "最大重试次数"); }},
                     {"2", "初始封禁时长", "修改 bantime", true, [this] { actionChangeJailParam(kRule1Jail, "bantime", "time", "初始封禁时长"); }},
                     {"3", "监测时间窗口", "修改 findtime", true, [this] { actionChangeJailParam(kRule1Jail, "findtime", "time", "监测时间窗口"); }},
                     {"4", "封禁范围策略", "端口级/全端口 ufw-drop", true, [this] { actionChangeBanScope(kRule1Jail); }},
                     {"5", "指数封禁开关", "修改 bantime.increment", true, [this] { actionToggleIncrement(); }},
                     {"6", "增长系数", "修改 bantime.factor", true, [this] { actionChangeJailParam(kRule1Jail, "bantime.factor", "factor", "指数封禁增长系数"); }},
                     {"7", "封禁上限", "修改 bantime.maxtime", true, [this] { actionChangeJailParam(kRule1Jail, "bantime.maxtime", "time", "指数封禁上限"); }},
                 });
    }

    void pushRule2Menu() {
        pushMenu("扫描升级规则", "基于 UFW BLOCK/AUDIT 的跨端口慢扫升级封禁",
                 {
                     {"1", "启用/关闭", "切换 enabled", true, [this] { actionToggleJailEnabled(kRule2Jail); }},
                     {"2", "扫描阈值", "修改 maxretry", true, [this] { actionChangeJailParam(kRule2Jail, "maxretry", "int", "扫描阈值"); }},
                     {"3", "检测窗口", "修改 findtime", true, [this] { actionChangeJailParam(kRule2Jail, "findtime", "time", "检测窗口"); }},
                     {"4", "封禁时长", "修改 bantime", true, [this] { actionChangeJailParam(kRule2Jail, "bantime", "time", "封禁时长"); }},
                     {"5", "强制全端口动作", "将 banaction 设置为 ufw-drop", true, [this] { actionApplyUfwDrop(kRule2Jail); }},
                 });
    }

    void pushF2bIpMenu() {
        pushMenu("白名单策略", "规则级和全局 ignoreip 统一维护",
                 {
                     {"1", "SSH 白名单", "加入 SSH 防护 ignoreip", true, [this] { actionAddIgnoreIp(kRule1Jail); }},
                     {"2", "扫描白名单", "加入扫描升级 ignoreip", true, [this] { actionAddIgnoreIp(kRule2Jail); }},
                     {"3", "双规则白名单", "两个防护规则同时加入 ignoreip", true, [this] { actionAddIgnoreIp("both"); }},
                     {"4", "全局白名单", "写入 [DEFAULT] ignoreip", true, [this] { actionAddIgnoreIp("DEFAULT"); }},
                 });
    }

    void pushF2bAuditMenu() {
        pushMenu("一致性核验", "从日志、封禁状态、UFW 规则三个角度确认防护闭环",
                 {
                     {"1", "双日志核验", "按扫描升级窗口检查 UFW 命中和封禁", false, [this] { actionDualAudit(false); }},
                     {"2", "当前封禁详情", "IP、封禁时间、预计剩余", false, [this] { actionCurrentBanDetails(); }},
                     {"3", "封禁日志", "查看 fail2ban Ban 记录", false, [this] { actionF2bBanLogs(); }},
                     {"4", "补封禁候选 IP", "预览达到规则2阈值但未封禁的 IP", true, [this] { actionBanDualAuditCandidates(); }},
                     {"5", "导出防护诊断", "导出 fail2ban/UFW 配置与日志", false, [this] { actionExportF2bDiagnostic(); }},
                 });
    }

    void pushF2bGlobalMenu() {
        pushMenu("全局同步", "让 SSH 防护和扫描升级规则保持同一组节奏参数",
                 {
                     {"1", "同步封禁时长", "两个规则同步 bantime", true, [this] { actionChangeBothRules("bantime", "time", "封禁时长"); }},
                     {"2", "同步检测窗口", "两个规则同步 findtime", true, [this] { actionChangeBothRules("findtime", "time", "检测窗口"); }},
                     {"3", "同步触发阈值", "两个规则同步 maxretry", true, [this] { actionChangeBothRules("maxretry", "int", "触发阈值"); }},
                 });
    }

    void pushSecurityOpsMenu() {
        pushMenu("处置修复", "从发现问题到修复链路都在这里完成",
                 {
                     {"1", "来源 IP 处置", "fail2ban 封禁/解封/忽略，UFW 放行/拒绝", true, [this] { actionIpDisposition(); }},
                     {"2", "端口防火墙", "UFW 端口放行/拒绝/删除规则", true, [this] { actionPortFirewall(); }},
                     {"3", "一致性核验", "检查 UFW 命中、封禁列表和规则落地", false, [this] { pushF2bAuditMenu(); }},
                     {"4", "补齐 UFW deny", "为当前封禁 IP 补齐防火墙规则", true, [this] { actionSyncF2bToUfw(); }},
                     {"5", "清理异常规则", "清理重复/失效 deny 规则", true, [this] { actionRepairUfwAnomalies(); }},
                     {"6", "策略安装/修复", "补齐 filter/action/jail 配置", true, [this] { actionEnsureFail2banStack(); }},
                 });
    }

    void pushSecurityServiceMenu() {
        pushMenu("服务诊断", "只放底层状态和排障动作，日常操作不用绕到这里",
                 {
                     {"1", "服务控制", "fail2ban 与 UFW 服务动作", true, [this] { actionServiceControl(); }},
                     {"2", "依赖检查", "检查工具是否可用", false, [this] { actionDependencyDoctor(); }},
                     {"3", "日志摘要", "fail2ban 与 UFW 原始日志", false, [this] { actionLogSummary(); }},
                     {"4", "导出报告", "写入 /tmp 诊断报告", false, [this] { actionExportReport(); }},
                     {"5", "导出防护诊断", "导出 fail2ban/UFW 配置与日志", false, [this] { actionExportF2bDiagnostic(); }},
                     {"6", "安装依赖", "Debian/Ubuntu apt 命令", true, [this] { actionInstallDependencies(); }},
                 });
    }

    void pushInspectMenu() {
        pushMenu("下钻检查", "面向排障的聚焦原始详情",
                 {
                     {"1", "端口下钻", "监听、防火墙、计数、conntrack", false, [this] { actionFocusedPortInspect(); }},
                     {"2", "conntrack 快照", "当前活跃连接视图", false, [this] { actionConntrackSnapshot(); }},
                     {"3", "原始 nft 表", "查看统计表", false, [this] { actionRawNftTable(); }},
                 });
    }

    void pushDiagnoseMenu() {
        pushMenu("诊断", "底层依赖、原始日志、报告导出",
                 {
                     {"1", "依赖检查", "检查工具是否可用", false, [this] { actionDependencyDoctor(); }},
                     {"2", "日志摘要", "fail2ban 与 UFW 日志", false, [this] { actionLogSummary(); }},
                     {"3", "导出报告", "写入 /tmp 报告", false, [this] { actionExportReport(); }},
                     {"4", "安装依赖", "Debian/Ubuntu apt 命令", true, [this] { actionInstallDependencies(); }},
                 });
    }

    void pushUfwAnalyzeMenu() {
        pushMenu("威胁分析", "攻击来源、端口扫描和本机监听进程",
                 {
                     {"1", "最近24小时", "分析最近 24 小时 UFW 日志", false, [this] { actionUfwAnalyzeHours(24); }},
                     {"2", "最近7天", "分析最近 7 天 UFW 日志", false, [this] { actionUfwAnalyzeDays(7); }},
                     {"3", "最近28天", "分析最近 28 天 UFW 日志", false, [this] { actionUfwAnalyzeDays(28); }},
                     {"4", "自定义时间段", "输入开始/结束日期", false, [this] { actionUfwAnalyzeCustom(); }},
                     {"5", "指定IP追查", "先选时间段再输入 IP", false, [this] { actionUfwTraceIp(); }},
                     {"6", "分析缓存", "查看缓存状态或手动清理", false, [this] { pushUfwCacheMenu(); }},
                 });
    }

    void pushUfwCacheMenu() {
        pushMenu("分析缓存", "缓存只用于加速威胁分析，不参与防火墙决策",
                 {
                     {"1", "缓存状态", "查看路径、活跃时间、记录数和清理策略", false, [this] { actionUfwCacheStatus(); }},
                     {"2", "清理缓存", "清空 SQLite 或 fallback 文本缓存", true, [this] { actionClearUfwCache(); }},
                 });
    }

    void pushResult(const std::string &title, const ScreenBuffer &buffer) {
        Page page;
        page.kind = PageKind::Result;
        page.title = title;
        page.lines = buffer.lines();
        pages_.push_back(std::move(page));
    }

    ScreenBuffer renderPage(const Page &page) {
        if (page.kind == PageKind::Dashboard) {
            return renderDashboardPage(page);
        }
        if (page.kind == PageKind::Result) {
            ScreenBuffer buffer;
            buffer.addAll(page.lines);
            return buffer;
        }
        ScreenBuffer buffer;
        buffer.add("  " + page.subtitle);
        buffer.add("");
        buffer.add(ansi::gray + std::string("  ↑/↓ 或滚轮移动，Enter 确认。当前选中项会高亮。") + ansi::plain);
        buffer.add("");
        buffer.add(ansi::bold + std::string("  序号  操作                    说明") + ansi::plain);
        buffer.add(ansi::gray + std::string("  --------------------------------------------------------------------------") + ansi::plain);
        for (std::size_t i = 0; i < page.items.size(); ++i) {
            const auto &item = page.items[i];
            buffer.add(menuLine(item.key, item.title + (item.needsRoot ? " [root]" : ""), item.detail,
                                page.selected == static_cast<int>(i)));
        }
        buffer.add(menuLine("0", page.root ? "退出" : "返回",
                            page.root ? "退出程序" : "返回上一级",
                            page.selected == static_cast<int>(page.items.size())));
        return buffer;
    }

    ScreenBuffer renderDashboardPage(const Page &page) {
        const DashboardSnapshot *snapshot = cachedDashboardValid() ? &cachedDashboardSnapshot() : nullptr;
        const char frames[] = {'|', '/', '-', '\\'};
        const char spinner = frames[page.frame % 4];
        ScreenBuffer buffer;
        buffer.add("  " + page.subtitle);
        buffer.add("");
        std::ostringstream deps;
        deps << "权限 " << (isRoot() ? Ui::badge("root", ansi::green) : Ui::badge("非 root", ansi::yellow)) << "  ";
        const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl"};
        for (const auto &tool : tools) {
            deps << tool << " " << Ui::statusBadge(Shell::exists(tool), "可用", "缺失") << "  ";
        }
        buffer.add(deps.str());
        buffer.add("");
        if (snapshot == nullptr) {
            buffer.add(std::string("> 流量 / IP 概览  加载中 ") + spinner);
            buffer.add("  正在读取 nft、UFW、fail2ban 数据。");
            if (std::chrono::steady_clock::now() - page.started > std::chrono::seconds(2)) {
                buffer.add("  仍在读取系统数据，可按 q 返回，或等待加载完成。");
            }
            buffer.add("");
            buffer.add("> 近期来源态势  加载中");
            buffer.add("");
            buffer.add("> 防护组件状态  加载中");
            return buffer;
        }

        buffer.add("> 流量 / IP 概览");
        if (page.loading) {
            buffer.add(std::string("后台刷新中 ") + spinner + "  先显示上一份快照，刷新完成后自动更新。");
        }
        buffer.add(std::string("统计表: ") +
                   (snapshot->tableEnabled ? Ui::badge("已启用", ansi::green) : Ui::badge("未启用", ansi::yellow)) +
                   "  nft=inet " + kIpTrafficTable);
        if (!snapshot->tableEnabled) {
            buffer.add(ansi::yellow + std::string("IP 精细流量统计未启用。进入“流量统计 -> 开启统计”启用。") + ansi::plain);
        }
        addTrafficSummaryTable(buffer, snapshot->totalRows, 8, snapshot->tableEnabled ? "暂无匹配流量" : "统计表未启用", false);
        buffer.add("");
        buffer.add("> 近期来源态势");
        addUfwTable(buffer, snapshot->ufwHits, "暂无来源日志。可进入“安全中心 -> 分析追查”读取更长时间段。");
        buffer.add("");
        buffer.add("> 防护组件状态");
        const std::vector<int> serviceWidths = {18, 14, 32, 22};
        buffer.add(tableRow({"组件", "状态", "含义", "建议"}, serviceWidths, true));
        buffer.add(tableRule(serviceWidths));
        buffer.add(tableRow({"fail2ban", normalizedServiceState(snapshot->fail2banState),
                             serviceMeaning("fail2ban", snapshot->fail2banState),
                             serviceSuggestion("fail2ban", snapshot->fail2banState)}, serviceWidths));
        buffer.add(tableRow({"ufw", normalizedServiceState(snapshot->ufwState),
                             serviceMeaning("ufw", snapshot->ufwState),
                             serviceSuggestion("ufw", snapshot->ufwState)}, serviceWidths));
        buffer.add("");
        buffer.add("> Fail2ban 默认策略");
        F2bPolicyInfo sshPolicy;
        sshPolicy.name = kRule1Jail;
        sshPolicy.role = "SSH 登录";
        sshPolicy.config = readJailConfig(kRule1Jail);
        sshPolicy.filter = readJailValue(kRule1Jail, "filter");
        sshPolicy.state = normalizedServiceState(snapshot->fail2banState) == "运行" ? "随服务运行" : "待确认";
        F2bPolicyInfo scanPolicy;
        scanPolicy.name = kRule2Jail;
        scanPolicy.role = "UFW 慢扫";
        scanPolicy.config = readJailConfig(kRule2Jail);
        scanPolicy.filter = readJailValue(kRule2Jail, "filter");
        scanPolicy.state = lowerCopy(configValueOr(scanPolicy.config.enabled, "false")) == "true" ? "已配置" : "未启用";
        addF2bPolicyTable(buffer, {sshPolicy, scanPolicy}, "jail.local 中未发现默认策略");
        buffer.add("");
        buffer.add(ansi::gray + std::string("提示: “服务诊断”处理安装/启动/日志，“处置修复”处理封禁和规则一致性。") + ansi::plain);
        return buffer;
    }

    std::string footerFor(const Page &page, std::size_t) const {
        if (page.kind == PageKind::Dashboard) {
            return "↑↓/滚轮 滚动  r 刷新  q 返回";
        }
        if (page.kind == PageKind::Result) {
            return "↑↓/滚轮 滚动  PgUp/PgDn 翻页  q 返回";
        }
        return "↑↓/滚轮 选择  Enter 确认  q 返回";
    }

    bool updateAsync(Page &page) {
        if (page.kind != PageKind::Dashboard) {
            return false;
        }
        ++page.frame;
        if (page.loading && page.loader && page.loader->done.load()) {
            {
                std::lock_guard<std::mutex> lock(page.loader->mutex);
                cachedDashboardSnapshot() = page.loader->snapshot;
            }
            cachedDashboardValid() = true;
            page.loading = false;
            page.loader.reset();
            page.scrollOffset = 0;
            return true;
        }
        return false;
    }

    void dispatch(const InputEvent &event) {
        if (event.kind == InputKind::CtrlC) {
            std::raise(SIGINT);
            return;
        }
        if (pages_.empty() || event.kind == InputKind::None) {
            return;
        }
        Page &page = pages_.back();
        const bool rootExitKey =
            (static_cast<int>(event.kind) == static_cast<int>(InputKind::Escape)) ||
            (static_cast<int>(event.kind) == static_cast<int>(InputKind::Character) &&
             (static_cast<unsigned char>(event.ch) == static_cast<unsigned char>('q') ||
              static_cast<unsigned char>(event.ch) == static_cast<unsigned char>('Q') ||
              static_cast<unsigned char>(event.ch) == static_cast<unsigned char>('0')));
        if (pages_.size() == 1 && rootExitKey) {
            restoreTerminalDisplay();
#ifndef _WIN32
            _exit(0);
#else
            std::exit(0);
#endif
            return;
        }
        if (page.kind == PageKind::Menu) {
            handleMenu(event, page);
        } else if (page.kind == PageKind::Dashboard) {
            handleDashboard(event, page);
        } else {
            handleScrollable(event, page);
        }
    }

    void handleMenu(const InputEvent &event, Page &page) {
        const int selectableCount = static_cast<int>(page.items.size()) + 1;
        ScreenBuffer buffer = renderPage(page);
        if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
            event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
            event.kind == InputKind::Home || event.kind == InputKind::End) {
            adjustSelection(event.kind, page.selected, selectableCount);
            ensureLineVisible(6 + page.selected, page.scrollOffset, buffer.size());
            return;
        }
        if (event.kind == InputKind::PageUp || event.kind == InputKind::PageDown) {
            adjustScroll(event.kind, page.scrollOffset, buffer.size());
            return;
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return;
        }
        if (event.kind != InputKind::Character) {
            return;
        }
        if (event.ch == 'q' || event.ch == 'Q') {
            popPage();
            return;
        }
        if (event.ch == '\n') {
            activateSelected(page);
            return;
        }
        if (event.ch == '0') {
            popPage();
            return;
        }
        for (std::size_t i = 0; i < page.items.size(); ++i) {
            if (!page.items[i].key.empty() && event.ch == page.items[i].key[0]) {
                page.selected = static_cast<int>(i);
                activateSelected(page);
                return;
            }
        }
    }

    void handleDashboard(const InputEvent &event, Page &page) {
        ScreenBuffer buffer = renderPage(page);
        if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
            event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
            event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
            event.kind == InputKind::Home || event.kind == InputKind::End) {
            adjustScroll(event.kind, page.scrollOffset, buffer.size());
            return;
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return;
        }
        if (event.kind != InputKind::Character) {
            return;
        }
        if (event.ch == 'q' || event.ch == 'Q') {
            popPage();
        } else if (event.ch == 'r' || event.ch == 'R') {
            Shell::clearExistsCache();
            cachedDashboardValid() = false;
            startDashboardLoad(page);
            page.scrollOffset = 0;
        }
    }

    void handleScrollable(const InputEvent &event, Page &page) {
        ScreenBuffer buffer = renderPage(page);
        if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
            event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
            event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
            event.kind == InputKind::Home || event.kind == InputKind::End) {
            adjustScroll(event.kind, page.scrollOffset, buffer.size());
            return;
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return;
        }
        if (event.kind == InputKind::Character && (event.ch == 'q' || event.ch == 'Q')) {
            popPage();
        }
    }

    void activateSelected(Page &page) {
        if (page.selected == static_cast<int>(page.items.size())) {
            popPage();
            return;
        }
        if (page.selected < 0 || page.selected >= static_cast<int>(page.items.size())) {
            return;
        }
        ActionItem item = page.items[static_cast<std::size_t>(page.selected)];
        if (item.needsRoot && !isRoot()) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("这个操作需要 root 权限。") + ansi::plain);
            buffer.add("");
            buffer.add("请使用 sudo 重新运行，或返回选择只读页面。");
            pushResult("权限不足", buffer);
            return;
        }
        item.run();
    }

    void popPage() {
        if (pages_.empty() || pages_.back().root) {
            exit_ = true;
        } else {
            pages_.pop_back();
        }
    }

    PromptAnswer promptLine(const std::string &title,
                            const std::vector<std::string> &body,
                            const std::string &label,
                            const std::string &initial = "") {
        std::string value = initial;
        int scrollOffset = 0;
        while (true) {
            ScreenBuffer buffer;
            buffer.addAll(body);
            buffer.add("");
            buffer.add(ansi::cyan + label + ansi::plain + value);
            viewport_.render(title, buffer, scrollOffset, "Enter 确认  Backspace 删除  Esc/q 取消");
            const InputEvent event = inputReader().readEvent(120);
            if (event.kind == InputKind::CtrlC) {
                std::raise(SIGINT);
            }
            if (event.kind == InputKind::Escape) {
                return {};
            }
            if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
                event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
                event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
                event.kind == InputKind::Home || event.kind == InputKind::End) {
                adjustScroll(event.kind, scrollOffset, buffer.size());
                continue;
            }
            if (event.kind != InputKind::Character) {
                continue;
            }
            if (event.ch == '\n') {
                return {true, trim(value)};
            }
            if ((event.ch == 'q' || event.ch == 'Q') && value.empty()) {
                return {};
            }
            if (event.ch == 8 || event.ch == 127) {
                if (!value.empty()) {
                    value.pop_back();
                }
                continue;
            }
            const unsigned char ch = static_cast<unsigned char>(event.ch);
            if (ch >= 32 || ch >= 0x80) {
                value.push_back(event.ch);
            }
        }
    }

    bool confirmYesNo(const std::string &summary, bool defaultYes = false) {
        const std::string defaultText = defaultYes ? "默认: 是" : "默认: 否";
        const std::string prompt = defaultYes ? "执行? [Y/n]: " : "执行? [y/N]: ";
        PromptAnswer answer = promptLine("确认操作",
                                         {ansi::yellow + summary + ansi::plain,
                                          defaultText + "。输入 y 或 n，然后按 Enter。"},
                                         prompt);
        if (!answer.ok) {
            return false;
        }
        const std::string value = trim(answer.value);
        if (value.empty()) {
            return defaultYes;
        }
        if (value == "y" || value == "Y" || value == "yes" || value == "YES") {
            return true;
        }
        if (value == "n" || value == "N" || value == "no" || value == "NO") {
            return false;
        }
        return false;
    }

    bool confirmYesNoWithBody(const std::string &title, std::vector<std::string> body, bool defaultYes = false) {
        const std::string defaultText = defaultYes ? "默认: 是" : "默认: 否";
        const std::string prompt = defaultYes ? "执行? [Y/n]: " : "执行? [y/N]: ";
        body.push_back("");
        body.push_back(defaultText + "。输入 y 或 n，然后按 Enter。");
        PromptAnswer answer = promptLine(title, body, prompt);
        if (!answer.ok) {
            return false;
        }
        const std::string value = trim(answer.value);
        if (value.empty()) {
            return defaultYes;
        }
        if (value == "y" || value == "Y" || value == "yes" || value == "YES") {
            return true;
        }
        if (value == "n" || value == "N" || value == "no" || value == "NO") {
            return false;
        }
        return false;
    }

    void renderBusy(const std::string &title, const std::string &message) {
        ScreenBuffer buffer;
        buffer.add(message);
        viewport_.render(title, buffer, 0, "正在执行，请稍候");
    }

    ScreenBuffer runCommandList(const std::vector<std::string> &commands) {
        ScreenBuffer buffer;
        bool ok = true;
        for (const auto &command : commands) {
            buffer.add(ansi::gray + "$ " + command + ansi::plain);
            const CommandResult result = Shell::capture(command);
            ok = ok && result.ok();
            buffer.add(result.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                                   : ansi::yellow + "exit " + std::to_string(result.exitCode) + ansi::plain);
            const std::string output = trim(result.output);
            if (!output.empty()) {
                buffer.addAll(splitLines(output));
            }
            buffer.add("");
        }
        buffer.add(ok ? ansi::green + std::string("操作完成。") + ansi::plain
                      : ansi::yellow + std::string("部分命令失败，请查看上方输出。") + ansi::plain);
        return buffer;
    }

    void actionShowTrafficRanking() {
        renderBusy("流量排行", "正在读取 nft 统计数据...");
        ScreenBuffer buffer;
        if (!trafficTableEnabled()) {
            buffer.add(ansi::yellow + std::string("统计表未启用。进入“流量统计 -> 开启统计”启用。") + ansi::plain);
            pushResult("流量排行", buffer);
            return;
        }
        const auto rows = collectTrafficRows();
        buffer.add("> IP 总量");
        addTrafficSummaryTable(buffer, aggregateTrafficByIp(rows), 30, "暂无匹配流量", false);
        buffer.add("");
        buffer.add("> IP + 端口明细");
        addTrafficSummaryTable(buffer, aggregateTrafficByIpPort(rows), 80, "暂无匹配流量", true);
        pushResult("流量排行", buffer);
    }

    void actionInstallTraffic(bool resetOnly) {
        PromptAnswer ports = promptLine(resetOnly ? "重置流量统计" : "开启流量统计",
                                        {"输入需要统计的端口列表，支持单端口、逗号和范围。", "示例: 80,443,10000-10100"},
                                        "端口列表: ");
        if (!ports.ok) {
            return;
        }
        const std::string value = removeSpaces(ports.value);
        if (!isSafePortList(value)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("端口列表不合法。") + ansi::plain);
            buffer.add("示例: 80,443,10000-10100");
            pushResult(resetOnly ? "重置流量统计" : "开启流量统计", buffer);
            return;
        }

        if (!confirmYesNo("将重建 nft 统计表，旧统计数据会清空。端口: " + value, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult(resetOnly ? "重置流量统计" : "开启流量统计", buffer);
            return;
        }

        const std::string table = "inet " + kIpTrafficTable;
        const std::string portSet = "{ " + value + " }";
        std::vector<std::string> commands = {
            "nft delete table " + table + " 2>/dev/null || true",
            nftCommand("add table " + table),
            nftCommand("add chain " + table + " input_account { type filter hook input priority -150; policy accept; }"),
            nftCommand("add chain " + table + " output_account { type filter hook output priority -150; policy accept; }"),
            nftCommand("add chain " + table + " forward_account { type filter hook forward priority -150; policy accept; }"),
            nftCommand("add set " + table + " ipv4_download { type ipv4_addr . inet_service; flags dynamic; counter; }"),
            nftCommand("add set " + table + " ipv4_upload { type ipv4_addr . inet_service; flags dynamic; counter; }"),
            nftCommand("add set " + table + " ipv6_download { type ipv6_addr . inet_service; flags dynamic; counter; }"),
            nftCommand("add set " + table + " ipv6_upload { type ipv6_addr . inet_service; flags dynamic; counter; }"),
            nftCommand("add rule " + table + " input_account tcp dport " + portSet + " update @ipv4_download { ip saddr . tcp dport }"),
            nftCommand("add rule " + table + " input_account udp dport " + portSet + " update @ipv4_download { ip saddr . udp dport }"),
            nftCommand("add rule " + table + " input_account meta nfproto ipv6 tcp dport " + portSet + " update @ipv6_download { ip6 saddr . tcp dport }"),
            nftCommand("add rule " + table + " input_account meta nfproto ipv6 udp dport " + portSet + " update @ipv6_download { ip6 saddr . udp dport }"),
            nftCommand("add rule " + table + " output_account tcp sport " + portSet + " update @ipv4_upload { ip daddr . tcp sport }"),
            nftCommand("add rule " + table + " output_account udp sport " + portSet + " update @ipv4_upload { ip daddr . udp sport }"),
            nftCommand("add rule " + table + " output_account meta nfproto ipv6 tcp sport " + portSet + " update @ipv6_upload { ip6 daddr . tcp sport }"),
            nftCommand("add rule " + table + " output_account meta nfproto ipv6 udp sport " + portSet + " update @ipv6_upload { ip6 daddr . udp sport }"),
            nftCommand("add rule " + table + " forward_account tcp dport " + portSet + " update @ipv4_download { ip saddr . tcp dport }"),
            nftCommand("add rule " + table + " forward_account udp dport " + portSet + " update @ipv4_download { ip saddr . udp dport }"),
            nftCommand("add rule " + table + " forward_account tcp sport " + portSet + " update @ipv4_upload { ip daddr . tcp sport }"),
            nftCommand("add rule " + table + " forward_account udp sport " + portSet + " update @ipv4_upload { ip daddr . udp sport }"),
            nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp dport " + portSet + " update @ipv6_download { ip6 saddr . tcp dport }"),
            nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp dport " + portSet + " update @ipv6_download { ip6 saddr . udp dport }"),
            nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp sport " + portSet + " update @ipv6_upload { ip6 daddr . tcp sport }"),
            nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp sport " + portSet + " update @ipv6_upload { ip6 daddr . udp sport }"),
        };
        renderBusy(resetOnly ? "重置流量统计" : "开启流量统计", "正在应用 nft 规则...");
        cachedDashboardValid() = false;
        pushResult(resetOnly ? "重置流量统计" : "开启流量统计", runCommandList(commands));
    }

    void actionRemoveTrafficAccounting() {
        renderBusy("删除流量统计", "正在检查统计表...");
        if (!trafficTableEnabled()) {
            ScreenBuffer buffer;
            buffer.add("统计表未启用，无需删除。");
            pushResult("删除流量统计", buffer);
            return;
        }
        if (!confirmYesNo("将删除 inet " + kIpTrafficTable + " 并清空所有统计。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("删除流量统计", buffer);
            return;
        }
        cachedDashboardValid() = false;
        pushResult("删除流量统计", runCommandList({"nft delete table inet " + kIpTrafficTable}));
    }

    void actionRawNftTable() {
        renderBusy("原始 nft 表", "正在读取 nft 表...");
        CommandResult result = Shell::capture("nft list table inet " + kIpTrafficTable + " 2>/dev/null || true");
        ScreenBuffer buffer;
        const std::string output = trim(result.output);
        if (output.empty()) {
            buffer.add("(无输出，统计表可能未启用)");
        } else {
            buffer.addAll(splitLines(output));
        }
        pushResult("原始 nft 表", buffer);
    }

    void actionSecurityStatus() {
        renderBusy("安全总览", "正在读取防护链路状态...");
        auto fail2banStateFuture = std::async(std::launch::async, [] { return serviceState("fail2ban"); });
        auto ufwStateFuture = std::async(std::launch::async, [] { return ufwState(); });
        auto sshBannedFuture = std::async(std::launch::async, [] { return bannedSetForJail(kRule1Jail); });
        auto scanBannedFuture = std::async(std::launch::async, [] { return bannedSetForJail(kRule2Jail); });
        auto ufwTopFuture = std::async(std::launch::async, [] { return collectUfwSourceTop(); });
        ScreenBuffer buffer;
        buffer.add("> 防护链路");
        addKeyValueTable(buffer, {
            {"fail2ban 服务", fail2banStateFuture.get()},
            {"UFW 防火墙", ufwStateFuture.get()},
            {"规则落地一致性", "从“处置修复 -> 一致性核验”检查"},
            {"威胁分析缓存", kUfwCacheDir},
        });
        buffer.add("");

        const F2bJailConfig ssh = readJailConfig(kRule1Jail);
        const F2bJailConfig scan = readJailConfig(kRule2Jail);
        buffer.add("> 防护策略");
        const std::vector<int> policyWidths = {18, 10, 10, 10, 10, 18, 18};
        buffer.add(bufferTableRow({"策略", "启用", "阈值", "窗口", "封禁", "动作", "白名单"}, policyWidths, true));
        buffer.add(bufferTableRule(policyWidths));
        buffer.add(bufferTableRow({
            "SSH 登录",
            configValueOr(ssh.enabled, "默认"),
            configValueOr(ssh.maxretry, "5"),
            configValueOr(ssh.findtime, "3600"),
            configValueOr(ssh.bantime, "600"),
            configValueOr(ssh.banaction, "默认"),
            ssh.ignoreip.empty() ? "-" : ssh.ignoreip,
        }, policyWidths));
        buffer.add(bufferTableRow({
            "扫描升级",
            configValueOr(scan.enabled, "默认"),
            configValueOr(scan.maxretry, "50"),
            configValueOr(scan.findtime, "3600"),
            configValueOr(scan.bantime, "1d"),
            configValueOr(scan.banaction, "ufw-drop"),
            scan.ignoreip.empty() ? "-" : scan.ignoreip,
        }, policyWidths));
        buffer.add("");

        buffer.add("> 当前封禁");
        const auto sshBanned = sshBannedFuture.get();
        const auto scanBanned = scanBannedFuture.get();
        addKeyValueTable(buffer, {
            {"SSH 登录封禁", std::to_string(sshBanned.size()) + " 个 IP"},
            {"扫描升级封禁", std::to_string(scanBanned.size()) + " 个 IP"},
            {"详情入口", "安全中心 -> 处置修复 -> 一致性核验 -> 当前封禁详情"},
        });
        buffer.add("");

        buffer.add("> 近期来源 Top");
        addUfwTable(buffer, ufwTopFuture.get(), "暂无 UFW 来源日志，或 journalctl 不可用");
        buffer.add("");

        buffer.add("> 建议操作路径");
        buffer.add("  看攻击来源: 分析追查 -> 最近24小时 / 指定IP追查");
        buffer.add("  改防护规则: 策略配置 -> SSH防护 / 扫描升级 / 白名单");
        buffer.add("  处理异常IP: 处置修复 -> 来源IP处置 / 一致性核验 / 补齐UFW deny");
        pushResult("安全总览", buffer);
    }

    std::string promptPolicyName(const std::string &title, bool customOnly = false) {
        const auto policies = collectFail2banPolicies(false);
        std::vector<F2bPolicyInfo> filtered;
        for (const auto &policy : policies) {
            if (!customOnly || !policy.managedDefault) {
                filtered.push_back(policy);
            }
        }
        if (filtered.empty()) {
            ScreenBuffer buffer;
            buffer.add(customOnly ? "当前没有自定义策略。" : "没有可选策略。");
            pushResult(title, buffer);
            return "";
        }
        std::vector<std::string> body;
        body.push_back("选择要操作的 fail2ban 策略:");
        for (std::size_t i = 0; i < filtered.size(); ++i) {
            body.push_back(std::to_string(i + 1) + " = " + filtered[i].name + "  (" + filtered[i].role + ")");
        }
        PromptAnswer answer = promptLine(title, body, "序号或策略名: ");
        if (!answer.ok || answer.value.empty()) {
            return "";
        }
        if (isValidPositiveInt(answer.value)) {
            const std::size_t index = static_cast<std::size_t>(std::stoul(answer.value));
            if (index >= 1 && index <= filtered.size()) {
                return filtered[index - 1].name;
            }
        }
        if (isSafeIdentifier(answer.value)) {
            for (const auto &policy : filtered) {
                if (policy.name == answer.value) {
                    return policy.name;
                }
            }
        }
        ScreenBuffer buffer;
        buffer.add("无效策略选择。");
        pushResult(title, buffer);
        return "";
    }

    void actionF2bPolicyOverview() {
        renderBusy("策略总览", "正在读取 fail2ban 策略...");
        ScreenBuffer buffer;
        const auto policies = collectFail2banPolicies(true);
        buffer.add("> 策略清单");
        addF2bPolicyTable(buffer, policies, "未发现 fail2ban 策略");
        buffer.add("");
        buffer.add("> 说明");
        buffer.add("  " + kRule1Jail + " 是默认 SSH 登录防护策略，适合处理登录爆破。");
        buffer.add("  " + kRule2Jail + " 是默认 UFW 慢扫升级策略，适合把跨端口扫描升级为全端口封禁。");
        buffer.add("  自定义策略会作为普通 fail2ban jail 写入 jail.local，并可复用已有 filter 或生成新的 filter。");
        buffer.add("");
        buffer.add("> 操作入口");
        buffer.add("  新增/编辑: 防护策略 -> 自定义策略");
        buffer.add("  默认策略: 防护策略 -> SSH 防护规则 / 扫描升级规则");
        buffer.add("  封禁核验: 处置修复 -> 一致性核验");
        pushResult("策略总览", buffer);
    }

    void actionCreateCustomJail() {
        PromptAnswer name = promptLine("新增自定义策略",
                                       {"策略名会成为 fail2ban jail section，允许字母、数字、-、_。",
                                        "示例: nginx-404, app-login, sshd-extra"},
                                       "策略名: ");
        if (!name.ok || name.value.empty()) return;
        if (!isSafeIdentifier(name.value) || name.value == "DEFAULT") {
            ScreenBuffer buffer;
            buffer.add("策略名不合法。只能使用字母、数字、-、_，且不能是 DEFAULT。");
            pushResult("新增自定义策略", buffer);
            return;
        }
        PromptAnswer filter = promptLine("新增自定义策略",
                                         {"filter 名称通常与 /etc/fail2ban/filter.d/<name>.conf 对应。",
                                          "如果输入已有 filter 名称并跳过 failregex，就只引用已有 filter。"},
                                         "filter [" + name.value + "]: ",
                                         name.value);
        if (!filter.ok) return;
        if (!isSafeIdentifier(filter.value)) {
            ScreenBuffer buffer;
            buffer.add("filter 名称不合法。只能使用字母、数字、-、_。");
            pushResult("新增自定义策略", buffer);
            return;
        }
        PromptAnswer logpath = promptLine("新增自定义策略",
                                          {"日志路径支持普通路径和通配符，例如 /var/log/nginx/access.log*。"},
                                          "logpath [/var/log/auth.log]: ",
                                          "/var/log/auth.log");
        if (!logpath.ok) return;
        if (!isSafeLogPath(logpath.value)) {
            ScreenBuffer buffer;
            buffer.add("日志路径不合法。必须是 / 开头的安全路径，可包含 * 或 ?。");
            pushResult("新增自定义策略", buffer);
            return;
        }
        PromptAnswer maxretry = promptLine("新增自定义策略", {"触发阈值必须是正整数。"}, "maxretry [5]: ", "5");
        if (!maxretry.ok) return;
        PromptAnswer findtime = promptLine("新增自定义策略", {"检测窗口支持 600、10m、2h、1d、1w。"}, "findtime [10m]: ", "10m");
        if (!findtime.ok) return;
        PromptAnswer bantime = promptLine("新增自定义策略", {"封禁时长支持 600、10m、2h、1d、1w。"}, "bantime [1h]: ", "1h");
        if (!bantime.ok) return;
        PromptAnswer action = promptLine("新增自定义策略",
                                         {"banaction 留空表示使用 fail2ban 默认动作；输入 ufw-drop 可全端口封禁。"},
                                         "banaction [默认]: ");
        if (!action.ok) return;
        PromptAnswer failregex = promptLine("新增自定义策略",
                                            {"可选。输入 failregex 会生成 filter 文件；留空表示复用已有 filter。",
                                             "failregex 中用 <HOST> 标记来源 IP。"},
                                            "failregex [留空]: ");
        if (!failregex.ok) return;
        std::string message;
        if (!validateConfigValue("int", maxretry.value, message) ||
            !validateConfigValue("time", findtime.value, message) ||
            !validateConfigValue("time", bantime.value, message)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + message + ansi::plain);
            pushResult("新增自定义策略", buffer);
            return;
        }
        if (!action.value.empty() && !isSafeIdentifier(action.value)) {
            ScreenBuffer buffer;
            buffer.add("banaction 不合法。只允许字母、数字、-、_，或留空。");
            pushResult("新增自定义策略", buffer);
            return;
        }
        std::ostringstream summary;
        summary << "将创建策略 " << name.value
                << "，filter=" << filter.value
                << "，logpath=" << logpath.value
                << "，maxretry=" << maxretry.value
                << "，findtime=" << findtime.value
                << "，bantime=" << bantime.value;
        if (!action.value.empty()) {
            summary << "，banaction=" << action.value;
        }
        if (!failregex.value.empty()) {
            summary << "，并生成 filter 文件";
        }
        if (!confirmYesNo(summary.str(), false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("新增自定义策略", buffer);
            return;
        }

        ScreenBuffer buffer;
        std::string backup;
        std::string error;
        if (!failregex.value.empty()) {
            const std::string path = "/etc/fail2ban/filter.d/" + filter.value + ".conf";
            const std::string content = "[Definition]\nfailregex = " + failregex.value + "\nignoreregex =\n";
            const bool ok = writeManagedFileWithBackup(path, content, backup, error);
            buffer.add(std::string(ok ? "[OK] " : "[WARN] ") + "filter: " + path);
            if (!backup.empty()) buffer.add("  备份: " + backup);
            if (!error.empty()) buffer.add("  原因: " + error);
        }
        if (action.value == "ufw-drop") {
            backup.clear();
            error.clear();
            const bool ok = writeManagedFileWithBackup(kUfwDropActionFile, renderUfwDropActionFile(), backup, error);
            buffer.add(std::string(ok ? "[OK] " : "[WARN] ") + "action: " + kUfwDropActionFile);
            if (!backup.empty()) buffer.add("  备份: " + backup);
            if (!error.empty()) buffer.add("  原因: " + error);
        }

        IniConfig ini;
        ini.load(kJailConf);
        ini.set(name.value, "enabled", "true");
        ini.set(name.value, "filter", filter.value);
        ini.set(name.value, "logpath", logpath.value);
        ini.set(name.value, "backend", "auto");
        ini.set(name.value, "maxretry", maxretry.value);
        ini.set(name.value, "findtime", findtime.value);
        ini.set(name.value, "bantime", bantime.value);
        if (!action.value.empty()) {
            ini.set(name.value, "banaction", action.value);
        }
        backup.clear();
        const bool ok = ini.save(backup);
        buffer.add(std::string(ok ? "[OK] " : "[WARN] ") + kJailConf + " 已写入");
        if (!backup.empty()) buffer.add("  备份: " + backup);
        buffer.add("");
        buffer.add("建议执行: systemctl restart fail2ban");
        pushResult("新增自定义策略", buffer);
    }

    void actionEditAnyJailParam() {
        const std::string jail = promptPolicyName("编辑策略参数", false);
        if (jail.empty()) return;
        PromptAnswer key = promptLine("编辑策略参数",
                                      {"1 = enabled", "2 = maxretry", "3 = findtime", "4 = bantime",
                                       "5 = banaction", "6 = filter", "7 = logpath", "8 = backend", "9 = port"},
                                      "字段 [1-9] 或字段名: ");
        if (!key.ok || key.value.empty()) return;
        std::string field = key.value;
        if (field == "1") field = "enabled";
        else if (field == "2") field = "maxretry";
        else if (field == "3") field = "findtime";
        else if (field == "4") field = "bantime";
        else if (field == "5") field = "banaction";
        else if (field == "6") field = "filter";
        else if (field == "7") field = "logpath";
        else if (field == "8") field = "backend";
        else if (field == "9") field = "port";
        const std::set<std::string> allowed = {"enabled", "maxretry", "findtime", "bantime", "banaction", "filter", "logpath", "backend", "port"};
        if (!allowed.count(field)) {
            ScreenBuffer buffer;
            buffer.add("字段不支持。");
            pushResult("编辑策略参数", buffer);
            return;
        }
        PromptAnswer value = promptLine("编辑策略参数",
                                        {"目标策略: " + jail,
                                         "当前 " + field + ": " + configValueOr(readJailValue(jail, field), "未设置")},
                                        "新值: ");
        if (!value.ok || value.value.empty()) return;
        std::string message;
        if ((field == "maxretry" && !validateConfigValue("int", value.value, message)) ||
            ((field == "findtime" || field == "bantime") && !validateConfigValue("time", value.value, message)) ||
            ((field == "filter" || field == "backend" || field == "banaction") && !isSafeIdentifier(value.value)) ||
            (field == "logpath" && !isSafeLogPath(value.value)) ||
            (field == "port" && !isSafePortOrEmpty(removeSpaces(value.value)))) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + (message.empty() ? "字段值不合法。" : message) + ansi::plain);
            pushResult("编辑策略参数", buffer);
            return;
        }
        if (field == "enabled") {
            const std::string lower = lowerCopy(value.value);
            if (lower != "true" && lower != "false") {
                ScreenBuffer buffer;
                buffer.add("enabled 只能是 true 或 false。");
                pushResult("编辑策略参数", buffer);
                return;
            }
            value.value = lower;
        }
        if (!confirmYesNo("将设置 " + jail + " 的 " + field + " = " + value.value, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("编辑策略参数", buffer);
            return;
        }
        std::string backup;
        std::string error;
        const bool ok = applyJailConfigValue(jail, field, value.value, backup, error);
        pushConfigResult("编辑策略参数", ok, backup, error);
    }

    void actionDisableCustomJail() {
        const std::string jail = promptPolicyName("停用自定义策略", true);
        if (jail.empty()) return;
        if (!confirmYesNo("将设置 " + jail + " enabled=false，并保留其它配置。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("停用自定义策略", buffer);
            return;
        }
        std::string backup;
        std::string error;
        const bool ok = applyJailConfigValue(jail, "enabled", "false", backup, error);
        pushConfigResult("停用自定义策略", ok, backup, error);
    }

    void actionUfwCacheStatus() {
#if LTG_HAS_SQLITE
        sqlite3 *db = openUfwCacheDb();
        if (db) {
            sqlitePruneIdleUfwCache(db);
            sqliteTouchUfwCache(db);
            const std::time_t last = sqliteReadUfwActivity(db);
            const std::int64_t eventCount = sqliteSimpleCount(db, "SELECT count(*) FROM events;");
            const std::int64_t rangeCount = sqliteSimpleCount(db, "SELECT count(*) FROM loaded_ranges;");
            sqlite3_close(db);
            ScreenBuffer buffer;
            addKeyValueTable(buffer, {
                {"缓存引擎", "SQLite 原生 C API"},
                {"数据库", ufwCacheDbPath()},
                {"事件记录", std::to_string(eventCount) + " 行 / " + humanBytes(fileSizeBytes(ufwCacheDbPath()))},
                {"已加载范围", std::to_string(rangeCount) + " 段"},
                {"最近使用", last > 0 ? dateTimeStamp(last) : "尚未记录"},
                {"自动清理", "超过 " + std::to_string(kUfwCacheIdleDays) + " 天未使用，下一次进入威胁分析时自动清理"},
            });
            buffer.add("");
            buffer.add("> 说明");
            buffer.add("  SQLite 缓存按 ts/src/dpt/action 建索引，威胁分析直接 GROUP BY 聚合。");
            buffer.add("  最近24小时这种移动窗口只补缺口，不会每次重扫完整窗口。");
            buffer.add("  数据库只用于分析加速，不参与防火墙决策。");
            pushResult("分析缓存", buffer);
            return;
        }
#endif
        pruneIdleUfwCacheIfNeeded();
        touchUfwCacheActivity();
        ScreenBuffer buffer;
        const std::time_t last = readUfwCacheActivity();
        const std::uint64_t eventsBytes = fileSizeBytes(kUfwCacheDir + "/events.tsv");
        const std::uint64_t rangesBytes = fileSizeBytes(kUfwCacheDir + "/ranges.tsv");
        addKeyValueTable(buffer, {
            {"缓存路径", kUfwCacheDir},
            {"事件文件", std::to_string(countFileLines(kUfwCacheDir + "/events.tsv")) + " 行 / " + humanBytes(eventsBytes)},
            {"范围文件", std::to_string(countFileLines(kUfwCacheDir + "/ranges.tsv")) + " 行 / " + humanBytes(rangesBytes)},
            {"最近使用", last > 0 ? dateTimeStamp(last) : "尚未记录"},
            {"自动清理", "超过 " + std::to_string(kUfwCacheIdleDays) + " 天未使用，下一次进入威胁分析时自动清理"},
        });
        buffer.add("");
        buffer.add("> 说明");
        buffer.add("  缓存是普通文本文件，只保存已解析的 UFW 日志事件和已加载时间范围。");
        buffer.add("  它只用于加速“威胁分析”，不会改变 UFW/fail2ban 的实际规则。");
        buffer.add("  每次进入威胁分析会先检查 last_activity；超过空闲期就删除 events.tsv/ranges.tsv 后重建。");
        pushResult("分析缓存", buffer);
    }

    void actionClearUfwCache() {
        if (!confirmYesNo("将删除威胁分析缓存，下一次分析会重新读取系统日志。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("清理缓存", buffer);
            return;
        }
#if LTG_HAS_SQLITE
        sqlite3 *db = openUfwCacheDb();
        if (db) {
            sqliteClearUfwCache(db);
            sqliteTouchUfwCache(db);
            sqlite3_close(db);
            ScreenBuffer buffer;
            buffer.add(ansi::green + std::string("威胁分析 SQLite 缓存已清理。") + ansi::plain);
            buffer.add("已清空: events / loaded_ranges");
            buffer.add("保留: meta.last_activity，用于记录本次清理时间。");
            pushResult("清理缓存", buffer);
            return;
        }
#endif
        clearUfwAnalysisCacheFiles();
        touchUfwCacheActivity();
        ScreenBuffer buffer;
        buffer.add(ansi::green + std::string("威胁分析缓存已清理。") + ansi::plain);
        buffer.add("已删除: events.tsv / ranges.tsv");
        buffer.add("保留: last_activity，用于记录本次清理时间。");
        pushResult("清理缓存", buffer);
    }

    std::string promptJail() {
        PromptAnswer answer = promptLine("选择 Fail2ban 规则",
                                         {"1 = sshd", "2 = ufw-slowscan-global", "3 = 两个规则"},
                                         "目标规则 [1-3]: ");
        if (!answer.ok) {
            return "";
        }
        if (answer.value == "1") return kRule1Jail;
        if (answer.value == "2") return kRule2Jail;
        return "both";
    }

    void actionIpDisposition() {
        PromptAnswer op = promptLine("IP 处置向导",
                                     {"1 = fail2ban 封禁 IP", "2 = fail2ban 解封 IP", "3 = 加入 fail2ban 忽略列表",
                                      "4 = UFW 拒绝来源 IP", "5 = UFW 放行来源 IP"},
                                     "操作 [1-5]: ");
        if (!op.ok) return;
        PromptAnswer ip = promptLine("IP 处置向导", {"请输入 IP 或 CIDR。"}, "IP/CIDR: ");
        if (!ip.ok || ip.value.empty()) {
            ScreenBuffer buffer;
            buffer.add("IP/CIDR 不能为空，操作已取消。");
            pushResult("IP 处置向导", buffer);
            return;
        }
        if (!isValidIpOrCidr(ip.value)) {
            ScreenBuffer buffer;
            buffer.add("IP/CIDR 格式不合法。");
            pushResult("IP 处置向导", buffer);
            return;
        }
        std::string scope;
        if (op.value == "1" || op.value == "2" || op.value == "3") {
            scope = promptJail();
            if (scope.empty()) return;
        }
        if (!confirmYesNo("将执行来源 IP 处置，目标: " + ip.value, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("IP 处置向导", buffer);
            return;
        }
        std::vector<std::string> commands;
        auto addJail = [&](const std::string &jail, const std::string &verb) {
            commands.push_back(fail2banSetIpCommand(jail, verb, ip.value));
        };
        auto forScope = [&](const std::string &verb) {
            if (scope == "both") {
                addJail(kRule1Jail, verb);
                addJail(kRule2Jail, verb);
            } else {
                addJail(scope, verb);
            }
        };
        if (op.value == "1") forScope("banip");
        else if (op.value == "2") {
            forScope("unbanip");
            commands.push_back(ufwDeleteDenyFromCommand(ip.value));
        } else if (op.value == "3") forScope("addignoreip");
        else if (op.value == "4") commands.push_back(ufwDenyFromCommand(ip.value));
        else if (op.value == "5") commands.push_back(ufwAllowFromCommand(ip.value));
        else {
            ScreenBuffer buffer;
            buffer.add("无效操作。");
            pushResult("IP 处置向导", buffer);
            return;
        }
        renderBusy("来源 IP 处置", "正在执行处置动作...");
        cachedDashboardValid() = false;
        pushResult("IP 处置向导", runCommandList(commands));
    }

    void actionPortFirewall() {
        PromptAnswer op = promptLine("端口防火墙向导",
                                     {"1 = UFW 放行端口", "2 = UFW 拒绝端口", "3 = 删除放行规则", "4 = 删除拒绝规则"},
                                     "操作 [1-4]: ");
        if (!op.ok) return;
        PromptAnswer port = promptLine("端口防火墙向导", {"请输入端口，示例: 443。"}, "端口号: ");
        if (!port.ok) return;
        const std::string portValue = removeSpaces(port.value);
        if (!isSafeSinglePort(portValue)) {
            ScreenBuffer buffer;
            buffer.add("端口不合法。示例: 443");
            pushResult("端口防火墙向导", buffer);
            return;
        }
        PromptAnswer proto = promptLine("端口防火墙向导", {"协议可为空，或输入 tcp / udp。"}, "协议: ");
        if (!proto.ok) return;
        const std::string protoValue = removeSpaces(proto.value);
        if (!protoValue.empty() && protoValue != "tcp" && protoValue != "udp") {
            ScreenBuffer buffer;
            buffer.add("协议只允许 tcp 或 udp。");
            pushResult("端口防火墙向导", buffer);
            return;
        }
        const std::string target = protoValue.empty() ? portValue : portValue + "/" + protoValue;
        if (!confirmYesNo("将修改 UFW 端口规则，目标: " + target, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("端口防火墙向导", buffer);
            return;
        }
        std::vector<std::string> commands;
        if (op.value == "1") commands.push_back(ufwPortRuleCommand("allow", target));
        else if (op.value == "2") commands.push_back(ufwPortRuleCommand("deny", target));
        else if (op.value == "3") commands.push_back(ufwDeletePortRuleCommand("allow", target));
        else if (op.value == "4") commands.push_back(ufwDeletePortRuleCommand("deny", target));
        else {
            ScreenBuffer buffer;
            buffer.add("无效操作。");
            pushResult("端口防火墙向导", buffer);
            return;
        }
        renderBusy("端口防火墙向导", "正在修改 UFW 规则...");
        cachedDashboardValid() = false;
        pushResult("端口防火墙向导", runCommandList(commands));
    }

    void actionEnableUfwSafely() {
        renderBusy("启用 UFW", "正在检查 SSH 端口与现有放行规则...");
        const UfwSshExposure exposure = inspectUfwSshExposure();
        ScreenBuffer buffer;
        buffer.add(ansi::yellow + std::string("启用 UFW 可能影响当前远程连接。") + ansi::plain);
        buffer.add("");
        buffer.add("检测到的 SSH 端口: " + joinWords(exposure.sshPorts));
        buffer.add("常见 SSH 端口: 22/tcp");
        buffer.add("");
        buffer.add("现有 SSH/UFW 放行规则:");
        if (exposure.allowRules.empty()) {
            buffer.add("  " + ansi::yellow + std::string("- 未发现匹配 SSH 端口的 allow 规则") + ansi::plain);
        } else {
            for (const auto &line : exposure.allowRules) {
                buffer.add("  " + line);
            }
        }
        buffer.add("");
        buffer.add("建议先确认已放行当前 SSH 端口，例如:");
        for (const auto &port : exposure.sshPorts) {
            buffer.add("  ufw allow " + port + "/tcp");
        }
        if (std::find(exposure.sshPorts.begin(), exposure.sshPorts.end(), "22") == exposure.sshPorts.end()) {
            buffer.add("  ufw allow 22/tcp");
        }

        if (exposure.hasAllowRule()) {
            buffer.add("");
            buffer.add("已发现 SSH 放行规则。仍将执行: ufw --force enable");
            if (!confirmYesNoWithBody("启用 UFW 风险预检", buffer.lines(), false)) {
                ScreenBuffer cancel;
                cancel.add("操作已取消。");
                pushResult("启用 UFW", cancel);
                return;
            }
        } else {
            buffer.add("");
            buffer.add(ansi::yellow + std::string("未发现 SSH allow 规则。若你通过 SSH 操作，继续可能导致断连。") + ansi::plain);
            std::vector<std::string> body = buffer.lines();
            body.push_back("");
            body.push_back("未发现 SSH allow 规则。普通 y/回车不会执行。");
            body.push_back("只有确认已保留控制台或已手动放行 SSH 后，才输入完整确认词。");
            PromptAnswer confirm = promptLine("启用 UFW 强确认",
                                              body,
                                              "输入 ENABLE UFW 执行: ");
            if (!confirm.ok || confirm.value != "ENABLE UFW") {
                ScreenBuffer cancel;
                cancel.add("确认词不匹配，操作已取消。");
                pushResult("启用 UFW", cancel);
                return;
            }
        }

        renderBusy("启用 UFW", "正在执行 ufw --force enable...");
        cachedDashboardValid() = false;
        pushResult("启用 UFW", runCommandList({"ufw --force enable"}));
    }

    void actionServiceControl() {
        PromptAnswer op = promptLine("服务控制",
                                     {"1 = 重启 fail2ban", "2 = 启用并启动 fail2ban", "3 = 停止 fail2ban",
                                      "4 = 启用 UFW", "5 = 重载 UFW"},
                                     "操作 [1-5]: ");
        if (!op.ok) return;
        std::string command;
        if (op.value == "1") command = "systemctl restart fail2ban";
        else if (op.value == "2") command = "systemctl enable --now fail2ban";
        else if (op.value == "3") command = "systemctl stop fail2ban";
        else if (op.value == "4") {
            actionEnableUfwSafely();
            return;
        }
        else if (op.value == "5") command = "ufw reload";
        else {
            ScreenBuffer buffer;
            buffer.add("无效操作。");
            pushResult("服务控制", buffer);
            return;
        }
        if (!confirmYesNo("将执行: " + command, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("服务控制", buffer);
            return;
        }
        renderBusy("服务控制", "正在执行服务命令...");
        cachedDashboardValid() = false;
        pushResult("服务控制", runCommandList({command}));
    }

    bool validateConfigValue(const std::string &type, const std::string &value, std::string &message) {
        if (type == "time" && !isValidTimeToken(value)) {
            message = "时间格式错误。支持 600、10m、2h、1d、1w。";
            return false;
        }
        if (type == "int" && !isValidPositiveInt(value)) {
            message = "请输入正整数。";
            return false;
        }
        if (type == "factor" && !isValidPositiveNumber(value)) {
            message = "请输入正数，例如 1.5 或 2。";
            return false;
        }
        return true;
    }

    void pushConfigResult(const std::string &title, bool ok, const std::string &backupPath, const std::string &error) {
        ScreenBuffer buffer;
        buffer.add(ok ? ansi::green + std::string("配置已写入。") + ansi::plain
                      : ansi::yellow + std::string("配置写入失败。") + ansi::plain);
        if (!backupPath.empty()) {
            buffer.add("备份: " + backupPath);
        }
        if (!error.empty()) {
            buffer.add("原因: " + error);
        }
        if (ok) {
            buffer.add("");
            buffer.add("建议重载:");
            buffer.add("systemctl restart fail2ban");
        }
        pushResult(title, buffer);
    }

    void actionChangeJailParam(const std::string &jail,
                               const std::string &key,
                               const std::string &type,
                               const std::string &title) {
        const F2bJailConfig cfg = readJailConfig(jail);
        std::string current;
        if (key == "maxretry") current = cfg.maxretry;
        else if (key == "findtime") current = cfg.findtime;
        else if (key == "bantime") current = cfg.bantime;
        else if (key == "bantime.factor") current = cfg.factor;
        else if (key == "bantime.maxtime") current = cfg.maxtime;
        PromptAnswer value = promptLine(title,
                                        {"目标规则: " + jail,
                                         "当前值: " + (current.empty() ? "未设置" : current),
                                         type == "time" ? "时间格式: 600、10m、2h、1d、1w" : "输入新值，留空取消。"},
                                        "新值: ");
        if (!value.ok || value.value.empty()) {
            return;
        }
        std::string error;
        if (!validateConfigValue(type, value.value, error)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + error + ansi::plain);
            pushResult(title, buffer);
            return;
        }
        if (!confirmYesNo("将修改 " + jail + " 的 " + key + " = " + value.value, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult(title, buffer);
            return;
        }
        std::string backup;
        const bool ok = applyJailConfigValue(jail, key, value.value, backup, error);
        pushConfigResult(title, ok, backup, error);
    }

    void actionToggleJailEnabled(const std::string &jail) {
        const F2bJailConfig cfg = readJailConfig(jail);
        const std::string next = lowerCopy(cfg.enabled) == "true" ? "false" : "true";
        if (!confirmYesNo("将设置 " + jail + " enabled = " + next, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("启用/关闭规则", buffer);
            return;
        }
        std::string backup;
        std::string error;
        const bool ok = applyJailConfigValue(jail, "enabled", next, backup, error);
        pushConfigResult("启用/关闭规则", ok, backup, error);
    }

    void actionToggleIncrement() {
        const F2bJailConfig cfg = readJailConfig(kRule1Jail);
        const std::string next = lowerCopy(cfg.increment) == "true" ? "false" : "true";
        if (!confirmYesNo("将设置 sshd bantime.increment = " + next, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("指数封禁开关", buffer);
            return;
        }
        std::string backup;
        std::string error;
        const bool ok = applyJailConfigValue(kRule1Jail, "bantime.increment", next, backup, error);
        pushConfigResult("指数封禁开关", ok, backup, error);
    }

    void actionApplyUfwDrop(const std::string &jail) {
        if (!confirmYesNo("将设置 " + jail + " banaction = ufw-drop，并确保 action 文件存在。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("强制全端口动作", buffer);
            return;
        }
        std::string backup;
        std::string error;
        ScreenBuffer buffer;
        bool ok = writeManagedFileWithBackup(kUfwDropActionFile, renderUfwDropActionFile(), backup, error);
        buffer.add(ok ? ansi::green + std::string("ufw-drop action 已写入。") + ansi::plain
                      : ansi::yellow + "ufw-drop action 写入失败: " + error + ansi::plain);
        if (!backup.empty()) buffer.add("备份: " + backup);
        backup.clear();
        error.clear();
        ok = applyJailConfigValue(jail, "banaction", "ufw-drop", backup, error);
        buffer.add(ok ? ansi::green + std::string("banaction 已设置。") + ansi::plain
                      : ansi::yellow + "banaction 设置失败: " + error + ansi::plain);
        if (!backup.empty()) buffer.add("备份: " + backup);
        pushResult("强制全端口动作", buffer);
    }

    void actionChangeBanScope(const std::string &jail) {
        PromptAnswer choice = promptLine("封禁范围策略",
                                         {"1 = fail2ban 默认动作", "2 = ufw-drop 全端口封禁"},
                                         "选择 [1-2]: ");
        if (!choice.ok) return;
        if (choice.value == "2") {
            actionApplyUfwDrop(jail);
            return;
        }
        if (choice.value != "1") {
            ScreenBuffer buffer;
            buffer.add("无效选择。");
            pushResult("封禁范围策略", buffer);
            return;
        }
        if (!confirmYesNo("将清空 " + jail + " 的 banaction，使其回到 fail2ban 默认动作。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("封禁范围策略", buffer);
            return;
        }
        std::string backup;
        std::string error;
        const bool ok = applyJailConfigValue(jail, "banaction", "iptables-multiport", backup, error);
        pushConfigResult("封禁范围策略", ok, backup, error);
    }

    void actionChangeBothRules(const std::string &key, const std::string &type, const std::string &title) {
        PromptAnswer value = promptLine("全局同步: " + title,
                                        {"目标: sshd 和 ufw-slowscan-global", "输入新值，留空取消。"},
                                        "新值: ");
        if (!value.ok || value.value.empty()) return;
        std::string error;
        if (!validateConfigValue(type, value.value, error)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + error + ansi::plain);
            pushResult("全局同步: " + title, buffer);
            return;
        }
        if (!confirmYesNo("将同时设置两个规则的 " + key + " = " + value.value, false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("全局同步: " + title, buffer);
            return;
        }
        ScreenBuffer buffer;
        for (const auto &jail : {kRule1Jail, kRule2Jail}) {
            std::string backup;
            error.clear();
            const bool ok = applyJailConfigValue(jail, key, value.value, backup, error);
            buffer.add(std::string(ok ? "[OK] " : "[WARN] ") + jail + " " + key + " = " + value.value);
            if (!backup.empty()) buffer.add("  备份: " + backup);
            if (!error.empty()) buffer.add("  原因: " + error);
        }
        pushResult("全局同步: " + title, buffer);
    }

    void actionF2bUnban(const std::string &scope) {
        PromptAnswer ip = promptLine("Fail2ban 解封", {"请输入要解封的 IP。"}, "IP: ");
        if (!ip.ok || ip.value.empty()) return;
        if (!isValidIpOrCidr(ip.value)) {
            ScreenBuffer buffer;
            buffer.add("IP/CIDR 格式不合法。");
            pushResult("Fail2ban 解封", buffer);
            return;
        }
        if (!confirmYesNo("将从 " + scope + " 解封 " + ip.value + "，并尝试删除 UFW deny。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("Fail2ban 解封", buffer);
            return;
        }
        std::vector<std::string> commands;
        auto add = [&](const std::string &jail) {
            commands.push_back(fail2banSetIpCommand(jail, "unbanip", ip.value));
        };
        if (scope == "both") {
            add(kRule1Jail);
            add(kRule2Jail);
        } else {
            add(scope);
        }
        commands.push_back(ufwDeleteDenyFromCommand(ip.value));
        renderBusy("Fail2ban 解封", "正在解封...");
        pushResult("Fail2ban 解封", runCommandList(commands));
    }

    void actionAddIgnoreIp(const std::string &scope) {
        PromptAnswer ip = promptLine("白名单管理",
                                     {"输入 IP/CIDR。DEFAULT 表示写入 [DEFAULT] ignoreip。"},
                                     "IP/CIDR: ");
        if (!ip.ok || ip.value.empty()) return;
        if (!isValidIpOrCidr(ip.value)) {
            ScreenBuffer buffer;
            buffer.add("IP/CIDR 格式不合法。");
            pushResult("白名单管理", buffer);
            return;
        }
        if (!confirmYesNo("将把 " + ip.value + " 加入 " + scope + " 白名单。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("白名单管理", buffer);
            return;
        }
        ScreenBuffer buffer;
        const std::vector<std::string> targets =
            scope == "both" ? std::vector<std::string>{kRule1Jail, kRule2Jail} : std::vector<std::string>{scope};
        for (const auto &target : targets) {
            IniConfig ini;
            ini.load(kJailConf);
            const std::string current = ini.get(target, "ignoreip");
            std::vector<std::string> words = splitWords(current);
            if (std::find(words.begin(), words.end(), ip.value) == words.end()) {
                words.push_back(ip.value);
            }
            ini.set(target, "ignoreip", joinWords(words));
            std::string backup;
            const bool ok = ini.save(backup);
            buffer.add(std::string(ok ? "[OK] " : "[WARN] ") + target + " ignoreip = " + joinWords(words));
            if (!backup.empty()) buffer.add("  备份: " + backup);
        }
        pushResult("白名单管理", buffer);
    }

    void actionEnsureFail2banStack() {
        if (!confirmYesNo("将创建/修复 jail.local、UFW 慢扫 filter、ufw-drop action，并重载 fail2ban。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("安装/修复配置", buffer);
            return;
        }
        ScreenBuffer buffer;
        std::vector<std::string> failures;
        std::string backup;
        std::string error;
        bool ok = writeManagedFileWithBackup(kRule2FilterFile, renderRule2FilterFile(), backup, error);
        buffer.add(ok ? "[OK] 规则2 filter 已写入" : "[WARN] 规则2 filter 写入失败: " + error);
        if (!backup.empty()) buffer.add("  备份: " + backup);
        if (!ok) failures.push_back(kRule2FilterFile + ": " + error);
        backup.clear();
        error.clear();
        ok = writeManagedFileWithBackup(kUfwDropActionFile, renderUfwDropActionFile(), backup, error);
        buffer.add(ok ? "[OK] ufw-drop action 已写入" : "[WARN] ufw-drop action 写入失败: " + error);
        if (!backup.empty()) buffer.add("  备份: " + backup);
        if (!ok) failures.push_back(kUfwDropActionFile + ": " + error);

        IniConfig ini;
        ini.load(kJailConf);
        ini.set(kRule1Jail, "enabled", configValueOr(ini.get(kRule1Jail, "enabled"), "true"));
        ini.set(kRule1Jail, "maxretry", configValueOr(ini.get(kRule1Jail, "maxretry"), "5"));
        ini.set(kRule1Jail, "findtime", configValueOr(ini.get(kRule1Jail, "findtime"), "3600"));
        ini.set(kRule1Jail, "bantime", configValueOr(ini.get(kRule1Jail, "bantime"), "600"));
        ini.set(kRule2Jail, "enabled", configValueOr(ini.get(kRule2Jail, "enabled"), "true"));
        ini.set(kRule2Jail, "filter", "ufw-slowscan-global");
        ini.set(kRule2Jail, "backend", "systemd");
        ini.set(kRule2Jail, "journalmatch", "_TRANSPORT=kernel");
        ini.set(kRule2Jail, "maxretry", configValueOr(ini.get(kRule2Jail, "maxretry"), "50"));
        ini.set(kRule2Jail, "findtime", configValueOr(ini.get(kRule2Jail, "findtime"), "3600"));
        ini.set(kRule2Jail, "bantime", configValueOr(ini.get(kRule2Jail, "bantime"), "1d"));
        ini.set(kRule2Jail, "banaction", "ufw-drop");
        backup.clear();
        ok = ini.save(backup);
        buffer.add(ok ? "[OK] jail.local 已更新" : "[WARN] jail.local 写入失败");
        if (!backup.empty()) buffer.add("  备份: " + backup);
        if (!ok) failures.push_back(kJailConf + ": 无法写入");
        buffer.add("");
        if (!failures.empty()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("关键配置写入失败，已停止重载 fail2ban。") + ansi::plain);
            result.add("请先修复下面的问题，再重新执行安装/修复配置。");
            result.add("");
            for (const auto &failure : failures) {
                result.add("- " + failure);
            }
            result.add("");
            result.addAll(buffer.lines());
            pushResult("安装/修复配置", result);
            return;
        }
        buffer.addAll(runCommandList(ensureFail2banBaselineCommands()).lines());
        pushResult("安装/修复配置", buffer);
    }

    void actionSyncF2bToUfw() {
        if (!confirmYesNo("将为 fail2ban 当前封禁 IP 补齐 UFW deny 规则。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("防护链路同步", buffer);
            return;
        }
        const std::string ufw = Shell::capture("ufw status numbered 2>/dev/null || true").output;
        std::vector<std::string> commands;
        for (const auto &jail : {kRule1Jail, kRule2Jail}) {
            for (const auto &ip : bannedSetForJail(jail)) {
                if (ufw.find(ip) == std::string::npos) {
                    commands.push_back(ufwDenyFromCommand(ip, "f2b:" + jail + " ip:" + ip));
                }
            }
        }
        if (commands.empty()) {
            ScreenBuffer buffer;
            buffer.add("没有发现需要补齐的 UFW deny 规则。");
            pushResult("防护链路同步", buffer);
            return;
        }
        renderBusy("防护链路同步", "正在补齐 UFW 规则...");
        pushResult("防护链路同步", runCommandList(commands));
    }

    void actionDualAudit(bool forceFix) {
        (void)forceFix;
        const F2bJailConfig cfg = readJailConfig(kRule2Jail);
        long long seconds = 3600;
        parseTimeToSeconds(configValueOr(cfg.findtime, "3600"), seconds);
        const std::time_t end = std::time(nullptr);
        const std::time_t start = end - static_cast<std::time_t>(seconds);
        renderBusy("双日志核验", "正在读取 UFW 与 fail2ban 日志...");
        const auto rows = buildDualAuditRows(start, end, 40);
        ScreenBuffer buffer;
        buffer.add("窗口: " + dateTimeStamp(start) + " ~ " + dateTimeStamp(end));
        buffer.add("规则2阈值: " + configValueOr(cfg.maxretry, "50") + " 次 / " + configValueOr(cfg.findtime, "3600"));
        buffer.add("");
        const std::vector<int> widths = {34, 10, 8, 8, 10, 28};
        buffer.add(bufferTableRow({"IP", "UFW命中", "规则1", "规则2", "窗口Ban", "结论"}, widths, true));
        buffer.add(bufferTableRule(widths));
        std::vector<std::string> fixIps;
        for (const auto &row : rows) {
            const bool needsFix = row.conclusion == "达到规则2阈值但未封禁";
            if (needsFix) fixIps.push_back(row.ip);
            buffer.add(bufferTableRow({row.ip, std::to_string(row.ufwHits), row.rule1Banned ? "是" : "否",
                                       row.rule2Banned ? "是" : "否", row.banLogged ? "是" : "否",
                                       needsFix ? ansi::yellow + row.conclusion + ansi::plain : row.conclusion}, widths));
        }
        if (rows.empty()) {
            buffer.add("  " + ansi::gray + "- 当前窗口无 UFW BLOCK/AUDIT 命中" + ansi::plain);
        }
        if (!fixIps.empty()) {
            buffer.add("");
            buffer.add(ansi::yellow + std::string("候选补封禁 IP: ") + std::to_string(fixIps.size()) + ansi::plain);
            for (const auto &ip : fixIps) {
                buffer.add("  - " + ip);
            }
            buffer.add("如需执行，请返回“一致性核验 -> 补封禁候选 IP”。");
        }
        pushResult("双日志核验", buffer);
    }

    void actionBanDualAuditCandidates() {
        const F2bJailConfig cfg = readJailConfig(kRule2Jail);
        long long seconds = 3600;
        parseTimeToSeconds(configValueOr(cfg.findtime, "3600"), seconds);
        const std::time_t end = std::time(nullptr);
        const std::time_t start = end - static_cast<std::time_t>(seconds);
        renderBusy("补封禁候选 IP", "正在重新核验候选 IP...");
        const auto rows = buildDualAuditRows(start, end, 40);
        const auto fixIps = dualAuditCandidateIps(rows);
        ScreenBuffer preview;
        preview.add("窗口: " + dateTimeStamp(start) + " ~ " + dateTimeStamp(end));
        preview.add("规则2阈值: " + configValueOr(cfg.maxretry, "50") + " 次 / " + configValueOr(cfg.findtime, "3600"));
        preview.add("");
        if (fixIps.empty()) {
            preview.add("没有发现需要补封禁的候选 IP。");
            pushResult("补封禁候选 IP", preview);
            return;
        }
        preview.add(ansi::yellow + std::string("将补封禁以下候选 IP:") + ansi::plain);
        for (const auto &ip : fixIps) {
            preview.add("  - " + ip);
        }
        preview.add("");
        preview.add("执行命令会写入 fail2ban 运行状态，并影响对应来源访问。");
        preview.add("");
        preview.add("将对 " + std::to_string(fixIps.size()) + " 个候选 IP 执行规则2补封禁。");
        if (!confirmYesNoWithBody("补封禁候选 IP 预览", preview.lines(), false)) {
            ScreenBuffer cancel;
            cancel.add("操作已取消。");
            pushResult("补封禁候选 IP", cancel);
            return;
        }
        std::vector<std::string> commands;
        for (const auto &ip : fixIps) {
            commands.push_back(fail2banSetIpCommand(kRule2Jail, "banip", ip));
        }
        commands.push_back("ufw reload || true");
        pushResult("补封禁候选 IP", runCommandList(commands));
    }

    void actionF2bBanLogs() {
        renderBusy("查看封禁日志", "正在读取 fail2ban 日志...");
        pushResult("查看封禁日志", runCommandList({
            "journalctl -u fail2ban --no-pager -n 240 2>/dev/null | grep ' Ban ' || tail -n 240 /var/log/fail2ban.log 2>/dev/null | grep ' Ban ' || true"}));
    }

    void actionCurrentBanDetails() {
        renderBusy("当前封禁详情", "正在读取当前封禁列表...");
        ScreenBuffer buffer;
        const std::vector<int> widths = {20, 34, 20, 18};
        buffer.add(bufferTableRow({"规则", "IP", "最后封禁时间", "剩余时间"}, widths, true));
        buffer.add(bufferTableRule(widths));
        bool empty = true;
        for (const auto &jail : {kRule1Jail, kRule2Jail}) {
            for (const auto &ip : bannedSetForJail(jail)) {
                empty = false;
                const std::time_t last = lastBanTimestamp(jail, ip);
                buffer.add(bufferTableRow({jail, ip, last > 0 ? dateTimeStamp(last) : "未知", remainingBanTime(jail, ip)}, widths));
            }
        }
        if (empty) buffer.add("  " + ansi::gray + "- 当前无 fail2ban 封禁 IP" + ansi::plain);
        pushResult("当前封禁详情", buffer);
    }

    void actionRepairUfwAnomalies() {
        renderBusy("UFW异常修复", "正在解析待清理规则...");
        const auto candidates = findUfwAnomalyDeleteCandidates();
        ScreenBuffer preview;
        if (candidates.empty()) {
            preview.add("没有发现需要删除的失效/重复 f2b UFW deny 规则。");
            pushResult("UFW异常修复", preview);
            return;
        }
        preview.add(ansi::yellow + std::string("将删除以下 UFW deny 规则:") + ansi::plain);
        preview.add("");
        const std::vector<int> widths = {8, 34, 28};
        preview.add(bufferTableRow({"编号", "IP", "原因"}, widths, true));
        preview.add(bufferTableRule(widths));
        for (const auto &candidate : candidates) {
            preview.add(bufferTableRow({std::to_string(candidate.number), candidate.ip, candidate.reason}, widths));
            preview.add("  规则: " + candidate.line);
        }
        preview.add("");
        preview.add("规则编号会按倒序删除，避免 UFW 编号重排导致误删。");
        preview.add("");
        preview.add("确认删除上述 " + std::to_string(candidates.size()) + " 条 UFW 规则?");
        if (!confirmYesNoWithBody("UFW异常修复预览", preview.lines(), false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("UFW异常修复", buffer);
            return;
        }
        std::vector<std::string> commands;
        std::vector<UfwDeleteCandidate> sorted = candidates;
        std::sort(sorted.begin(), sorted.end(), [](const UfwDeleteCandidate &a, const UfwDeleteCandidate &b) {
            return a.number > b.number;
        });
        for (const auto &candidate : sorted) {
            commands.push_back("ufw --force delete " + std::to_string(candidate.number));
        }
        commands.push_back("true");
        renderBusy("UFW异常修复", "正在清理异常 UFW 规则...");
        ScreenBuffer buffer = runCommandList(commands);
        buffer.add("");
        buffer.add("下一步建议: 返回执行“防护链路同步”补齐缺失规则。");
        pushResult("UFW异常修复", buffer);
    }

    void actionExportF2bDiagnostic() {
        const std::string out = "/tmp/f2b-panel-ltg-" + nowStamp() + ".log";
        if (!confirmYesNo("将在 /tmp 写入 Fail2ban/UFW 诊断报告: " + out +
                          "。内容包含服务状态、UFW/fail2ban 配置、规则编号和日志片段，可能含来源 IP、端口与路径信息。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("导出防护诊断", buffer);
            return;
        }
        std::ostringstream cmd;
        cmd << "{ "
            << "echo '### time'; date; "
            << "echo; echo '### systemctl fail2ban'; systemctl status fail2ban --no-pager -l 2>&1; "
            << "echo; echo '### journal fail2ban'; journalctl -u fail2ban --no-pager -n 220 2>&1; "
            << "echo; echo '### fail2ban client'; fail2ban-client -V 2>&1; fail2ban-client ping 2>&1; fail2ban-client status 2>&1; fail2ban-client status " << kRule1Jail << " 2>&1; fail2ban-client status " << kRule2Jail << " 2>&1; "
            << "echo; echo '### ufw'; ufw status verbose 2>&1; ufw status numbered 2>&1; "
            << "echo; echo '### jail.local'; sed -n '1,260p' " << shellQuote(kJailConf) << " 2>&1; "
            << "echo; echo '### ufw-drop action'; sed -n '1,220p' " << shellQuote(kUfwDropActionFile) << " 2>&1; "
            << "echo; echo '### rule2 filter'; sed -n '1,160p' " << shellQuote(kRule2FilterFile) << " 2>&1; "
            << "echo; echo '### fail2ban log'; tail -n 260 /var/log/fail2ban.log 2>&1; "
            << "} > " << shellQuote(out);
        renderBusy("导出防护诊断", "正在写入报告...");
        ScreenBuffer buffer = runCommandList({cmd.str()});
        buffer.add("报告路径: " + out);
        pushResult("导出防护诊断", buffer);
    }

    void pushUfwAnalysisReport(const std::string &title, std::time_t start, std::time_t end, const std::string &traceIp = "") {
        renderBusy("威胁分析", "正在加载日志与分析缓存...");
        const UfwAnalysisReport report = analyzeUfwEvents(title, start, end, false);
        ScreenBuffer buffer;
        addUfwAnalysisToBuffer(buffer, report, traceIp);
        pushResult("威胁分析 - " + title, buffer);
    }

    void actionUfwAnalyzeHours(int hours) {
        const std::time_t end = std::time(nullptr);
        pushUfwAnalysisReport("最近" + std::to_string(hours) + "小时", end - hours * 3600, end);
    }

    void actionUfwAnalyzeDays(int days) {
        const std::time_t end = std::time(nullptr);
        pushUfwAnalysisReport("最近" + std::to_string(days) + "天", end - days * 86400, end);
    }

    void actionUfwAnalyzeCustom() {
        PromptAnswer startText = promptLine("自定义时间段", {"日期格式: YYYY MM DD、YYYY-MM-DD、MM DD。开始留空=今天 00:00:00。"}, "开始日期: ");
        if (!startText.ok) return;
        std::time_t start = 0;
        if (trim(startText.value).empty()) {
            std::tm tm{};
            const std::time_t now = std::time(nullptr);
#ifdef _WIN32
            localtime_s(&tm, &now);
#else
            localtime_r(&now, &tm);
#endif
            tm.tm_hour = 0;
            tm.tm_min = 0;
            tm.tm_sec = 0;
            start = makeLocalTime(tm);
        } else if (!parseYmdDate(startText.value, false, start)) {
            ScreenBuffer buffer;
            buffer.add("开始日期格式无效。");
            pushResult("自定义时间段", buffer);
            return;
        }
        PromptAnswer endText = promptLine("自定义时间段", {"结束留空=开始日期 23:59:59。"}, "结束日期: ");
        if (!endText.ok) return;
        std::time_t end = 0;
        if (trim(endText.value).empty()) {
            std::tm tm{};
#ifdef _WIN32
            localtime_s(&tm, &start);
#else
            localtime_r(&start, &tm);
#endif
            tm.tm_hour = 23;
            tm.tm_min = 59;
            tm.tm_sec = 59;
            end = makeLocalTime(tm);
        } else if (!parseYmdDate(endText.value, true, end)) {
            ScreenBuffer buffer;
            buffer.add("结束日期格式无效。");
            pushResult("自定义时间段", buffer);
            return;
        }
        if (end < start) {
            ScreenBuffer buffer;
            buffer.add("结束时间不能早于开始时间。");
            pushResult("自定义时间段", buffer);
            return;
        }
        pushUfwAnalysisReport("自定义时间段", start, end);
    }

    void actionUfwTraceIp() {
        PromptAnswer days = promptLine("指定IP追查", {"输入分析天数，例如 1、7、28。"}, "天数: ", "7");
        if (!days.ok) return;
        if (!isValidPositiveInt(days.value)) {
            ScreenBuffer buffer;
            buffer.add("天数必须是正整数。");
            pushResult("指定IP追查", buffer);
            return;
        }
        PromptAnswer ip = promptLine("指定IP追查", {"请输入要追查的 IP。"}, "IP: ");
        if (!ip.ok || ip.value.empty()) return;
        if (!isValidIpOrCidr(ip.value) || ip.value.find('/') != std::string::npos) {
            ScreenBuffer buffer;
            buffer.add("请输入单个有效 IP，CIDR 不适用于下钻追查。");
            pushResult("指定IP追查", buffer);
            return;
        }
        const std::time_t end = std::time(nullptr);
        const int d = std::stoi(days.value);
        pushUfwAnalysisReport("最近" + std::to_string(d) + "天 IP追查", end - d * 86400, end, ip.value);
    }

    void actionConntrackSnapshot() {
        PromptAnswer ports = promptLine("conntrack 实时快照",
                                        {"过滤端口可为空，或输入 80,443。"},
                                        "过滤端口: ");
        if (!ports.ok) return;
        const std::string value = removeSpaces(ports.value);
        if (!isSafePortOrEmpty(value)) {
            ScreenBuffer buffer;
            buffer.add("端口列表不合法。示例: 80,443");
            pushResult("conntrack 实时快照", buffer);
            return;
        }
        std::string command = "conntrack -L -o extended 2>/dev/null";
        if (!value.empty()) {
            std::string regex = value;
            std::replace(regex.begin(), regex.end(), ',', '|');
            command += " | grep -E 'dport=(" + regex + ")|sport=(" + regex + ")'";
        }
        renderBusy("conntrack 实时快照", "正在读取活跃连接...");
        CommandResult result = Shell::capture(command + " | head -160 || true");
        ScreenBuffer buffer;
        const std::string output = trim(result.output);
        if (output.empty()) buffer.add("(无输出)");
        else buffer.addAll(splitLines(output));
        pushResult("conntrack 实时快照", buffer);
    }

    void actionFocusedPortInspect() {
        PromptAnswer port = promptLine("端口下钻", {"请输入单个端口，例如 443。"}, "端口号: ");
        if (!port.ok) return;
        const std::string value = removeSpaces(port.value);
        if (!isSafeSinglePort(value)) {
            ScreenBuffer buffer;
            buffer.add("端口不合法。请输入单个端口，例如 443。");
            pushResult("端口下钻", buffer);
            return;
        }
        renderBusy("端口下钻", "正在读取端口相关信息...");
        std::vector<std::string> commands = {
            "ss -tulpen 2>/dev/null | awk '$0 ~ /:" + value + "([[:space:]]|$)/ {print}' || true",
            "ufw status numbered 2>/dev/null | grep -E '(^|[^0-9])" + value + "([^0-9]|$)' || true",
            "nft list table inet " + kIpTrafficTable + " 2>/dev/null | grep -E '(^|[^0-9])" + value + "([^0-9]|$)|bytes|elements' | head -160 || true",
            "conntrack -L -o extended 2>/dev/null | grep -E 'dport=" + value + "|sport=" + value + "' | head -80 || true",
        };
        pushResult("端口下钻", runCommandList(commands));
    }

    void actionDependencyDoctor() {
        ScreenBuffer buffer;
        const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl", "systemctl", "awk", "grep"};
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto &tool : tools) {
            rows.push_back({tool, Shell::exists(tool) ? Ui::badge("可用", ansi::green) : Ui::badge("缺失", ansi::yellow)});
        }
        addKeyValueTable(buffer, rows);
        buffer.add("");
        buffer.add("Debian/Ubuntu 安装命令:");
        buffer.add("apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev");
        pushResult("依赖检查", buffer);
    }

    void actionLogSummary() {
        renderBusy("日志摘要", "正在读取日志...");
        pushResult("日志摘要", runCommandList({
            "tail -n 120 /var/log/fail2ban.log 2>/dev/null || journalctl -u fail2ban --no-pager -n 120 2>/dev/null || true",
            "journalctl -k --no-pager -n 160 2>/dev/null | grep -i 'ufw' || tail -n 160 /var/log/ufw.log 2>/dev/null || true",
        }));
    }

    void actionExportReport() {
        const std::string out = "/tmp/linux-traffic-guard-" + nowStamp() + ".log";
        if (!confirmYesNo("将在 /tmp 写入诊断报告: " + out +
                          "。内容包含服务状态、监听进程、conntrack、UFW/fail2ban 状态和日志片段，可能含来源 IP 与端口信息。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("导出诊断报告", buffer);
            return;
        }
        std::ostringstream cmd;
        cmd << "{ "
            << "echo '### time'; date; "
            << "echo; echo '### services'; systemctl status fail2ban --no-pager -l 2>/dev/null | sed -n '1,60p'; "
            << "echo; echo '### fail2ban'; fail2ban-client status 2>/dev/null; fail2ban-client status " << kRule1Jail << " 2>/dev/null; fail2ban-client status " << kRule2Jail << " 2>/dev/null; "
            << "echo; echo '### ufw'; ufw status verbose 2>/dev/null; "
            << "echo; echo '### listeners'; ss -tulpen 2>/dev/null | head -160; "
            << "echo; echo '### accounting'; nft list table inet " << kIpTrafficTable << " 2>/dev/null; "
            << "echo; echo '### conntrack'; conntrack -L -o extended 2>/dev/null | head -180; "
            << "echo; echo '### fail2ban log'; tail -n 220 /var/log/fail2ban.log 2>/dev/null; "
            << "echo; echo '### ufw log'; journalctl -k --no-pager -n 220 2>/dev/null | grep -i 'ufw' || true; "
            << "} > " << shellQuote(out);
        renderBusy("导出诊断报告", "正在写入报告...");
        ScreenBuffer buffer = runCommandList({cmd.str()});
        buffer.add("报告路径: " + out);
        pushResult("导出诊断报告", buffer);
    }

    void actionInstallDependencies() {
        if (!confirmYesNo("将通过 apt 安装 fail2ban/ufw/nftables/iproute2/conntrack。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("安装常见依赖", buffer);
            return;
        }
        renderBusy("安装常见依赖", "正在执行 apt 命令...");
        ScreenBuffer buffer = runCommandList({"apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev"});
        Shell::clearExistsCache();
        cachedDashboardValid() = false;
        buffer.add("");
        buffer.add("已刷新依赖检测缓存。返回仪表盘后会重新读取工具状态。");
        pushResult("安装常见依赖", buffer);
    }
};

inline void printScreenBuffer(const ScreenBuffer &buffer) {
    const bool useColor = shouldUseColor();
    for (const auto &line : buffer.lines()) {
        std::cout << (useColor ? line : stripAnsi(line)) << "\n";
    }
}

inline void addSection(ScreenBuffer &buffer, const std::string &title) {
    if (!buffer.lines().empty()) {
        buffer.add("");
    }
    buffer.add(ansi::cyan + "> " + title + ansi::plain);
}

inline void addTableLines(ScreenBuffer &buffer, const Table &table, const std::string &emptyMessage = "暂无数据") {
    buffer.addAll(tableLines(table, emptyMessage));
}

inline ScreenBuffer commandListBuffer(const std::vector<std::string> &commands) {
    ScreenBuffer buffer;
    bool ok = true;
    for (const auto &command : commands) {
        buffer.add(ansi::gray + "$ " + command + ansi::plain);
        const CommandResult result = Shell::capture(command);
        ok = ok && result.ok();
        buffer.add(result.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                               : ansi::yellow + "exit " + std::to_string(result.exitCode) + ansi::plain);
        const std::string output = trim(result.output);
        if (!output.empty()) {
            buffer.addAll(splitLines(output));
        }
        buffer.add("");
    }
    buffer.add(ok ? ansi::green + std::string("操作完成。") + ansi::plain
                  : ansi::yellow + std::string("部分命令失败，请查看上方输出。") + ansi::plain);
    return buffer;
}

inline ScreenBuffer dependencyDoctorBuffer() {
    ScreenBuffer buffer;
    const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl", "systemctl", "awk", "grep"};
    Table table({"工具", "状态"}, {24, 14});
    for (const auto &tool : tools) {
        table.add({tool, Shell::exists(tool) ? "可用" : "缺失"});
    }
    addSection(buffer, "依赖检查");
    addTableLines(buffer, table);
    buffer.add("");
    buffer.add("Debian/Ubuntu 安装命令:");
    buffer.add("apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev");
    return buffer;
}

inline ScreenBuffer dashboardBufferForCli() {
    ScreenBuffer buffer;
    buffer.add(ansi::bold + kName + " v" + kVersion + ansi::plain);
    buffer.add(ansi::gray + std::string("流量/IP 优先的服务器防护仪表盘") + ansi::plain);
    buffer.add(ansi::gray + std::string(72, '-') + ansi::plain);

    std::ostringstream deps;
    deps << "权限 " << (isRoot() ? Ui::badge("root", ansi::green) : Ui::badge("非 root", ansi::yellow)) << "  ";
    const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl"};
    for (const auto &tool : tools) {
        deps << tool << " " << Ui::statusBadge(Shell::exists(tool), "可用", "缺失") << "  ";
    }
    buffer.add(deps.str());

    const bool tableEnabled = trafficTableEnabled();
    const auto trafficRows = tableEnabled ? collectTrafficRows() : std::vector<TrafficRow>{};
    const auto totalRows = aggregateTrafficByIp(trafficRows);
    const std::string f2b = serviceState("fail2ban");
    const std::string ufw = ufwState();

    addSection(buffer, "流量 / IP 概览");
    buffer.add(std::string("统计表: ") +
               (tableEnabled ? Ui::badge("已启用", ansi::green) : Ui::badge("未启用", ansi::yellow)) +
               "  nft=inet " + kIpTrafficTable);
    if (!tableEnabled) {
        buffer.add(ansi::yellow + std::string("IP 精细流量统计未启用。进入“流量统计 -> 开启统计”启用。") + ansi::plain);
    }
    addTableLines(buffer, trafficSummaryTable(totalRows, 8, false), tableEnabled ? "暂无匹配流量" : "统计表未启用");

    addSection(buffer, "近期来源态势");
    addTableLines(buffer, ufwHitsTable(collectUfwSourceTop()), "暂无来源日志。可进入“安全中心 -> 分析追查”读取更长时间段。");

    addSection(buffer, "防护组件状态");
    Table services({"组件", "状态", "含义", "建议"}, {18, 12, 30, 18});
    services.add({"fail2ban", normalizedServiceState(f2b), serviceMeaning("fail2ban", f2b), serviceSuggestion("fail2ban", f2b)});
    services.add({"ufw", normalizedServiceState(ufw), serviceMeaning("ufw", ufw), serviceSuggestion("ufw", ufw)});
    addTableLines(buffer, services);

    addSection(buffer, "Fail2ban 默认策略");
    const F2bJailConfig ssh = readJailConfig(kRule1Jail);
    const F2bJailConfig scan = readJailConfig(kRule2Jail);
    Table policies({"策略", "定位", "启用", "阈值", "窗口", "封禁", "动作"}, {24, 16, 10, 8, 9, 9, 16});
    policies.add({kRule1Jail, "SSH 登录",
                  configValueOr(ssh.enabled, normalizedServiceState(f2b) == "运行" ? "随服务" : "待确认"),
                  configValueOr(ssh.maxretry, "5"),
                  configValueOr(ssh.findtime, "3600"),
                  configValueOr(ssh.bantime, "600"),
                  configValueOr(ssh.banaction, "默认")});
    policies.add({kRule2Jail, "UFW 慢扫",
                  configValueOr(scan.enabled, "false"),
                  configValueOr(scan.maxretry, "50"),
                  configValueOr(scan.findtime, "3600"),
                  configValueOr(scan.bantime, "1d"),
                  configValueOr(scan.banaction, "ufw-drop")});
    addTableLines(buffer, policies);
    return buffer;
}

inline void renderDashboard(bool) {
    printScreenBuffer(dashboardBufferForCli());
}

inline void showTrafficRanking() {
    ScreenBuffer buffer;
    addSection(buffer, "流量排行");
    if (!trafficTableEnabled()) {
        buffer.add(ansi::yellow + std::string("统计表未启用。进入“流量统计 -> 开启统计”启用。") + ansi::plain);
        printScreenBuffer(buffer);
        return;
    }
    const auto rows = collectTrafficRows();
    addSection(buffer, "IP 总量");
    addTableLines(buffer, trafficSummaryTable(aggregateTrafficByIp(rows), 30, false), "暂无匹配流量");
    addSection(buffer, "IP + 端口明细");
    addTableLines(buffer, trafficSummaryTable(aggregateTrafficByIpPort(rows), 50, true), "暂无匹配流量");
    printScreenBuffer(buffer);
}

inline void dependencyDoctor() {
    printScreenBuffer(dependencyDoctorBuffer());
}

inline void logSummary() {
    printScreenBuffer(commandListBuffer({
        "tail -n 120 /var/log/fail2ban.log 2>/dev/null || journalctl -u fail2ban --no-pager -n 120 2>/dev/null || true",
        "journalctl -k --no-pager -n 160 2>/dev/null | grep -i 'ufw' || tail -n 160 /var/log/ufw.log 2>/dev/null || true",
    }));
}

inline void exportDiagnosticReport() {
    const std::string out = "/tmp/linux-traffic-guard-" + nowStamp() + ".log";
    std::ostringstream cmd;
    cmd << "{ "
        << "echo '### time'; date; "
        << "echo; echo '### services'; systemctl status fail2ban --no-pager -l 2>/dev/null | sed -n '1,60p'; "
        << "echo; echo '### fail2ban'; fail2ban-client status 2>/dev/null; fail2ban-client status " << kRule1Jail << " 2>/dev/null; fail2ban-client status " << kRule2Jail << " 2>/dev/null; "
        << "echo; echo '### ufw'; ufw status verbose 2>/dev/null; "
        << "echo; echo '### listeners'; ss -tulpen 2>/dev/null | head -160; "
        << "echo; echo '### accounting'; nft list table inet " << kIpTrafficTable << " 2>/dev/null; "
        << "echo; echo '### conntrack'; conntrack -L -o extended 2>/dev/null | head -180; "
        << "echo; echo '### fail2ban log'; tail -n 220 /var/log/fail2ban.log 2>/dev/null; "
        << "echo; echo '### ufw log'; journalctl -k --no-pager -n 220 2>/dev/null | grep -i 'ufw' || true; "
        << "} > " << shellQuote(out);
    ScreenBuffer buffer = commandListBuffer({cmd.str()});
    buffer.add("报告路径: " + out);
    printScreenBuffer(buffer);
}

inline int selfTest() {
    struct CaseResult {
        std::string name;
        bool ok = false;
        std::string detail;
    };
    std::vector<CaseResult> cases;
    const auto check = [&](const std::string &name, bool ok, const std::string &detail = "") {
        cases.push_back({name, ok, detail});
    };

    check("端口列表校验", isSafePortList("22,80,443,10000-10010") &&
                               !isSafePortList("0,70000") && !isSafePortList("80,,443"));
    check("单端口校验", isSafeSinglePort("22") && isSafeSinglePort("65535") &&
                            !isSafeSinglePort("0") && !isSafeSinglePort("80,443") &&
                            !isSafeSinglePort("80-90") && !isSafeSinglePort("abc"));
    check("IP/CIDR 校验", isValidIpOrCidr("192.168.1.1") && isValidIpOrCidr("10.0.0.0/8") &&
                              isValidIpOrCidr("2001:db8::1/64") && isValidIpOrCidr("::1") &&
                              isValidIpOrCidr("::ffff:192.0.2.128") &&
                              !isValidIpOrCidr("999.1.1.1") && !isValidIpOrCidr("::::") &&
                              !isValidIpOrCidr("2001:::1") && !isValidIpOrCidr("abcd") &&
                              !isValidIpOrCidr("1.2.3.4/33") && !isValidIpOrCidr("2001:db8::1/999"));
    check("严格正数校验", isStrictPositiveNumber("0.1") && isStrictPositiveNumber("2") &&
                                !isStrictPositiveNumber("0") && !isStrictPositiveNumber("0.0") &&
                                !isStrictPositiveNumber("00") && !isStrictPositiveNumber("abc"));
    std::time_t parsedDate = 0;
    check("日历日期校验", parseYmdDate("2026-02-28", false, parsedDate) &&
                              parseYmdDate("2024-02-29", true, parsedDate) &&
                              !parseYmdDate("2026-13-01", false, parsedDate) &&
                              !parseYmdDate("2026-02-31", false, parsedDate) &&
                              !parseYmdDate("2025-02-29", false, parsedDate));
    long long seconds = 0;
    check("时间 token 解析", parseTimeToSeconds("10m", seconds) && seconds == 600 &&
                                  parseTimeToSeconds("2h", seconds) && seconds == 7200 &&
                                  !parseTimeToSeconds("abc", seconds));
    check("UTF-8 宽度裁剪", visibleWidth("中文AB") == 6 && visibleWidth(fitLine("中文AB", 5)) <= 5);

    UfwLogEvent event;
    const std::string ufwLine = "2026-05-03T20:01:02 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 DPT=22";
    check("UFW 日志解析", parseUfwLogEvent(ufwLine, event) && event.action == "BLOCK" &&
                              event.src == "1.2.3.4" && event.dpt == "22");
    const std::string badUfwLine = "2026-05-03T20:01:02 host kernel: [UFW BLOCK] SRC=:::: DST=5.6.7.8 DPT=22";
    check("UFW 无效来源过滤", !parseUfwLogEvent(badUfwLine, event));

    const auto traffic = parseTrafficSetOutput("elements = { 1.2.3.4 . 443 counter packets 7 bytes 2048 }", "下载", "IPv4");
    check("nft 统计解析", traffic.size() == 1 && traffic[0].ip == "1.2.3.4" &&
                              traffic[0].port == "443" && traffic[0].packets == 7 && traffic[0].bytes == 2048);
    std::vector<TrafficRow> bidirectionalTraffic = traffic;
    TrafficRow upload;
    upload.ip = "1.2.3.4";
    upload.port = "443";
    upload.direction = "上传";
    upload.family = "IPv4";
    upload.packets = 3;
    upload.bytes = 1024;
    bidirectionalTraffic.push_back(upload);
    const auto byIp = aggregateTrafficByIp(bidirectionalTraffic);
    const auto byIpPort = aggregateTrafficByIpPort(bidirectionalTraffic);
    check("上下行流量同排聚合", byIp.size() == 1 && byIp[0].downloadBytes == 2048 &&
                                  byIp[0].uploadBytes == 1024 && byIp[0].totalBytes() == 3072 &&
                                  byIpPort.size() == 1 && byIpPort[0].port == "443");

    const auto merged = mergeRanges({{10, 20}, {1, 5}, {6, 9}, {30, 40}});
    check("range 合并", merged.size() == 2 && merged[0].first == 1 && merged[0].second == 20 &&
                            rangeCovered(1, 20, merged) && !rangeCovered(1, 30, merged));

    IniConfig ini;
    ini.loadString("[sshd]\nmaxretry = 5\n\n[DEFAULT]\nignoreip = 127.0.0.1\n");
    ini.set("sshd", "bantime", "10m");
    ini.set("ufw-slowscan-global", "enabled", "true");
    const std::string rendered = ini.toString();
    check("IniConfig 内存读写", ini.get("sshd", "maxretry") == "5" &&
                                  rendered.find("bantime = 10m") != std::string::npos &&
                                  rendered.find("[ufw-slowscan-global]") != std::string::npos);
    check("危险命令 helper", fail2banSetIpCommand("sshd", "banip", "1.2.3.4").find("fail2ban-client set 'sshd' banip '1.2.3.4'") != std::string::npos &&
                               ufwDenyFromCommand("1.2.3.4", "case").find("comment 'case'") != std::string::npos &&
                               ufwDeleteDenyFromCommand("1.2.3.4").find("--force delete deny") != std::string::npos);

#if LTG_HAS_SQLITE
    check("SQLite 编译模式", true, "LTG_HAS_SQLITE=1");
#else
    check("SQLite fallback 编译模式", true, "LTG_HAS_SQLITE=0");
#endif

    int failed = 0;
    for (const auto &test : cases) {
        if (!test.ok) {
            ++failed;
        }
        std::cout << (test.ok ? colorIf("[PASS] ", ansi::green) : colorIf("[FAIL] ", ansi::red))
                  << test.name;
        if (!test.detail.empty()) {
            std::cout << "  " << colorIf(test.detail, ansi::gray);
        }
        std::cout << "\n";
    }
    std::cout << "\nself-test: " << (cases.size() - static_cast<std::size_t>(failed)) << "/" << cases.size() << " passed\n";
    return failed == 0 ? 0 : 1;
}

inline int cliUfwAnalyze(const std::string &period) {
    const std::time_t end = std::time(nullptr);
    std::time_t start = end - 86400;
    std::string title = "最近24小时";
    if (period == "24h" || period == "1d") {
        start = end - 86400;
        title = "最近24小时";
    } else if (period == "7d") {
        start = end - 7 * 86400;
        title = "最近7天";
    } else if (period == "28d") {
        start = end - 28 * 86400;
        title = "最近28天";
    } else {
        std::cerr << "无效时间段。支持: 24h, 7d, 28d\n";
        return 1;
    }
    const UfwAnalysisReport report = analyzeUfwEvents(title, start, end, false);
    ScreenBuffer buffer;
    addUfwAnalysisToBuffer(buffer, report);
    printScreenBuffer(buffer);
    return 0;
}

inline int cliF2bAudit() {
    const F2bJailConfig cfg = readJailConfig(kRule2Jail);
    long long seconds = 3600;
    parseTimeToSeconds(configValueOr(cfg.findtime, "3600"), seconds);
    const std::time_t end = std::time(nullptr);
    const std::time_t start = end - static_cast<std::time_t>(seconds);
    const auto rows = buildDualAuditRows(start, end, 40);
    std::cout << "双日志核验: " << dateTimeStamp(start) << " ~ " << dateTimeStamp(end) << "\n";
    std::cout << "规则2阈值: " << configValueOr(cfg.maxretry, "50") << " / " << configValueOr(cfg.findtime, "3600") << "\n";
    Table table({"IP", "UFW命中", "规则1", "规则2", "窗口Ban", "结论"}, {34, 10, 8, 8, 10, 28});
    for (const auto &row : rows) {
        table.add({row.ip, std::to_string(row.ufwHits), row.rule1Banned ? "是" : "否",
                   row.rule2Banned ? "是" : "否", row.banLogged ? "是" : "否", row.conclusion});
    }
    table.print("当前窗口无 UFW BLOCK/AUDIT 命中");
    return 0;
}

inline void usage(const char *argv0) {
    std::cout << kName << " " << kVersion << "\n";
    std::cout << "Ubuntu 服务器流量与防护运维工具，单头文件 C++17，纯 ANSI TUI。\n\n";
    std::cout << "用法: " << argv0 << " [选项]\n\n";
    std::cout << "说明:\n";
    std::cout << "  除 --help / --version / --self-test 外，本工具必须以 root 权限运行。\n";
    std::cout << "  交互模式会进入全屏 TUI；命令行参数模式输出普通文本，方便脚本/日志收集。\n";
    std::cout << "  会调用系统工具 nft/ufw/fail2ban-client/journalctl/ss/conntrack，不依赖 .sh/.py。\n\n";
    std::cout << "选项:\n";
    std::cout << "  --status          打印仪表盘\n";
    std::cout << "  --ip-traffic      查看 IP 精细流量排行\n";
    std::cout << "  --doctor          检查依赖\n";
    std::cout << "  --audit           查看日志摘要\n";
    std::cout << "  --f2b-audit       防护链路双日志核验\n";
    std::cout << "  --ufw-analyze P   分析 UFW 日志，P=24h|7d|28d\n";
    std::cout << "  --export-report   导出诊断报告\n";
    std::cout << "  --self-test       运行非 root 纯逻辑自测\n";
    std::cout << "  --version         显示版本\n";
    std::cout << "  --help            显示帮助\n";
    std::cout << "\nUbuntu 依赖:\n";
    std::cout << "  sudo apt update\n";
    std::cout << "  sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep\n";
    std::cout << "  # 仓库目录中也可执行: make deps\n";
    std::cout << "\n编译:\n";
    std::cout << "  make\n";
    std::cout << "  # 或: g++ -std=c++17 -O2 -Wall -Wextra -x c++ linux_traffic_guard.hpp -o ltg -lsqlite3\n";
    std::cout << "\n安装/卸载:\n";
    std::cout << "  make bootstrap       # 首次安装: 依赖 + 编译 + 安装\n";
    std::cout << "  make update          # 后续更新: git pull + 编译 + 安装\n";
    std::cout << "  sudo make install\n";
    std::cout << "  sudo make uninstall\n";
}

inline int requireRootOrExit() {
    if (isRoot()) {
        return 0;
    }
    std::cerr << colorIf("Linux 流量守卫需要 root 权限运行。请使用 sudo 重新执行。", ansi::yellow, STDERR_FILENO) << "\n";
    return 77;
}

inline int appMain(int argc, char **argv) {
    std::ios::sync_with_stdio(false);

    if (argc > 1) {
        pauseEnabled() = false;
        const std::string arg = argv[1];
        if (arg == "--version") {
            std::cout << kName << " " << kVersion << "\n";
            return 0;
        }
        if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            return 0;
        }
        if (arg == "--self-test") {
            return selfTest();
        }
        const int rootCheck = requireRootOrExit();
        if (rootCheck != 0) {
            return rootCheck;
        }
        if (arg == "--status") {
            renderDashboard(false);
            return 0;
        }
        if (arg == "--ip-traffic") {
            showTrafficRanking();
            return 0;
        }
        if (arg == "--doctor" || arg == "--check-deps") {
            dependencyDoctor();
            return 0;
        }
        if (arg == "--audit") {
            logSummary();
            return 0;
        }
        if (arg == "--f2b-audit") {
            return cliF2bAudit();
        }
        if (arg == "--ufw-analyze") {
            if (argc < 3) {
                std::cerr << "--ufw-analyze 需要参数: 24h, 7d, 28d\n";
                return 1;
            }
            return cliUfwAnalyze(argv[2]);
        }
        if (arg == "--export-report") {
            exportDiagnosticReport();
            return 0;
        }
        usage(argv[0]);
        return 1;
    }

    const int rootCheck = requireRootOrExit();
    if (rootCheck != 0) {
        return rootCheck;
    }
    TerminalGuard terminal;
    TuiApp app;
    app.run();
    return 0;
}

} // namespace linux_traffic_guard

#ifndef LINUX_TRAFFIC_GUARD_NO_MAIN
int main(int argc, char **argv) {
    return linux_traffic_guard::appMain(argc, argv);
}
#endif

#endif // LINUX_TRAFFIC_GUARD_HPP
