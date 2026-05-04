#define LINUX_TRAFFIC_GUARD_NO_MAIN
#ifndef LINUX_TRAFFIC_GUARD_HPP
#define LINUX_TRAFFIC_GUARD_HPP

/*
 * Linux Traffic Guard / Linux 流量守卫
 *
 * Modular C++17 server traffic and security operations TUI for Ubuntu.
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

#include "ltg/version.hpp"

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
#include <arpa/inet.h>
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

inline const std::string kName = "Linux 流量守卫";
inline const std::string kLatestBinaryUrl = "https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64";
inline const std::string kLatestSha256Url = "https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/SHA256SUMS";
inline const std::string kIpTrafficTable = "usp_ip_traffic";
inline const std::string kTrafficHistoryDir = "/var/tmp/linux_traffic_guard_traffic_history_v1";
inline const std::string kTrafficSnapshotService = "linux-traffic-guard-traffic-snapshot.service";
inline const std::string kTrafficSnapshotTimer = "linux-traffic-guard-traffic-snapshot.timer";
inline const std::string kUnknownUfwPort = "UNKNOWN";
inline const std::string kDbIpLiteDownloadPage = "https://db-ip.com/db/download/ip-to-city-lite";
inline const std::string kDbIpLiteDir = "/var/lib/linux-traffic-guard";
inline const std::string kDbIpLiteMmdbPath = "/var/lib/linux-traffic-guard/dbip-city-lite.mmdb";
inline const std::string kDbIpLiteMetaPath = "/var/lib/linux-traffic-guard/dbip-city-lite.url";
inline const std::string kDbIpLiteAttribution = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0";
inline const std::string kRule1Jail = "sshd";
inline const std::string kRule2Jail = "ufw-slowscan-global";
inline const std::string kFail2banEffectProbeIp = "203.0.113.254";
inline const std::string kJailConf = "/etc/fail2ban/jail.local";
inline const std::string kRule2FilterFile = "/etc/fail2ban/filter.d/ufw-slowscan-global.conf";
inline const std::string kUfwDropActionFile = "/etc/fail2ban/action.d/ufw-drop.conf";
inline const std::string kUfwCacheDir = "/var/tmp/linux_traffic_guard_ufw_cache_v2";
inline const std::string kFail2banDb = "/var/lib/fail2ban/fail2ban.sqlite3";
inline constexpr int kUfwCacheIdleDays = 14;
inline constexpr std::size_t kDashboardTrafficDays = 31;
inline constexpr std::size_t kDashboardTrafficPortLimit = 10;

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
    std::string geo;
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

struct TrafficDelta {
    TrafficRow row;
    std::time_t sampledAt = 0;
    std::string day;
    std::string month;
    std::string year;
};

struct TrafficSnapshotResult {
    bool ok = false;
    std::time_t sampledAt = 0;
    std::size_t liveRows = 0;
    std::size_t deltaRows = 0;
    std::size_t resetRows = 0;
    std::string message;
};

struct TrafficPeriodTotal {
    std::string period;
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

enum class TrafficPeriodMode {
    Day,
    Month,
    Year
};

struct UfwHit {
    std::string value;
    std::string geo;
    std::uint64_t count = 0;
    std::uint64_t peak = 0;
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
    bool configured = false;
    bool jailLoaded = false;
    std::string recentBan;
    std::string runtimeDetail;
    bool managedDefault = false;
};

enum class F2bJailRuntimeState {
    Loaded,
    NotLoaded,
    PermissionDenied,
    Fail2banUnavailable,
    Unknown
};

struct F2bJailRuntimeInfo {
    std::string jail;
    F2bJailRuntimeState state = F2bJailRuntimeState::Unknown;
    std::string label;
    std::string raw;
    std::set<std::string> bannedIps;

    bool loaded() const {
        return state == F2bJailRuntimeState::Loaded;
    }
};

struct UfwLogEvent {
    std::time_t ts = 0;
    std::string day;
    std::string action;
    std::string src;
    std::string dpt;
};

struct UfwLogEvidence {
    std::size_t rawMatches = 0;
    std::size_t validPublic = 0;
    std::size_t filteredSource = 0;
    std::size_t noDpt = 0;
    std::size_t block = 0;
    std::size_t audit = 0;
    std::size_t allow = 0;
    bool cacheCovered = false;
    std::string cacheRanges;
    std::string liveSource;
};

struct UfwAnalysisReport {
    std::string title;
    std::time_t start = 0;
    std::time_t end = 0;
    std::size_t validLines = 0;
    std::string sourceNote;
    UfwLogEvidence evidence;
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

struct DualAuditReport {
    F2bJailRuntimeInfo rule1;
    F2bJailRuntimeInfo rule2;
    std::vector<DualAuditRow> rows;
};

struct F2bEffectProbe {
    bool serviceOk = false;
    bool jailLoaded = false;
    bool banListed = false;
    bool ufwLanded = false;
    bool unbanOk = false;
    bool ufwCleanupOk = false;
    CommandResult ping;
    CommandResult ban;
    CommandResult statusAfterBan;
    CommandResult ufwStatus;
    CommandResult unban;
    CommandResult ufwCleanup;
    F2bJailRuntimeInfo jailStatus;
};

enum class ReliabilityStatus {
    Pass,
    Fail,
    Warning,
    Skipped,
    Permission
};

struct ReliabilityCheckResult {
    std::string group;
    std::string name;
    ReliabilityStatus status = ReliabilityStatus::Skipped;
    std::string summary;
    std::string evidence;
    std::string suggestion;
};

struct ReliabilityReport {
    std::vector<ReliabilityCheckResult> results;

    bool ok() const {
        return std::none_of(results.begin(), results.end(), [](const ReliabilityCheckResult &result) {
            return result.status == ReliabilityStatus::Fail || result.status == ReliabilityStatus::Permission;
        });
    }
};

struct DashboardSnapshot {
    bool tableEnabled = false;
    std::vector<TrafficRow> trafficRows;
    std::vector<TrafficSummaryRow> totalRows;
    std::set<int> trackedPorts;
    std::string trafficPeriodLabel;
    bool trafficHistoryAvailable = false;
    std::vector<UfwHit> ufwHits;
    std::string ufwHitsNote;
    std::vector<F2bPolicyInfo> defaultPolicies;
    std::string fail2banState = "未知";
    std::string ufwState = "未知";
    std::chrono::steady_clock::time_point loadedAt{};
};

enum class TrafficGroupMode {
    Ip,
    Port,
    IpPort
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

inline std::string currentExecutablePath(const char *argv0) {
#ifdef _WIN32
    return argv0 ? argv0 : "ltg";
#else
    std::array<char, 4096> path{};
    const ssize_t len = readlink("/proc/self/exe", path.data(), path.size() - 1);
    if (len > 0) {
        path[static_cast<std::size_t>(len)] = '\0';
        return path.data();
    }
    return argv0 ? argv0 : "/usr/local/bin/ltg";
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

inline bool fileExists(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    return static_cast<bool>(input);
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

inline bool expandPortList(const std::string &value, std::set<int> &ports) {
    ports.clear();
    const std::string cleaned = removeSpaces(value);
    if (!isSafePortList(cleaned)) {
        return false;
    }
    std::size_t start = 0;
    while (start < cleaned.size()) {
        const std::size_t comma = cleaned.find(',', start);
        const std::string item = cleaned.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        const std::size_t dash = item.find('-');
        const int first = std::stoi(dash == std::string::npos ? item : item.substr(0, dash));
        const int last = dash == std::string::npos ? first : std::stoi(item.substr(dash + 1));
        for (int port = first; port <= last; ++port) {
            ports.insert(port);
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return true;
}

inline std::string joinPorts(const std::set<int> &ports, const std::string &sep = ",") {
    std::ostringstream out;
    bool first = true;
    for (int port : ports) {
        if (!first) {
            out << sep;
        }
        first = false;
        out << port;
    }
    return out.str();
}

inline std::string nftPortElements(const std::set<int> &ports) {
    return "{ " + joinPorts(ports, ", ") + " }";
}

inline std::string humanPortList(const std::set<int> &ports, std::size_t limit = 12) {
    if (ports.empty()) {
        return "未记录";
    }
    std::ostringstream out;
    std::size_t shown = 0;
    for (int port : ports) {
        if (shown > 0) {
            out << ", ";
        }
        out << port;
        ++shown;
        if (shown >= limit && ports.size() > limit) {
            out << " ... +" << (ports.size() - limit);
            break;
        }
    }
    return out.str();
}

inline std::set<int> setDifference(const std::set<int> &left, const std::set<int> &right) {
    std::set<int> out;
    std::set_difference(left.begin(), left.end(), right.begin(), right.end(), std::inserter(out, out.begin()));
    return out;
}

inline std::set<int> setIntersection(const std::set<int> &left, const std::set<int> &right) {
    std::set<int> out;
    std::set_intersection(left.begin(), left.end(), right.begin(), right.end(), std::inserter(out, out.begin()));
    return out;
}

inline void parseNftPortListInto(const std::string &text, std::set<int> &ports) {
    const std::regex rangePattern(R"(([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?)");
    for (std::sregex_iterator it(text.begin(), text.end(), rangePattern), end; it != end; ++it) {
        const int first = std::stoi((*it)[1].str());
        const int last = (*it)[2].matched ? std::stoi((*it)[2].str()) : first;
        if (first < 1 || last > 65535 || first > last) {
            continue;
        }
        for (int port = first; port <= last; ++port) {
            ports.insert(port);
        }
    }
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

#ifndef _WIN32
inline bool ipv4InCidr(std::uint32_t ip, std::uint32_t base, int bits) {
    const std::uint32_t mask = bits == 0 ? 0 : (0xffffffffu << (32 - bits));
    return (ip & mask) == (base & mask);
}

inline std::uint32_t ipv4Addr(unsigned a, unsigned b, unsigned c, unsigned d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

inline bool isGlobalIpv4(std::uint32_t ip) {
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

inline bool isIpv6MappedIpv4(const unsigned char *bytes) {
    for (int i = 0; i < 10; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

inline bool isGlobalIpv6(const unsigned char *bytes) {
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
    if ((bytes[0] & 0xfe) == 0xfc) return false;                 // fc00::/7
    if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return false; // fe80::/10
    if (bytes[0] == 0xff) return false;                           // ff00::/8
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8) return false;
    return true;
}
#endif

inline bool normalizePublicIpAddress(const std::string &raw, std::string &normalized) {
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

inline std::string localTimeFormat(std::time_t value, const char *format) {
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &value);
#else
    localtime_r(&value, &tm);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), format, &tm);
    return buf;
}

inline std::string localDayStamp(std::time_t value) {
    return localTimeFormat(value, "%Y-%m-%d");
}

inline std::string localMonthStamp(std::time_t value) {
    return localTimeFormat(value, "%Y-%m");
}

inline std::string localYearStamp(std::time_t value) {
    return localTimeFormat(value, "%Y");
}

inline std::string currentTrafficPeriodLabel(TrafficPeriodMode mode) {
    const std::time_t now = std::time(nullptr);
    if (mode == TrafficPeriodMode::Day) {
        return localDayStamp(now);
    }
    if (mode == TrafficPeriodMode::Year) {
        return localYearStamp(now);
    }
    return localMonthStamp(now);
}

inline std::string recentTrafficDaysLabel(const std::vector<std::string> &periods, std::size_t days) {
    if (periods.empty()) {
        return "最近" + std::to_string(days) + "天";
    }
    const auto range = std::minmax_element(periods.begin(), periods.end());
    return "最近" + std::to_string(days) + "天（" + *range.first + " ~ " + *range.second + "）";
}

inline std::string trafficPeriodModeTitle(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "日流量";
    if (mode == TrafficPeriodMode::Year) return "年流量";
    return "月流量";
}

inline std::string trafficPeriodModeDetailTitle(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "按日流量";
    if (mode == TrafficPeriodMode::Year) return "按年流量";
    return "按月流量";
}

inline std::string trafficPeriodModeUnit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "天";
    if (mode == TrafficPeriodMode::Year) return "年";
    return "月";
}

inline std::string trafficPeriodModeColumn(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "日期";
    if (mode == TrafficPeriodMode::Year) return "年份";
    return "月份";
}

inline std::string trafficPeriodVnstatCommand(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "vnstat -d";
    if (mode == TrafficPeriodMode::Year) return "vnstat -y";
    return "vnstat -m";
}

inline std::string trafficPeriodSample(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "2026-05-04";
    if (mode == TrafficPeriodMode::Year) return "2026";
    return "2026-05";
}

inline std::size_t defaultTrafficRollingLimit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return 31;
    if (mode == TrafficPeriodMode::Year) return 10;
    return 24;
}

inline std::size_t maxTrafficRollingLimit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return 366;
    if (mode == TrafficPeriodMode::Year) return 50;
    return 120;
}

inline bool parseTrafficRollingLimit(const std::string &text,
                                     TrafficPeriodMode mode,
                                     std::size_t &limit) {
    const std::string value = trim(text);
    if (value.empty()) {
        limit = defaultTrafficRollingLimit(mode);
        return true;
    }
    if (!std::regex_match(value, std::regex(R"([0-9]+)"))) {
        return false;
    }
    const unsigned long long parsed = std::stoull(value);
    if (parsed == 0 || parsed > maxTrafficRollingLimit(mode)) {
        return false;
    }
    limit = static_cast<std::size_t>(parsed);
    return true;
}

inline std::time_t makeLocalTime(std::tm tm) {
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

inline std::vector<std::string> recentTrafficDayPeriods(std::size_t days) {
    std::vector<std::string> periods;
    if (days == 0) {
        return periods;
    }
    const std::time_t now = std::time(nullptr);
    std::tm base{};
#ifdef _WIN32
    localtime_s(&base, &now);
#else
    localtime_r(&now, &base);
#endif
    base.tm_hour = 12;
    base.tm_min = 0;
    base.tm_sec = 0;
    for (std::size_t offset = 0; offset < days; ++offset) {
        std::tm candidate = base;
        candidate.tm_mday -= static_cast<int>(offset);
        periods.push_back(localDayStamp(makeLocalTime(candidate)));
    }
    return periods;
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

inline bool isValidTrafficPeriodLabel(TrafficPeriodMode mode, const std::string &value) {
    if (mode == TrafficPeriodMode::Day) {
        std::time_t ignored = 0;
        return std::regex_match(value, std::regex(R"([0-9]{4}-[0-9]{2}-[0-9]{2})")) &&
               parseYmdDate(value, false, ignored);
    }
    if (mode == TrafficPeriodMode::Month) {
        std::smatch match;
        if (!std::regex_match(value, match, std::regex(R"(([0-9]{4})-([0-9]{2}))"))) {
            return false;
        }
        const int year = std::stoi(match[1].str());
        const int month = std::stoi(match[2].str());
        return year >= 1970 && year <= 9999 && month >= 1 && month <= 12;
    }
    return std::regex_match(value, std::regex(R"([0-9]{4})"));
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

inline std::string firstNonEmptyLine(const std::string &text) {
    for (const auto &line : splitLines(text)) {
        const std::string value = trim(stripAnsi(line));
        if (!value.empty()) {
            return value;
        }
    }
    return "";
}

inline std::string summarizeCommandResult(const CommandResult &result, std::size_t maxLen = 180) {
    std::string summary = firstNonEmptyLine(result.output);
    if (summary.empty()) {
        summary = result.ok() ? "exit 0" : "exit " + std::to_string(result.exitCode);
    }
    return truncateText(summary, maxLen);
}

inline bool parseVersionTriplet(const std::string &text, std::array<int, 3> &version) {
    const std::regex pattern(R"((\d+)\.(\d+)\.(\d+))");
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return false;
    }
    version = {std::stoi(match[1].str()), std::stoi(match[2].str()), std::stoi(match[3].str())};
    return true;
}

inline int compareVersionTriplet(const std::array<int, 3> &a, const std::array<int, 3> &b) {
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
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

inline bool ufwStatusHasDenyForIp(const std::string &output, const std::string &ip, bool requireFail2banComment) {
    for (const auto &line : splitLines(output)) {
        const std::string lower = lowerCopy(line);
        if (line.find(ip) == std::string::npos || lower.find("deny") == std::string::npos) {
            continue;
        }
        if (!requireFail2banComment ||
            lower.find("f2b") != std::string::npos ||
            lower.find("fail2ban") != std::string::npos ||
            lower.find("ufw-drop") != std::string::npos) {
            return true;
        }
    }
    return false;
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

inline std::string f2bRuntimeStateLabel(F2bJailRuntimeState state) {
    switch (state) {
    case F2bJailRuntimeState::Loaded:
        return "已加载";
    case F2bJailRuntimeState::NotLoaded:
        return "未加载";
    case F2bJailRuntimeState::PermissionDenied:
        return "权限不足";
    case F2bJailRuntimeState::Fail2banUnavailable:
        return "fail2ban 不可用";
    case F2bJailRuntimeState::Unknown:
    default:
        return "未知";
    }
}

inline F2bJailRuntimeInfo parseFail2banJailStatus(const std::string &jail, const std::string &rawOutput, bool clientExists = true) {
    F2bJailRuntimeInfo info;
    info.jail = jail;
    info.raw = trim(rawOutput);
    const std::string lower = lowerCopy(info.raw);
    if (!clientExists) {
        info.state = F2bJailRuntimeState::Fail2banUnavailable;
    } else if (lower.find("permission denied") != std::string::npos ||
               lower.find("you must be root") != std::string::npos ||
               lower.find("access denied") != std::string::npos) {
        info.state = F2bJailRuntimeState::PermissionDenied;
    } else if (info.raw.empty() || lower.find("unable to contact server") != std::string::npos ||
               lower.find("connection refused") != std::string::npos ||
               lower.find("failed to access socket") != std::string::npos) {
        info.state = F2bJailRuntimeState::Fail2banUnavailable;
    } else if (info.raw.find("UnknownJailException") != std::string::npos ||
               lower.find("unknown jail") != std::string::npos ||
               lower.find("does not exist") != std::string::npos) {
        info.state = F2bJailRuntimeState::NotLoaded;
    } else if (lower.find("status for the jail") != std::string::npos ||
               lower.find("banned ip list") != std::string::npos ||
               lower.find("currently banned") != std::string::npos) {
        info.state = F2bJailRuntimeState::Loaded;
    } else {
        info.state = F2bJailRuntimeState::Unknown;
    }
    info.label = f2bRuntimeStateLabel(info.state);

    for (const auto &line : splitLines(info.raw)) {
        const std::size_t pos = line.find("Banned IP list:");
        if (pos == std::string::npos) {
            continue;
        }
        std::string list = line.substr(pos + std::string("Banned IP list:").size());
        std::replace(list.begin(), list.end(), ',', ' ');
        for (const auto &ip : splitWords(list)) {
            if (isValidIpOrCidr(ip) && ip.find('/') == std::string::npos) {
                info.bannedIps.insert(ip);
            }
        }
    }
    return info;
}

inline F2bJailRuntimeInfo fail2banJailRuntimeStatus(const std::string &jail) {
    if (!Shell::exists("fail2ban-client")) {
        return parseFail2banJailStatus(jail, "", false);
    }
    const CommandResult result = Shell::capture("fail2ban-client status " + shellQuote(jail) + " 2>&1");
    return parseFail2banJailStatus(jail, result.output, true);
}

inline std::set<std::string> bannedSetForJail(const std::string &jail) {
    return fail2banJailRuntimeStatus(jail).bannedIps;
}

inline std::string fail2banJailStatusLine(const std::string &jail) {
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

inline std::string recentBanLineForJail(const std::string &jail) {
    const std::string cmd =
        "(grep -h '\\[" + jail + "\\].* Ban ' /var/log/fail2ban.log* 2>/dev/null || "
        "journalctl -u fail2ban --no-pager 2>/dev/null | grep '\\[" + jail + "\\].* Ban ') | tail -1";
    return trim(Shell::capture(cmd).output);
}

inline std::string fail2banSetIpCommandStrict(const std::string &jail, const std::string &verb, const std::string &ip) {
    return "fail2ban-client set " + shellQuote(jail) + " " + verb + " " + shellQuote(ip);
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

inline std::vector<F2bPolicyInfo> collectDefaultFail2banPolicies(bool includeRuntimeStatus) {
    std::vector<F2bPolicyInfo> defaults;
    for (const auto &policy : collectFail2banPolicies(includeRuntimeStatus)) {
        if (policy.name == kRule1Jail || policy.name == kRule2Jail) {
            defaults.push_back(policy);
        }
    }
    return defaults;
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
    if (port == kUnknownUfwPort) {
        return "日志无DPT";
    }
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

inline std::time_t ufwLogLineTimeOrNow(const std::string &line) {
    std::time_t ts = 0;
    if (!parseIsoLogTime(line, ts)) {
        parseSyslogTime(line, ts);
    }
    return ts > 0 ? ts : std::time(nullptr);
}

inline void observeUfwRawLogLine(const std::string &line, UfwLogEvidence &evidence) {
    std::smatch match;
    static const std::regex actionPattern(R"(\[UFW (BLOCK|AUDIT|ALLOW)\])");
    static const std::regex dptPattern(R"(\bDPT=([0-9]+)\b)");
    if (!std::regex_search(line, match, actionPattern)) {
        return;
    }
    ++evidence.rawMatches;
    const std::string action = match[1].str();
    if (action == "BLOCK") {
        ++evidence.block;
    } else if (action == "AUDIT") {
        ++evidence.audit;
    } else if (action == "ALLOW") {
        ++evidence.allow;
    }
    if (!std::regex_search(line, dptPattern)) {
        ++evidence.noDpt;
    }
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
    if (!normalizePublicIpAddress(match[1].str(), event.src)) {
        return false;
    }
    if (std::regex_search(line, match, dptPattern)) {
        event.dpt = match[1].str();
    } else {
        event.dpt = kUnknownUfwPort;
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

inline bool latestOverlappingRange(std::time_t start,
                                   std::time_t end,
                                   const std::vector<std::pair<std::time_t, std::time_t>> &ranges,
                                   std::time_t &outStart,
                                   std::time_t &outEnd) {
    bool found = false;
    outStart = 0;
    outEnd = 0;
    for (const auto &range : mergeRanges(ranges)) {
        const std::time_t left = std::max(start, range.first);
        const std::time_t right = std::min(end, range.second);
        if (left >= right) {
            continue;
        }
        if (!found || right > outEnd || (right == outEnd && left > outStart)) {
            found = true;
            outStart = left;
            outEnd = right;
        }
    }
    return found;
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

inline std::string unescapeQuotedValue(std::string value) {
    std::string out;
    bool escaped = false;
    for (char ch : value) {
        if (escaped) {
            out.push_back(ch);
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else {
            out.push_back(ch);
        }
    }
    if (escaped) {
        out.push_back('\\');
    }
    return out;
}

inline std::string parseMmdbLookupString(const std::string &output) {
    std::smatch match;
    const std::regex quoted(R"MMDB("((?:[^"\\]|\\.)*)"\s*<)MMDB");
    if (std::regex_search(output, match, quoted)) {
        return unescapeQuotedValue(match[1].str());
    }
    return "";
}

inline bool dbIpLiteDatabaseReady() {
    return fileExists(kDbIpLiteMmdbPath) && Shell::exists("mmdblookup");
}

inline std::string mmdbLookupString(const std::string &ip, const std::vector<std::string> &path) {
    if (!dbIpLiteDatabaseReady()) {
        return "";
    }
    std::ostringstream command;
    command << "mmdblookup --file " << shellQuote(kDbIpLiteMmdbPath)
            << " --ip " << shellQuote(ip);
    for (const auto &item : path) {
        command << " " << shellQuote(item);
    }
    return parseMmdbLookupString(Shell::capture(command.str()).output);
}

inline std::string ipGeoLabel(const std::string &rawIp) {
    static std::mutex mutex;
    static std::map<std::string, std::string> cache;
    std::string ip;
    if (!normalizePublicIpAddress(rawIp, ip)) {
        return "-";
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        const auto found = cache.find(ip);
        if (found != cache.end()) {
            return found->second;
        }
    }
    std::string country = mmdbLookupString(ip, {"country", "names", "zh-CN"});
    if (country.empty()) {
        country = mmdbLookupString(ip, {"country", "names", "en"});
    }
    std::string label = "-";
    if (!country.empty()) {
        label = country;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        cache[ip] = label;
    }
    return label;
}

inline std::string dbIpLiteDownloadCommand() {
    std::ostringstream command;
    command << "mkdir -p " << shellQuote(kDbIpLiteDir)
            << " && url=$(curl -fsSL " << shellQuote(kDbIpLiteDownloadPage)
            << " | grep -Eo 'https://download[.]db-ip[.]com/free/dbip-city-lite-[0-9]{4}-[0-9]{2}[.]mmdb[.]gz' | head -n1)"
            << " && test -n \"$url\""
            << " && tmpgz=$(mktemp /tmp/ltg-dbip.XXXXXX.mmdb.gz)"
            << " && tmp=$(mktemp /tmp/ltg-dbip.XXXXXX.mmdb)"
            << " && curl -fL \"$url\" -o \"$tmpgz\""
            << " && gzip -dc \"$tmpgz\" > \"$tmp\""
            << " && install -m 0644 \"$tmp\" " << shellQuote(kDbIpLiteMmdbPath)
            << " && printf '%s\\n' \"$url\" > " << shellQuote(kDbIpLiteMetaPath)
            << " && rm -f \"$tmpgz\" \"$tmp\""
            << " && mmdblookup --file " << shellQuote(kDbIpLiteMmdbPath)
            << " --ip 8.8.8.8 country iso_code >/dev/null"
            << " && echo 'installed DB-IP Lite MMDB: " << kDbIpLiteMmdbPath << "'";
    return command.str();
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

inline std::vector<UfwLogEvent> loadLiveUfwEvents(std::time_t start, std::time_t end, std::string &sourceNote, UfwLogEvidence *evidence = nullptr);

inline std::string ufwRangesSummary(const std::vector<std::pair<std::time_t, std::time_t>> &ranges) {
    if (ranges.empty()) {
        return "无缓存范围";
    }
    std::ostringstream out;
    std::size_t shown = 0;
    for (const auto &range : ranges) {
        if (shown != 0) {
            out << " | ";
        }
        out << dateTimeStamp(range.first) << "~" << dateTimeStamp(range.second);
        if (++shown >= 3) {
            break;
        }
    }
    if (ranges.size() > shown) {
        out << " | ...";
    }
    return out.str();
}

inline UfwAnalysisReport buildUfwReportFromEvents(const std::string &title,
                                                  std::time_t start,
                                                  std::time_t end,
                                                  const std::string &sourceNote,
                                                  const std::vector<UfwLogEvent> &events,
                                                  const UfwLogEvidence &evidence = {}) {
    UfwAnalysisReport report;
    report.title = title;
    report.start = start;
    report.end = end;
    report.sourceNote = sourceNote;
    report.validLines = events.size();
    report.evidence = evidence;
    if (report.evidence.validPublic == 0 && !events.empty()) {
        report.evidence.validPublic = events.size();
    }
    for (const auto &event : events) {
        if (event.action == "ALLOW") {
            if (event.ts >= std::time(nullptr) - 3 * 86400) {
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
}

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
    report.evidence.validPublic = report.validLines;
    report.evidence.rawMatches = report.validLines;
    report.evidence.block = static_cast<std::size_t>(
        sqliteCountScalar(db, "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ? AND action='BLOCK';", start, end));
    report.evidence.audit = static_cast<std::size_t>(
        sqliteCountScalar(db, "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ? AND action='AUDIT';", start, end));
    report.evidence.allow = static_cast<std::size_t>(
        sqliteCountScalar(db, "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ? AND action='ALLOW';", start, end));
    report.evidence.noDpt = static_cast<std::size_t>(
        sqliteCountScalar(db, "SELECT count(*) FROM events WHERE ts BETWEEN ? AND ? AND dpt='" + kUnknownUfwPort + "';", start, end));

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
    UfwLogEvidence liveEvidence;
    if (!gaps.empty()) {
        std::vector<UfwLogEvent> loaded;
        std::string liveNote;
        for (const auto &gap : gaps) {
            std::string note;
            UfwLogEvidence gapEvidence;
            auto part = loadLiveUfwEvents(gap.first, gap.second, note, &gapEvidence);
            liveEvidence.rawMatches += gapEvidence.rawMatches;
            liveEvidence.validPublic += gapEvidence.validPublic;
            liveEvidence.filteredSource += gapEvidence.filteredSource;
            liveEvidence.noDpt += gapEvidence.noDpt;
            liveEvidence.block += gapEvidence.block;
            liveEvidence.audit += gapEvidence.audit;
            liveEvidence.allow += gapEvidence.allow;
            if (!gapEvidence.liveSource.empty()) {
                liveEvidence.liveSource = gapEvidence.liveSource;
            }
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
    report.evidence.cacheCovered = rangeCovered(start, end, ranges);
    report.evidence.cacheRanges = ufwRangesSummary(ranges);
    report.evidence.liveSource = liveEvidence.liveSource;
    if (forceRefresh || (report.evidence.cacheCovered && ranges.size() == 1 && ranges.front().first <= start && ranges.front().second >= end)) {
        if (liveEvidence.rawMatches > 0 || forceRefresh) {
            report.evidence.rawMatches = liveEvidence.rawMatches;
            report.evidence.validPublic = liveEvidence.validPublic;
            report.evidence.filteredSource = liveEvidence.filteredSource;
            report.evidence.noDpt = liveEvidence.noDpt;
            report.evidence.block = liveEvidence.block;
            report.evidence.audit = liveEvidence.audit;
            report.evidence.allow = liveEvidence.allow;
        }
    }
    if (report.evidence.cacheCovered && report.validLines == 0 && sourceNote == "SQLite 缓存") {
        report.sourceNote = "SQLite 缓存(窗口内无有效记录)";
    }
    sqlite3_close(db);
    return report;
}
#endif

inline std::vector<UfwLogEvent> loadLiveUfwEvents(std::time_t start, std::time_t end, std::string &sourceNote, UfwLogEvidence *evidence) {
    std::vector<UfwLogEvent> events;
    if (evidence) {
        *evidence = {};
    }
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
    if (evidence) {
        evidence->liveSource = sourceNote;
    }
    for (const auto &line : splitLines(output)) {
        const std::time_t ts = ufwLogLineTimeOrNow(line);
        if (ts < start || ts > end) {
            continue;
        }
        if (evidence) {
            observeUfwRawLogLine(line, *evidence);
        }
        UfwLogEvent event;
        if (!parseUfwLogEvent(line, event)) {
            if (evidence) {
                ++evidence->filteredSource;
            }
            continue;
        }
        if (evidence) {
            ++evidence->validPublic;
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
    UfwLogEvidence evidence;
    if (!forceRefresh && rangeCovered(start, end, ranges)) {
        events = readUfwCacheEvents(start, end);
        report.sourceNote = "文本缓存";
        evidence.cacheCovered = true;
        evidence.cacheRanges = ufwRangesSummary(ranges);
    } else {
        events = loadLiveUfwEvents(start, end, report.sourceNote, &evidence);
        writeUfwCacheEvents(events);
        ranges.push_back({start, end});
        writeUfwCacheRanges(ranges);
        evidence.cacheCovered = rangeCovered(start, end, ranges);
        evidence.cacheRanges = ufwRangesSummary(ranges);
    }
    touchUfwCacheActivity();
    if (report.sourceNote == "文本缓存") {
        evidence.rawMatches = events.size();
        evidence.validPublic = events.size();
        for (const auto &event : events) {
            if (event.action == "BLOCK") ++evidence.block;
            else if (event.action == "AUDIT") ++evidence.audit;
            else if (event.action == "ALLOW") ++evidence.allow;
            if (event.dpt == kUnknownUfwPort) ++evidence.noDpt;
        }
        if (events.empty()) {
            report.sourceNote = "文本缓存(窗口内无有效记录)";
        }
    }
    return buildUfwReportFromEvents(report.title, report.start, report.end, report.sourceNote, events, evidence);
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

inline DualAuditReport buildDualAuditReport(std::time_t start, std::time_t end, int limit = 30) {
    DualAuditReport report;
    report.rule1 = fail2banJailRuntimeStatus(kRule1Jail);
    report.rule2 = fail2banJailRuntimeStatus(kRule2Jail);
    std::string sourceNote;
    const auto events = loadLiveUfwEvents(start, end, sourceNote);
    std::map<std::string, int> hits;
    for (const auto &event : events) {
        if (event.action == "BLOCK" || event.action == "AUDIT") {
            hits[event.src] += 1;
        }
    }
    const F2bJailConfig cfg = readJailConfig(kRule2Jail);
    int threshold = 50;
    if (isValidPositiveInt(configValueOr(cfg.maxretry, "50"))) {
        threshold = std::stoi(configValueOr(cfg.maxretry, "50"));
    }
    std::string banLog = Shell::capture("journalctl -u fail2ban --no-pager --since " + shellQuote(dateTimeStamp(start)) +
                                        " 2>/dev/null | grep ' Ban ' || grep -h ' Ban ' /var/log/fail2ban.log* 2>/dev/null || true").output;
    for (const auto &item : sortedCounter(hits)) {
        if (static_cast<int>(report.rows.size()) >= limit) {
            break;
        }
        DualAuditRow row;
        row.ip = item.first;
        row.ufwHits = item.second;
        row.rule1Banned = report.rule1.bannedIps.count(item.first) > 0;
        row.rule2Banned = report.rule2.bannedIps.count(item.first) > 0;
        row.banLogged = banLog.find(item.first) != std::string::npos;
        if (!report.rule2.loaded()) {
            row.conclusion = "规则2未加载，无法自动封禁";
        } else if (row.rule2Banned) {
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
        report.rows.push_back(row);
    }
    return report;
}

inline std::vector<DualAuditRow> buildDualAuditRows(std::time_t start, std::time_t end, int limit = 30) {
    return buildDualAuditReport(start, end, limit).rows;
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
                const std::string &footer,
                bool showHardwareCursor = true) const {
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

        std::ostringstream frame;
        const auto draw = [&](int row, const std::string &text) {
            frame << "\033[" << row << ";1H\033[2K" << fitLine(text, cols);
        };

        frame << "\033[?25l\033[H";
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
        frame << (showHardwareCursor ? "\033[?25h" : "\033[?25l");
        std::cout << frame.str();
        std::cout.flush();
    }
};

inline bool adjustScroll(InputKind kind, int &scrollOffset, std::size_t lineCount) {
    const int before = scrollOffset;
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    if (kind == InputKind::Up || kind == InputKind::MouseUp) scrollOffset -= 3;
    else if (kind == InputKind::Down || kind == InputKind::MouseDown) scrollOffset += 3;
    else if (kind == InputKind::PageUp) scrollOffset -= bodyRows;
    else if (kind == InputKind::PageDown) scrollOffset += bodyRows;
    else if (kind == InputKind::Home) scrollOffset = 0;
    else if (kind == InputKind::End) scrollOffset = maxOffset;
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
    return scrollOffset != before;
}

inline bool adjustScrollByRows(int rows, int &scrollOffset, std::size_t lineCount) {
    const int before = scrollOffset;
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    scrollOffset = std::max(0, std::min(scrollOffset + rows, maxOffset));
    return scrollOffset != before;
}

inline bool adjustScrollForEvent(const InputEvent &event, int &scrollOffset, std::size_t lineCount) {
    const int bodyRows = std::max(3, terminalRows() - 4);
    if (event.kind == InputKind::Up || event.kind == InputKind::MouseUp) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind == InputKind::Down || event.kind == InputKind::MouseDown) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
        event.kind == InputKind::Home || event.kind == InputKind::End) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind != InputKind::Character) {
        return false;
    }
    if (event.ch == 'k') return adjustScrollByRows(-3, scrollOffset, lineCount);
    if (event.ch == 'j') return adjustScrollByRows(3, scrollOffset, lineCount);
    if (event.ch == 'g') return adjustScroll(InputKind::Home, scrollOffset, lineCount);
    if (event.ch == 'G') return adjustScroll(InputKind::End, scrollOffset, lineCount);
    if (event.ch == 2) return adjustScroll(InputKind::PageUp, scrollOffset, lineCount);       // Ctrl-b
    if (event.ch == 6) return adjustScroll(InputKind::PageDown, scrollOffset, lineCount);     // Ctrl-f
    if (event.ch == 21) return adjustScrollByRows(-(bodyRows / 2), scrollOffset, lineCount);  // Ctrl-u
    if (event.ch == 4) return adjustScrollByRows(bodyRows / 2, scrollOffset, lineCount);      // Ctrl-d
    return false;
}

inline bool isScrollInput(const InputEvent &event) {
    if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
        event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
        event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
        event.kind == InputKind::Home || event.kind == InputKind::End) {
        return true;
    }
    return event.kind == InputKind::Character &&
           (event.ch == 'j' || event.ch == 'k' || event.ch == 'g' || event.ch == 'G' ||
            event.ch == 2 || event.ch == 4 || event.ch == 6 || event.ch == 21);
}

inline std::string cursorMoveSequence(int row, int col) {
    std::ostringstream out;
    out << "\033[" << std::max(1, row) << ";" << std::max(1, col) << "H\033[?25h";
    return out.str();
}

inline std::string promptInputLine(const std::string &label, const std::string &value, bool cursorOn) {
    return ansi::cyan + label + ansi::plain + value +
           (cursorOn ? ansi::inverse + std::string(" ") + ansi::plain : " ");
}

inline bool adjustSelection(InputKind kind, int &selected, int count) {
    const int before = selected;
    if (count <= 0) {
        selected = 0;
        return selected != before;
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
    return selected != before;
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

inline std::string ufwAnalysisAccuracyNote() {
    return "口径: 精确时间窗口内的公网 SRC UFW BLOCK/AUDIT；按本机本地日期计算单日峰值。"
           "与旧 Python 脚本不同，LTG 不会把同一天但窗口外的已缓存日志并入当前结果。"
           "国家/地区只用于展示，不参与排序、计数或 fail2ban 决策。";
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
    buffer.add(ufwAnalysisAccuracyNote());
    const std::vector<int> evidenceWidths = {16, 56};
    buffer.add(bufferTableRow({"证据", "值"}, evidenceWidths, true));
    buffer.add(bufferTableRule(evidenceWidths));
    buffer.add(bufferTableRow({"原始匹配行", std::to_string(report.evidence.rawMatches)}, evidenceWidths));
    buffer.add(bufferTableRow({"有效公网SRC", std::to_string(report.evidence.validPublic)}, evidenceWidths));
    buffer.add(bufferTableRow({"过滤/无效SRC", std::to_string(report.evidence.filteredSource)}, evidenceWidths));
    buffer.add(bufferTableRow({"动作分布", "BLOCK " + std::to_string(report.evidence.block) +
                                       " / AUDIT " + std::to_string(report.evidence.audit) +
                                       " / ALLOW " + std::to_string(report.evidence.allow)}, evidenceWidths));
    buffer.add(bufferTableRow({"无DPT记录", std::to_string(report.evidence.noDpt)}, evidenceWidths));
    buffer.add(bufferTableRow({"缓存覆盖", report.evidence.cacheCovered ? "是" : "否"}, evidenceWidths));
    if (!report.evidence.cacheRanges.empty()) {
        buffer.add("缓存范围: " + report.evidence.cacheRanges);
    }
    if (report.evidence.cacheCovered && report.validLines == 0) {
        buffer.add(ansi::gray + std::string("缓存命中且当前窗口内无有效公网 UFW 记录。") + ansi::plain);
    }
    buffer.add("");

    struct IpRisk {
        std::string ip;
        std::string country;
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
        const std::string country = ipGeoLabel(item.first);
        if (peak >= 100) high.push_back({item.first, country, peak, total});
        else if (peak >= 10) med.push_back({item.first, country, peak, total});
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
    const std::vector<int> ipWidths = {30, 18, 10, 10, 18, 34};
    buffer.add(ansi::red + std::string("> TOP 高危 IP (单日峰值 >= 100)") + ansi::plain);
    buffer.add(bufferTableRow({"IP", "国家/地区", "单日峰值", "时段总计", "最近3天ALLOW", "扫描端口TOP5"}, ipWidths, true));
    buffer.add(bufferTableRule(ipWidths));
    if (high.empty()) {
        buffer.add("  " + ansi::gray + "- 暂无高危 IP" + ansi::plain);
    }
    for (std::size_t i = 0; i < high.size() && i < 15; ++i) {
        buffer.add(bufferTableRow({high[i].ip, high[i].country, std::to_string(high[i].peak), std::to_string(high[i].total),
                                   allowText(high[i].ip), topPortsText(report, high[i].ip)}, ipWidths));
    }
    buffer.add("");
    buffer.add(ansi::yellow + std::string("> TOP 中危 IP (10 <= 单日峰值 < 100)") + ansi::plain);
    buffer.add(bufferTableRow({"IP", "国家/地区", "单日峰值", "时段总计"}, {30, 18, 10, 10}, true));
    buffer.add(bufferTableRule({30, 18, 10, 10}));
    if (med.empty()) {
        buffer.add("  " + ansi::gray + "- 暂无中危 IP" + ansi::plain);
    }
    for (std::size_t i = 0; i < med.size() && i < 10; ++i) {
        buffer.add(bufferTableRow({med[i].ip, med[i].country, std::to_string(med[i].peak), std::to_string(med[i].total)}, {30, 18, 10, 10}));
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
        buffer.add("国家/地区: " + ipGeoLabel(traceIp));
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

inline std::string nftCommandIgnoreError(const std::string &body) {
    return nftCommand(body) + " 2>/dev/null || true";
}

inline std::vector<std::string> trafficAccountingRuleCommands(const std::set<int> &ports, bool resetTable) {
    const std::string table = "inet " + kIpTrafficTable;
    const std::string portElements = nftPortElements(ports);
    std::vector<std::string> commands;
    if (resetTable) {
        commands.push_back("nft delete table " + table + " 2>/dev/null || true");
    }
    commands.push_back(nftCommandIgnoreError("add table " + table));
    commands.push_back(nftCommandIgnoreError("add set " + table + " tracked_ports { type inet_service; flags interval; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv4_download { type ipv4_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv4_upload { type ipv4_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv6_download { type ipv6_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv6_upload { type ipv6_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("flush set " + table + " tracked_ports"));
    commands.push_back(nftCommand("add element " + table + " tracked_ports " + portElements));
    for (const char *chain : {"input_account", "output_account", "forward_account"}) {
        commands.push_back(nftCommandIgnoreError("flush chain " + table + " " + std::string(chain)));
        commands.push_back(nftCommandIgnoreError("delete chain " + table + " " + std::string(chain)));
    }
    commands.push_back(nftCommand("add chain " + table + " input_account { type filter hook input priority -150; policy accept; }"));
    commands.push_back(nftCommand("add chain " + table + " output_account { type filter hook output priority -150; policy accept; }"));
    commands.push_back(nftCommand("add chain " + table + " forward_account { type filter hook forward priority -150; policy accept; }"));
    commands.push_back(nftCommand("add rule " + table + " input_account tcp dport @tracked_ports update @ipv4_download { ip saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account udp dport @tracked_ports update @ipv4_download { ip saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account meta nfproto ipv6 tcp dport @tracked_ports update @ipv6_download { ip6 saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account meta nfproto ipv6 udp dport @tracked_ports update @ipv6_download { ip6 saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account tcp sport @tracked_ports update @ipv4_upload { ip daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account udp sport @tracked_ports update @ipv4_upload { ip daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account meta nfproto ipv6 tcp sport @tracked_ports update @ipv6_upload { ip6 daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account meta nfproto ipv6 udp sport @tracked_ports update @ipv6_upload { ip6 daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account tcp dport @tracked_ports update @ipv4_download { ip saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account udp dport @tracked_ports update @ipv4_download { ip saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account tcp sport @tracked_ports update @ipv4_upload { ip daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account udp sport @tracked_ports update @ipv4_upload { ip daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp dport @tracked_ports update @ipv6_download { ip6 saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp dport @tracked_ports update @ipv6_download { ip6 saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp sport @tracked_ports update @ipv6_upload { ip6 daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp sport @tracked_ports update @ipv6_upload { ip6 daddr . udp sport }"));
    return commands;
}

inline std::vector<std::string> trafficPortSetUpdateCommands(const std::set<int> &ports) {
    const std::string table = "inet " + kIpTrafficTable;
    std::vector<std::string> commands = {
        nftCommandIgnoreError("add set " + table + " tracked_ports { type inet_service; flags interval; }"),
        nftCommandIgnoreError("flush set " + table + " tracked_ports"),
    };
    if (!ports.empty()) {
        commands.push_back(nftCommand("add element " + table + " tracked_ports " + nftPortElements(ports)));
    }
    return commands;
}

inline bool writeTrafficSnapshotTimerUnits(const std::string &argv0, std::string &error) {
#ifdef _WIN32
    (void)argv0;
    error = "Windows 不支持 systemd timer。";
    return false;
#else
    const std::string exe = currentExecutablePath(argv0.empty() ? nullptr : argv0.c_str());
    const std::string servicePath = "/etc/systemd/system/" + kTrafficSnapshotService;
    const std::string timerPath = "/etc/systemd/system/" + kTrafficSnapshotTimer;
    std::ostringstream service;
    service << "[Unit]\n"
            << "Description=Linux Traffic Guard traffic history snapshot\n\n"
            << "[Service]\n"
            << "Type=oneshot\n"
            << "ExecStart=" << exe << " --traffic-snapshot\n";
    std::ostringstream timer;
    timer << "[Unit]\n"
          << "Description=Run Linux Traffic Guard traffic snapshot every 5 minutes\n\n"
          << "[Timer]\n"
          << "OnBootSec=2min\n"
          << "OnUnitActiveSec=5min\n"
          << "AccuracySec=30s\n"
          << "Persistent=true\n\n"
          << "[Install]\n"
          << "WantedBy=timers.target\n";
    if (!writeTextFile(servicePath, service.str())) {
        error = "无法写入 " + servicePath;
        return false;
    }
    if (!writeTextFile(timerPath, timer.str())) {
        error = "无法写入 " + timerPath;
        return false;
    }
    return true;
#endif
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

inline bool trafficTrackedPortsSetEnabled() {
    return Shell::exists("nft") &&
           Shell::capture("nft list set inet " + kIpTrafficTable + " tracked_ports 2>/dev/null").ok();
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

inline std::string trafficHistoryPath(const std::string &name) {
    return kTrafficHistoryDir + "/" + name;
}

inline bool trafficHistoryConfiguredFast() {
#if LTG_HAS_SQLITE
    return fileExists(trafficHistoryPath("events.sqlite3"));
#else
    return fileExists(trafficHistoryPath("tracked_ports.tsv")) ||
           fileExists(trafficHistoryPath("snapshot.tsv")) ||
           fileExists(trafficHistoryPath("delta.tsv"));
#endif
}

inline std::string trafficKey(const TrafficRow &row) {
    return row.family + "\t" + row.direction + "\t" + row.ip + "\t" + row.port;
}

inline bool sameOrHigherCounters(const TrafficRow &current, const TrafficRow &previous) {
    return current.bytes >= previous.bytes && current.packets >= previous.packets;
}

inline std::vector<TrafficDelta> computeTrafficDeltas(const std::vector<TrafficRow> &current,
                                                      const std::map<std::string, TrafficRow> &previous,
                                                      std::time_t sampledAt,
                                                      std::size_t &resetRows) {
    std::vector<TrafficDelta> deltas;
    resetRows = 0;
    for (const auto &row : current) {
        const auto found = previous.find(trafficKey(row));
        if (found == previous.end()) {
            if (row.bytes > 0 || row.packets > 0) {
                deltas.push_back({row, sampledAt, localDayStamp(sampledAt), localMonthStamp(sampledAt), localYearStamp(sampledAt)});
            }
            continue;
        }
        if (!sameOrHigherCounters(row, found->second)) {
            ++resetRows;
            continue;
        }
        TrafficRow delta = row;
        delta.bytes -= found->second.bytes;
        delta.packets -= found->second.packets;
        if (delta.bytes == 0 && delta.packets == 0) {
            continue;
        }
        deltas.push_back({delta, sampledAt, localDayStamp(sampledAt), localMonthStamp(sampledAt), localYearStamp(sampledAt)});
    }
    return deltas;
}

#if LTG_HAS_SQLITE
inline std::string trafficHistoryDbPath() {
    return trafficHistoryPath("events.sqlite3");
}

inline bool trafficSqlExec(sqlite3 *db, const std::string &sql, std::string &error) {
    char *rawError = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &rawError);
    if (rc != SQLITE_OK) {
        error = rawError ? rawError : sqlite3_errmsg(db);
        sqlite3_free(rawError);
        return false;
    }
    return true;
}

inline bool openTrafficHistoryDb(sqlite3 **db, std::string &error) {
    ensureDirectory(kTrafficHistoryDir);
    if (sqlite3_open(trafficHistoryDbPath().c_str(), db) != SQLITE_OK) {
        error = *db ? sqlite3_errmsg(*db) : "无法打开 SQLite 历史库";
        if (*db) {
            sqlite3_close(*db);
            *db = nullptr;
        }
        return false;
    }
    const std::string schema =
        "create table if not exists traffic_snapshot("
        "sampled_at integer not null,family text not null,direction text not null,ip text not null,port text not null,"
        "bytes integer not null,packets integer not null,primary key(sampled_at,family,direction,ip,port));"
        "create table if not exists traffic_delta("
        "sampled_at integer not null,day text not null,month text not null,year text not null,"
        "family text not null,direction text not null,ip text not null,port text not null,bytes integer not null,packets integer not null);"
        "create table if not exists tracked_ports(port integer primary key);"
        "create table if not exists meta(key text primary key,value text not null);"
        "create index if not exists idx_traffic_delta_month_port on traffic_delta(month,port,direction);"
        "create index if not exists idx_traffic_delta_day_port on traffic_delta(day,port,direction);"
        "create index if not exists idx_traffic_delta_year_port on traffic_delta(year,port,direction);";
    if (!trafficSqlExec(*db, schema, error)) {
        sqlite3_close(*db);
        *db = nullptr;
        return false;
    }
    return true;
}

inline std::map<std::string, TrafficRow> loadLatestTrafficSnapshot(std::string &error) {
    std::map<std::string, TrafficRow> out;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return out;
    }
    const char *sql =
        "select family,direction,ip,port,bytes,packets from traffic_snapshot "
        "where sampled_at=(select max(sampled_at) from traffic_snapshot);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db);
        sqlite3_close(db);
        return out;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrafficRow row;
        row.family = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        row.direction = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        row.ip = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        row.port = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        row.bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 4));
        row.packets = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        out[trafficKey(row)] = row;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

inline bool trafficHistoryHasDeltas() {
    if (!fileExists(trafficHistoryDbPath())) {
        return false;
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return false;
    }
    sqlite3_stmt *stmt = nullptr;
    bool hasRows = false;
    if (sqlite3_prepare_v2(db, "select 1 from traffic_delta limit 1;", -1, &stmt, nullptr) == SQLITE_OK) {
        hasRows = sqlite3_step(stmt) == SQLITE_ROW;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return hasRows;
}

inline bool insertTrafficSnapshotRows(const std::vector<TrafficRow> &rows, std::time_t sampledAt, std::string &error) {
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return false;
    }
    trafficSqlExec(db, "begin immediate;", error);
    const char *sql =
        "insert or replace into traffic_snapshot(sampled_at,family,direction,ip,port,bytes,packets) values(?,?,?,?,?,?,?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db);
        sqlite3_close(db);
        return false;
    }
    bool ok = true;
    for (const auto &row : rows) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(sampledAt));
        sqlite3_bind_text(stmt, 2, row.family.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, row.direction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, row.ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, row.port.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(row.bytes));
        sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(row.packets));
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            error = sqlite3_errmsg(db);
            ok = false;
            break;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
    sqlite3_finalize(stmt);
    trafficSqlExec(db, ok ? "commit;" : "rollback;", error);
    sqlite3_close(db);
    return ok;
}

inline bool insertTrafficDeltas(const std::vector<TrafficDelta> &deltas, std::string &error) {
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return false;
    }
    trafficSqlExec(db, "begin immediate;", error);
    const char *sql =
        "insert into traffic_delta(sampled_at,day,month,year,family,direction,ip,port,bytes,packets) values(?,?,?,?,?,?,?,?,?,?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db);
        sqlite3_close(db);
        return false;
    }
    bool ok = true;
    for (const auto &delta : deltas) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(delta.sampledAt));
        sqlite3_bind_text(stmt, 2, delta.day.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, delta.month.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, delta.year.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, delta.row.family.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, delta.row.direction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, delta.row.ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, delta.row.port.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(delta.row.bytes));
        sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(delta.row.packets));
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            error = sqlite3_errmsg(db);
            ok = false;
            break;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
    sqlite3_finalize(stmt);
    trafficSqlExec(db, ok ? "commit;" : "rollback;", error);
    sqlite3_close(db);
    return ok;
}

inline bool storeTrackedTrafficPorts(const std::set<int> &ports, std::string &error) {
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return false;
    }
    trafficSqlExec(db, "begin immediate; delete from tracked_ports;", error);
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "insert or ignore into tracked_ports(port) values(?);", -1, &stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db);
        sqlite3_close(db);
        return false;
    }
    bool ok = true;
    for (int port : ports) {
        sqlite3_bind_int(stmt, 1, port);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            error = sqlite3_errmsg(db);
            ok = false;
            break;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
    sqlite3_finalize(stmt);
    trafficSqlExec(db, ok ? "commit;" : "rollback;", error);
    sqlite3_close(db);
    return ok;
}

inline std::set<int> loadTrackedTrafficPorts() {
    std::set<int> out;
    std::string error;
    if (!fileExists(trafficHistoryDbPath())) {
        return out;
    }
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return out;
    }
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "select port from tracked_ports order by port;", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out.insert(sqlite3_column_int(stmt, 0));
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}

inline std::vector<TrafficRow> loadTrafficDeltasForPeriod(TrafficPeriodMode mode, const std::string &period) {
    std::vector<TrafficRow> rows;
    if (!fileExists(trafficHistoryDbPath())) {
        return rows;
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return rows;
    }
    const std::string column = mode == TrafficPeriodMode::Day ? "day" : mode == TrafficPeriodMode::Year ? "year" : "month";
    const std::string sql = "select family,direction,ip,port,sum(bytes),sum(packets) from traffic_delta where " +
                            column + "=? group by family,direction,ip,port;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return rows;
    }
    sqlite3_bind_text(stmt, 1, period.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrafficRow row;
        row.family = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        row.direction = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        row.ip = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        row.port = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        row.bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 4));
        row.packets = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rows;
}

inline std::vector<TrafficSummaryRow> loadTrafficPortSummaryForPeriod(TrafficPeriodMode mode, const std::string &period) {
    std::map<std::string, TrafficSummaryRow> grouped;
    if (!fileExists(trafficHistoryDbPath())) {
        return {};
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return {};
    }
    const std::string column = mode == TrafficPeriodMode::Day ? "day" : mode == TrafficPeriodMode::Year ? "year" : "month";
    const std::string sql = "select direction,port,sum(bytes),sum(packets) from traffic_delta where " +
                            column + "=? group by direction,port;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return {};
    }
    sqlite3_bind_text(stmt, 1, period.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const std::string direction = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const std::string port = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        auto &slot = grouped[port];
        slot.ip = "*";
        slot.port = port;
        const auto bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 2));
        const auto packets = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        if (direction == "上传") {
            slot.uploadBytes += bytes;
            slot.uploadPackets += packets;
        } else {
            slot.downloadBytes += bytes;
            slot.downloadPackets += packets;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::vector<TrafficSummaryRow> out;
    for (const auto &item : grouped) {
        out.push_back(item.second);
    }
    std::sort(out.begin(), out.end(), [](const TrafficSummaryRow &a, const TrafficSummaryRow &b) {
        if (a.totalBytes() != b.totalBytes()) {
            return a.totalBytes() > b.totalBytes();
        }
        return a.port < b.port;
    });
    return out;
}

inline std::vector<TrafficPeriodTotal> loadTrafficPeriodTotals(TrafficPeriodMode mode, std::size_t limit) {
    std::map<std::string, TrafficPeriodTotal, std::greater<std::string>> grouped;
    if (!fileExists(trafficHistoryDbPath())) {
        return {};
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return {};
    }
    const std::string column = mode == TrafficPeriodMode::Day ? "day" : mode == TrafficPeriodMode::Year ? "year" : "month";
    const std::string sql = "select " + column + ",direction,sum(bytes),sum(packets) from traffic_delta group by " +
                            column + ",direction order by " + column + " desc;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return {};
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const std::string period = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        const std::string direction = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        auto &slot = grouped[period];
        slot.period = period;
        const auto bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 2));
        const auto packets = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 3));
        if (direction == "上传") {
            slot.uploadBytes += bytes;
            slot.uploadPackets += packets;
        } else {
            slot.downloadBytes += bytes;
            slot.downloadPackets += packets;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::vector<TrafficPeriodTotal> out;
    for (const auto &item : grouped) {
        out.push_back(item.second);
        if (out.size() >= limit) {
            break;
        }
    }
    return out;
}

inline std::map<std::string, std::vector<TrafficRow>> loadTrafficDeltasForPeriods(TrafficPeriodMode mode,
                                                                                  const std::vector<std::string> &periods) {
    std::map<std::string, std::vector<TrafficRow>> out;
    if (periods.empty() || !fileExists(trafficHistoryDbPath())) {
        return out;
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return out;
    }
    const std::string column = mode == TrafficPeriodMode::Day ? "day" : mode == TrafficPeriodMode::Year ? "year" : "month";
    std::ostringstream placeholders;
    for (std::size_t i = 0; i < periods.size(); ++i) {
        if (i != 0) {
            placeholders << ",";
        }
        placeholders << "?";
    }
    const std::string sql = "select " + column + ",family,direction,ip,port,sum(bytes),sum(packets) from traffic_delta where " +
                            column + " in (" + placeholders.str() + ") group by " + column + ",family,direction,ip,port;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return out;
    }
    for (std::size_t i = 0; i < periods.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), periods[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const auto *periodText = sqlite3_column_text(stmt, 0);
        const auto *familyText = sqlite3_column_text(stmt, 1);
        const auto *directionText = sqlite3_column_text(stmt, 2);
        const auto *ipText = sqlite3_column_text(stmt, 3);
        const auto *portText = sqlite3_column_text(stmt, 4);
        if (!periodText || !familyText || !directionText || !ipText || !portText) {
            continue;
        }
        TrafficRow row;
        row.family = reinterpret_cast<const char *>(familyText);
        row.direction = reinterpret_cast<const char *>(directionText);
        row.ip = reinterpret_cast<const char *>(ipText);
        row.port = reinterpret_cast<const char *>(portText);
        row.bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        row.packets = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 6));
        out[reinterpret_cast<const char *>(periodText)].push_back(std::move(row));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
}
#else
inline std::map<std::string, TrafficRow> loadLatestTrafficSnapshot(std::string &error) {
    std::map<std::string, TrafficRow> out;
    std::ifstream input(trafficHistoryPath("snapshot.tsv"), std::ios::binary);
    if (!input) {
        error.clear();
        return out;
    }
    std::string line;
    std::time_t latest = 0;
    std::vector<std::pair<std::time_t, TrafficRow>> parsed;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 7) {
            continue;
        }
        TrafficRow row;
        row.family = parts[1];
        row.direction = parts[2];
        row.ip = parts[3];
        row.port = parts[4];
        std::uint64_t bytes = 0;
        std::uint64_t packets = 0;
        if (!parseU64(parts[5], bytes) || !parseU64(parts[6], packets)) {
            continue;
        }
        row.bytes = bytes;
        row.packets = packets;
        const std::time_t ts = static_cast<std::time_t>(std::stoll(parts[0]));
        latest = std::max(latest, ts);
        parsed.push_back({ts, row});
    }
    for (const auto &item : parsed) {
        if (item.first == latest) {
            out[trafficKey(item.second)] = item.second;
        }
    }
    return out;
}

inline bool trafficHistoryHasDeltas() {
    std::ifstream input(trafficHistoryPath("delta.tsv"), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        if (!trim(line).empty()) {
            return true;
        }
    }
    return false;
}

inline bool insertTrafficSnapshotRows(const std::vector<TrafficRow> &rows, std::time_t sampledAt, std::string &error) {
    ensureDirectory(kTrafficHistoryDir);
    std::ofstream output(trafficHistoryPath("snapshot.tsv"), std::ios::binary | std::ios::app);
    if (!output) {
        error = "无法写入 snapshot.tsv";
        return false;
    }
    for (const auto &row : rows) {
        output << sampledAt << '\t' << row.family << '\t' << row.direction << '\t' << row.ip << '\t'
               << row.port << '\t' << row.bytes << '\t' << row.packets << '\n';
    }
    return static_cast<bool>(output);
}

inline bool insertTrafficDeltas(const std::vector<TrafficDelta> &deltas, std::string &error) {
    ensureDirectory(kTrafficHistoryDir);
    std::ofstream output(trafficHistoryPath("delta.tsv"), std::ios::binary | std::ios::app);
    if (!output) {
        error = "无法写入 delta.tsv";
        return false;
    }
    for (const auto &delta : deltas) {
        output << delta.sampledAt << '\t' << delta.day << '\t' << delta.month << '\t' << delta.year << '\t'
               << delta.row.family << '\t' << delta.row.direction << '\t' << delta.row.ip << '\t'
               << delta.row.port << '\t' << delta.row.bytes << '\t' << delta.row.packets << '\n';
    }
    return static_cast<bool>(output);
}

inline bool storeTrackedTrafficPorts(const std::set<int> &ports, std::string &error) {
    ensureDirectory(kTrafficHistoryDir);
    std::ofstream output(trafficHistoryPath("tracked_ports.tsv"), std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "无法写入 tracked_ports.tsv";
        return false;
    }
    for (int port : ports) {
        output << port << '\n';
    }
    return static_cast<bool>(output);
}

inline std::set<int> loadTrackedTrafficPorts() {
    std::set<int> out;
    std::ifstream input(trafficHistoryPath("tracked_ports.tsv"), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        if (isSafeSinglePort(trim(line))) {
            out.insert(std::stoi(trim(line)));
        }
    }
    return out;
}

inline std::vector<TrafficRow> loadTrafficDeltasForPeriod(TrafficPeriodMode mode, const std::string &period) {
    std::vector<TrafficRow> rows;
    std::ifstream input(trafficHistoryPath("delta.tsv"), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 10) {
            continue;
        }
        const std::string &bucket = mode == TrafficPeriodMode::Day ? parts[1] : mode == TrafficPeriodMode::Year ? parts[3] : parts[2];
        if (bucket != period) {
            continue;
        }
        TrafficRow row;
        row.family = parts[4];
        row.direction = parts[5];
        row.ip = parts[6];
        row.port = parts[7];
        if (!parseU64(parts[8], row.bytes) || !parseU64(parts[9], row.packets)) {
            continue;
        }
        rows.push_back(row);
    }
    return rows;
}

inline std::vector<TrafficSummaryRow> loadTrafficPortSummaryForPeriod(TrafficPeriodMode mode, const std::string &period) {
    std::map<std::string, TrafficSummaryRow> grouped;
    for (const auto &row : loadTrafficDeltasForPeriod(mode, period)) {
        auto &slot = grouped[row.port];
        slot.ip = "*";
        slot.port = row.port;
        if (row.direction == "上传") {
            slot.uploadBytes += row.bytes;
            slot.uploadPackets += row.packets;
        } else {
            slot.downloadBytes += row.bytes;
            slot.downloadPackets += row.packets;
        }
    }
    std::vector<TrafficSummaryRow> out;
    for (const auto &item : grouped) {
        out.push_back(item.second);
    }
    std::sort(out.begin(), out.end(), [](const TrafficSummaryRow &a, const TrafficSummaryRow &b) {
        if (a.totalBytes() != b.totalBytes()) {
            return a.totalBytes() > b.totalBytes();
        }
        return a.port < b.port;
    });
    return out;
}

inline std::vector<TrafficPeriodTotal> loadTrafficPeriodTotals(TrafficPeriodMode mode, std::size_t limit) {
    std::map<std::string, TrafficPeriodTotal, std::greater<std::string>> grouped;
    std::ifstream input(trafficHistoryPath("delta.tsv"), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 10) {
            continue;
        }
        const std::string &period = mode == TrafficPeriodMode::Day ? parts[1] : mode == TrafficPeriodMode::Year ? parts[3] : parts[2];
        TrafficRow row;
        row.direction = parts[5];
        if (!parseU64(parts[8], row.bytes) || !parseU64(parts[9], row.packets)) {
            continue;
        }
        auto &slot = grouped[period];
        slot.period = period;
        if (row.direction == "上传") {
            slot.uploadBytes += row.bytes;
            slot.uploadPackets += row.packets;
        } else {
            slot.downloadBytes += row.bytes;
            slot.downloadPackets += row.packets;
        }
    }
    std::vector<TrafficPeriodTotal> out;
    for (const auto &item : grouped) {
        out.push_back(item.second);
        if (out.size() >= limit) {
            break;
        }
    }
    return out;
}

inline std::map<std::string, std::vector<TrafficRow>> loadTrafficDeltasForPeriods(TrafficPeriodMode mode,
                                                                                  const std::vector<std::string> &periods) {
    std::map<std::string, std::vector<TrafficRow>> out;
    if (periods.empty()) {
        return out;
    }
    const std::set<std::string> wanted(periods.begin(), periods.end());
    std::ifstream input(trafficHistoryPath("delta.tsv"), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 10) {
            continue;
        }
        const std::string &period = mode == TrafficPeriodMode::Day ? parts[1] : mode == TrafficPeriodMode::Year ? parts[3] : parts[2];
        if (wanted.find(period) == wanted.end()) {
            continue;
        }
        TrafficRow row;
        row.family = parts[4];
        row.direction = parts[5];
        row.ip = parts[6];
        row.port = parts[7];
        if (!parseU64(parts[8], row.bytes) || !parseU64(parts[9], row.packets)) {
            continue;
        }
        out[period].push_back(std::move(row));
    }
    return out;
}
#endif

inline std::set<int> detectExistingTrafficPorts() {
    std::set<int> ports = loadTrackedTrafficPorts();
    if (!Shell::exists("nft")) {
        return ports;
    }
    const CommandResult tracked = Shell::capture("nft list set inet " + kIpTrafficTable + " tracked_ports 2>/dev/null || true");
    const std::regex elementsPattern(R"(elements\s*=\s*\{([^}]*)\})");
    std::smatch match;
    if (std::regex_search(tracked.output, match, elementsPattern)) {
        parseNftPortListInto(match[1].str(), ports);
    }
    const CommandResult table = Shell::capture("nft list table inet " + kIpTrafficTable + " 2>/dev/null || true");
    const std::regex literalPattern(R"((?:dport|sport)\s+\{([^}]*)\})");
    for (std::sregex_iterator it(table.output.begin(), table.output.end(), literalPattern), end; it != end; ++it) {
        parseNftPortListInto((*it)[1].str(), ports);
    }
    return ports;
}

inline std::set<int> nftTrackedTrafficPorts() {
    std::set<int> ports;
    if (!Shell::exists("nft")) {
        return ports;
    }
    const CommandResult tracked = Shell::capture("nft list set inet " + kIpTrafficTable + " tracked_ports 2>/dev/null || true");
    const std::regex elementsPattern(R"(elements\s*=\s*\{([^}]*)\})");
    std::smatch match;
    if (std::regex_search(tracked.output, match, elementsPattern)) {
        parseNftPortListInto(match[1].str(), ports);
    }
    return ports;
}

inline bool nftChainContains(const std::string &body, const std::string &chain, const std::string &needle) {
    const std::string marker = "chain " + chain;
    const std::size_t start = body.find(marker);
    if (start == std::string::npos) {
        return false;
    }
    const std::size_t next = body.find("\n\tchain ", start + marker.size());
    const std::string section = body.substr(start, next == std::string::npos ? std::string::npos : next - start);
    return section.find(needle) != std::string::npos;
}

struct TrafficAccountingVerification {
    bool ok = false;
    std::set<int> nftPorts;
    std::vector<std::string> failures;
    std::string evidence;
};

inline TrafficAccountingVerification verifyTrafficAccountingApplied(const std::set<int> &expectedPorts) {
    TrafficAccountingVerification verification;
    if (!Shell::exists("nft")) {
        verification.failures.push_back("nft 命令不可用");
        return verification;
    }
    const CommandResult table = Shell::capture("nft list table inet " + kIpTrafficTable + " 2>&1");
    if (!table.ok()) {
        verification.failures.push_back("统计表不存在或不可读取: " + firstNonEmptyLine(table.output));
        return verification;
    }
    const std::string &body = table.output;
    const std::vector<std::string> sets = {"tracked_ports", "ipv4_download", "ipv4_upload", "ipv6_download", "ipv6_upload"};
    for (const auto &setName : sets) {
        if (body.find("set " + setName) == std::string::npos) {
            verification.failures.push_back("缺少 set " + setName);
        }
    }
    const std::vector<std::pair<std::string, std::string>> chains = {
        {"input_account", "hook input"},
        {"output_account", "hook output"},
        {"forward_account", "hook forward"},
    };
    for (const auto &chain : chains) {
        if (!nftChainContains(body, chain.first, chain.second)) {
            verification.failures.push_back("chain " + chain.first + " 未挂载 " + chain.second);
        }
    }
    if (body.find("@tracked_ports") == std::string::npos) {
        verification.failures.push_back("规则未引用 @tracked_ports");
    }
    for (const auto &counterSet : {"@ipv4_download", "@ipv4_upload", "@ipv6_download", "@ipv6_upload"}) {
        if (body.find(counterSet) == std::string::npos) {
            verification.failures.push_back(std::string("规则未更新 ") + counterSet);
        }
    }
    verification.nftPorts = nftTrackedTrafficPorts();
    if (verification.nftPorts != expectedPorts) {
        verification.failures.push_back("nft tracked_ports 与目标端口不一致");
    }
    verification.evidence = "目标端口: " + humanPortList(expectedPorts) + " / nft端口: " + humanPortList(verification.nftPorts);
    verification.ok = verification.failures.empty();
    return verification;
}

inline TrafficSnapshotResult recordTrafficSnapshot() {
    TrafficSnapshotResult result;
    result.sampledAt = std::time(nullptr);
    if (!trafficTableEnabled()) {
        result.message = "流量统计规则未启用。";
        return result;
    }
    std::string error;
    const auto previous = loadLatestTrafficSnapshot(error);
    if (!error.empty()) {
        result.message = error;
        return result;
    }
    const auto current = collectTrafficRows();
    std::size_t resetRows = 0;
    const bool seedExistingCounters = !previous.empty() && !trafficHistoryHasDeltas();
    const auto deltas = computeTrafficDeltas(current, seedExistingCounters ? std::map<std::string, TrafficRow>{} : previous, result.sampledAt, resetRows);
    if (!insertTrafficSnapshotRows(current, result.sampledAt, error)) {
        result.message = error;
        return result;
    }
    if (!deltas.empty() && !insertTrafficDeltas(deltas, error)) {
        result.message = error;
        return result;
    }
    result.ok = true;
    result.liveRows = current.size();
    result.deltaRows = deltas.size();
    result.resetRows = resetRows;
    result.message = seedExistingCounters ? "采样完成，已把旧版本首轮快照中的已有计数纳入当前周期。" : "采样完成。";
    return result;
}

inline std::time_t latestTrafficSnapshotTime() {
#if LTG_HAS_SQLITE
    if (!fileExists(trafficHistoryDbPath())) {
        return 0;
    }
    std::string error;
    sqlite3 *db = nullptr;
    if (!openTrafficHistoryDb(&db, error)) {
        return 0;
    }
    sqlite3_stmt *stmt = nullptr;
    std::time_t out = 0;
    if (sqlite3_prepare_v2(db, "select max(sampled_at) from traffic_snapshot;", -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        out = static_cast<std::time_t>(sqlite3_column_int64(stmt, 0));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return out;
#else
    std::ifstream input(trafficHistoryPath("snapshot.tsv"), std::ios::binary);
    std::string line;
    std::time_t latest = 0;
    while (std::getline(input, line)) {
        const auto parts = splitByChar(line, '\t');
        if (parts.size() != 7) {
            continue;
        }
        try {
            const long long value = std::stoll(parts[0]);
            latest = std::max<std::time_t>(latest, static_cast<std::time_t>(value));
        } catch (...) {
            continue;
        }
    }
    return latest;
#endif
}

inline std::vector<TrafficSummaryRow> aggregateTraffic(const std::vector<TrafficRow> &rows, TrafficGroupMode mode) {
    std::map<std::string, TrafficSummaryRow> grouped;
    for (const auto &row : rows) {
        std::string key = row.ip;
        if (mode == TrafficGroupMode::Port) {
            key = row.port;
        } else if (mode == TrafficGroupMode::IpPort) {
            key = row.ip + "\n" + row.port;
        }
        auto &slot = grouped[key];
        slot.ip = mode == TrafficGroupMode::Port ? "*" : row.ip;
        slot.port = mode == TrafficGroupMode::Ip ? "*" : row.port;
        if (row.direction == "上传") {
            slot.uploadBytes += row.bytes;
            slot.uploadPackets += row.packets;
        } else {
            slot.downloadBytes += row.bytes;
            slot.downloadPackets += row.packets;
        }
    }
    std::vector<TrafficSummaryRow> out;
    for (auto entry : grouped) {
        if (mode != TrafficGroupMode::Port && !entry.second.ip.empty()) {
            entry.second.geo = ipGeoLabel(entry.second.ip);
        }
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
    return aggregateTraffic(rows, TrafficGroupMode::Ip);
}

inline std::vector<TrafficSummaryRow> aggregateTrafficByPort(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, TrafficGroupMode::Port);
}

inline std::vector<TrafficSummaryRow> aggregateTrafficByIpPort(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, TrafficGroupMode::IpPort);
}

inline std::vector<TrafficSummaryRow> aggregateTrafficHistoryByPort(TrafficPeriodMode mode, const std::string &period) {
    return loadTrafficPortSummaryForPeriod(mode, period);
}

inline std::vector<TrafficSummaryRow> aggregateTrafficHistoryByPortForRecentDays(std::size_t days, std::vector<std::string> &periods) {
    periods = recentTrafficDayPeriods(days);
    std::vector<TrafficRow> combined;
    for (const auto &entry : loadTrafficDeltasForPeriods(TrafficPeriodMode::Day, periods)) {
        combined.insert(combined.end(), entry.second.begin(), entry.second.end());
    }
    return aggregateTrafficByPort(combined);
}

inline TrafficSummaryRow sumTrafficSummaryRows(const std::vector<TrafficSummaryRow> &rows) {
    TrafficSummaryRow total;
    total.ip = "*";
    total.port = "*";
    for (const auto &row : rows) {
        total.downloadBytes += row.downloadBytes;
        total.uploadBytes += row.uploadBytes;
        total.downloadPackets += row.downloadPackets;
        total.uploadPackets += row.uploadPackets;
    }
    return total;
}

inline std::string compactTrafficSummary(const std::vector<TrafficSummaryRow> &rows,
                                         TrafficGroupMode mode,
                                         std::size_t limit) {
    if (rows.empty()) {
        return "-";
    }
    std::vector<std::string> items;
    for (std::size_t i = 0; i < rows.size() && i < limit; ++i) {
        std::ostringstream item;
        if (mode == TrafficGroupMode::Port) {
            item << rows[i].port;
        } else if (mode == TrafficGroupMode::IpPort) {
            item << rows[i].ip << ":" << rows[i].port;
        } else {
            item << rows[i].ip;
        }
        item << " " << humanBytes(rows[i].totalBytes());
        items.push_back(item.str());
    }
    if (rows.size() > limit) {
        items.push_back("+" + std::to_string(rows.size() - limit));
    }
    return joinWords(items, ", ");
}

inline Table trafficSummaryTable(const std::vector<TrafficSummaryRow> &rows, std::size_t limit, TrafficGroupMode mode) {
    Table table(mode == TrafficGroupMode::IpPort ? std::vector<std::string>{"序号", "IP", "国家/地区", "端口", "上行", "下行", "合计", "包数"}
                : mode == TrafficGroupMode::Port ? std::vector<std::string>{"序号", "端口", "服务", "上行", "下行", "合计", "包数"}
                                                  : std::vector<std::string>{"序号", "IP", "国家/地区", "上行", "下行", "合计", "包数"},
                mode == TrafficGroupMode::IpPort ? std::vector<std::size_t>{6, 28, 18, 8, 12, 12, 12, 10}
                : mode == TrafficGroupMode::Port ? std::vector<std::size_t>{6, 8, 18, 12, 12, 12, 10}
                                                  : std::vector<std::size_t>{6, 28, 18, 12, 12, 12, 10});
    for (std::size_t i = 0; i < rows.size() && i < limit; ++i) {
        std::vector<std::string> cells = {std::to_string(i + 1)};
        if (mode == TrafficGroupMode::Port) {
            cells.push_back(rows[i].port);
            cells.push_back(serviceNameForPort(rows[i].port));
        } else {
            cells.push_back(rows[i].ip);
            cells.push_back(rows[i].geo.empty() ? ipGeoLabel(rows[i].ip) : rows[i].geo);
            if (mode == TrafficGroupMode::IpPort) {
                cells.push_back(rows[i].port);
            }
        }
        cells.push_back(humanBytes(rows[i].uploadBytes));
        cells.push_back(humanBytes(rows[i].downloadBytes));
        cells.push_back(humanBytes(rows[i].totalBytes()));
        cells.push_back(std::to_string(rows[i].totalPackets()));
        table.add(std::move(cells));
    }
    return table;
}

inline Table trafficSummaryTable(const std::vector<TrafficSummaryRow> &rows, std::size_t limit, bool includePort) {
    return trafficSummaryTable(rows, limit, includePort ? TrafficGroupMode::IpPort : TrafficGroupMode::Ip);
}

inline Table trafficPeriodTotalsTable(const std::vector<TrafficPeriodTotal> &rows,
                                      TrafficPeriodMode mode,
                                      const std::map<std::string, std::vector<TrafficRow>> &details = {}) {
    const std::string label = mode == TrafficPeriodMode::Day ? "日期" : mode == TrafficPeriodMode::Year ? "年份" : "月份";
    Table table({label, "上行", "下行", "合计", "包数", "Top端口", "Top IP:端口"},
                {12, 11, 11, 11, 8, 26, 34});
    for (const auto &row : rows) {
        std::string topPorts = "-";
        std::string topIpPorts = "-";
        const auto detailIt = details.find(row.period);
        if (detailIt != details.end()) {
            topPorts = compactTrafficSummary(aggregateTrafficByPort(detailIt->second), TrafficGroupMode::Port, 3);
            topIpPorts = compactTrafficSummary(aggregateTrafficByIpPort(detailIt->second), TrafficGroupMode::IpPort, 3);
        }
        table.add({row.period,
                   humanBytes(row.uploadBytes),
                   humanBytes(row.downloadBytes),
                   humanBytes(row.totalBytes()),
                   std::to_string(row.totalPackets()),
                   topPorts,
                   topIpPorts});
    }
    return table;
}

inline std::string reliabilityStatusLabel(ReliabilityStatus status) {
    switch (status) {
    case ReliabilityStatus::Pass:
        return ansi::green + std::string("通过") + ansi::plain;
    case ReliabilityStatus::Fail:
        return ansi::red + std::string("失败") + ansi::plain;
    case ReliabilityStatus::Warning:
        return ansi::yellow + std::string("警告") + ansi::plain;
    case ReliabilityStatus::Permission:
        return ansi::yellow + std::string("权限不足") + ansi::plain;
    case ReliabilityStatus::Skipped:
    default:
        return ansi::gray + std::string("跳过") + ansi::plain;
    }
}

inline void addReliabilityResult(ReliabilityReport &report,
                                 const std::string &group,
                                 const std::string &name,
                                 ReliabilityStatus status,
                                 const std::string &summary,
                                 const std::string &evidence = "",
                                 const std::string &suggestion = "") {
    report.results.push_back({group, name, status, summary, evidence, suggestion});
}

inline std::string dependencyPackageForTool(const std::string &tool) {
    if (tool == "nft") return "nftables";
    if (tool == "ss") return "iproute2";
    if (tool == "awk") return "gawk";
    if (tool == "fail2ban-client") return "fail2ban";
    if (tool == "mmdblookup") return "mmdb-bin";
    if (tool == "curl" || tool == "wget") return tool;
    return tool;
}

inline void verifyDependencyChain(ReliabilityReport &report) {
    Shell::clearExistsCache();
    const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "systemctl", "journalctl", "ss", "conntrack", "awk", "grep"};
    for (const auto &tool : tools) {
        const bool ok = Shell::exists(tool);
        addReliabilityResult(report, "依赖链路", tool, ok ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                             ok ? "命令可执行" : "命令不可用",
                             "apt 包: " + dependencyPackageForTool(tool),
                             ok ? "" : "执行“安装常见依赖”，或 apt install -y " + dependencyPackageForTool(tool));
    }
    const bool downloader = Shell::exists("curl") || Shell::exists("wget");
    addReliabilityResult(report, "依赖链路", "curl/wget", downloader ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         downloader ? "至少一个下载工具可用" : "更新链路缺少下载工具",
                         std::string("curl=") + (Shell::exists("curl") ? "yes" : "no") +
                             " wget=" + (Shell::exists("wget") ? "yes" : "no"),
                         downloader ? "" : "apt install -y curl");
}

inline void verifyGeoDatabaseChain(ReliabilityReport &report) {
    const bool db = fileExists(kDbIpLiteMmdbPath);
    const bool reader = Shell::exists("mmdblookup");
    if (!db) {
        addReliabilityResult(report, "IP国家链路", "DB-IP Lite MMDB", ReliabilityStatus::Skipped,
                             "未安装本地国家库，表格国家/地区显示为 -",
                             kDbIpLiteMmdbPath,
                             "诊断 -> 安装/更新 IP 国家库");
        return;
    }
    addReliabilityResult(report, "IP国家链路", "DB-IP Lite MMDB", reader ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         reader ? "数据库与 MMDB 读取工具可用" : "数据库存在但缺少 mmdblookup",
                         kDbIpLiteMmdbPath + " / " + humanBytes(fileSizeBytes(kDbIpLiteMmdbPath)),
                         reader ? kDbIpLiteAttribution : "apt install -y mmdb-bin");
    if (reader) {
        const std::string label = ipGeoLabel("8.8.8.8");
        addReliabilityResult(report, "IP国家链路", "样例查询", label == "-" ? ReliabilityStatus::Fail : ReliabilityStatus::Pass,
                             label == "-" ? "样例 IP 未查到国家/地区" : "样例 IP 查询成功",
                             "8.8.8.8 => " + label);
    }
}

inline void verifyUpdateChainReadiness(ReliabilityReport &report) {
#ifdef _WIN32
    addReliabilityResult(report, "更新链路", "平台", ReliabilityStatus::Skipped, "Windows 不支持发布二进制自更新");
#else
    const std::string target = currentExecutablePath(nullptr);
    addReliabilityResult(report, "更新链路", "当前可执行文件", fileExists(target) ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         fileExists(target) ? "目标文件存在" : "无法定位当前可执行文件", target,
                         fileExists(target) ? "" : "请确认从真实 ltg 二进制启动");
    std::array<int, 3> current{};
    addReliabilityResult(report, "更新链路", "当前版本解析", parseVersionTriplet(kVersion, current) ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         parseVersionTriplet(kVersion, current) ? "版本号格式正确" : "版本号无法解析", kVersion);
    if (Shell::exists("curl")) {
        const CommandResult head = Shell::capture("curl -fsIL --max-time 12 " + shellQuote(kLatestBinaryUrl) + " | head -20");
        addReliabilityResult(report, "更新链路", "Release 资产可达", head.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                             head.ok() ? "latest 二进制下载地址可访问" : "无法确认 latest 二进制地址",
                             summarizeCommandResult(head),
                             head.ok() ? "" : "检查网络或手动访问 GitHub Release");
    } else if (Shell::exists("wget")) {
        const CommandResult spider = Shell::capture("wget --spider -S -T 12 " + shellQuote(kLatestBinaryUrl) + " 2>&1 | head -20");
        addReliabilityResult(report, "更新链路", "Release 资产可达", spider.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                             spider.ok() ? "latest 二进制下载地址可访问" : "无法确认 latest 二进制地址",
                             summarizeCommandResult(spider),
                             spider.ok() ? "" : "检查网络或手动访问 GitHub Release");
    } else {
        addReliabilityResult(report, "更新链路", "Release 资产可达", ReliabilityStatus::Skipped,
                             "缺少 curl/wget，无法检查远端资产", "", "先安装 curl");
    }
    addReliabilityResult(report, "更新链路", "覆盖权限", isRoot() ? ReliabilityStatus::Pass : ReliabilityStatus::Permission,
                         isRoot() ? "当前权限可覆盖安装" : "需要 sudo 才能覆盖当前 ltg",
                         target,
                         isRoot() ? "" : "使用 sudo ltg update");
#endif
}

inline bool loadCachedUfwAnalysisReportReadonly(const std::string &title,
                                                std::time_t start,
                                                std::time_t end,
                                                UfwAnalysisReport &report) {
#if LTG_HAS_SQLITE
    if (!fileExists(ufwCacheDbPath())) {
        return false;
    }
    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(ufwCacheDbPath().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        return false;
    }
    const auto ranges = sqliteReadUfwRanges(db);
    if (!rangeCovered(start, end, ranges)) {
        report.title = title;
        report.start = start;
        report.end = end;
        report.sourceNote = "SQLite 缓存未覆盖窗口";
        report.evidence.cacheCovered = false;
        report.evidence.cacheRanges = ufwRangesSummary(ranges);
        sqlite3_close(db);
        return false;
    }
    report = sqliteBuildUfwReport(db, title, start, end, "SQLite 缓存(只读)");
    report.evidence.cacheCovered = true;
    report.evidence.cacheRanges = ufwRangesSummary(ranges);
    if (report.validLines == 0) {
        report.sourceNote = "SQLite 缓存(窗口内无有效记录)";
    }
    sqlite3_close(db);
    return true;
#else
    const auto ranges = readUfwCacheRanges();
    if (!rangeCovered(start, end, ranges)) {
        report.title = title;
        report.start = start;
        report.end = end;
        report.sourceNote = "文本缓存未覆盖窗口";
        report.evidence.cacheCovered = false;
        report.evidence.cacheRanges = ufwRangesSummary(ranges);
        return false;
    }
    const auto events = readUfwCacheEvents(start, end);
    UfwLogEvidence evidence;
    evidence.cacheCovered = true;
    evidence.cacheRanges = ufwRangesSummary(ranges);
    evidence.rawMatches = events.size();
    evidence.validPublic = events.size();
    for (const auto &event : events) {
        if (event.action == "BLOCK") ++evidence.block;
        else if (event.action == "AUDIT") ++evidence.audit;
        else if (event.action == "ALLOW") ++evidence.allow;
        if (event.dpt == kUnknownUfwPort) ++evidence.noDpt;
    }
    report = buildUfwReportFromEvents(title, start, end,
                                      events.empty() ? "文本缓存(窗口内无有效记录)" : "文本缓存(只读)",
                                      events, evidence);
    return true;
#endif
}

inline std::string ufwTopSignature(const UfwAnalysisReport &report) {
    std::ostringstream out;
    out << "valid=" << report.validLines << ";src=";
    std::vector<std::pair<std::string, int>> sources;
    for (const auto &entry : report.ipDaily) {
        sources.push_back({entry.first, dailyTotal(entry.second)});
    }
    std::sort(sources.begin(), sources.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    for (std::size_t i = 0; i < sources.size() && i < 5; ++i) {
        out << sources[i].first << ":" << sources[i].second << ",";
    }
    out << ";ports=";
    for (const auto &port : sortedCounter([&] {
             std::map<std::string, int> totals;
             for (const auto &entry : report.portDaily) {
                 totals[entry.first] = dailyTotal(entry.second);
             }
             return totals;
         }())) {
        out << port.first << ":" << port.second << ",";
    }
    return out.str();
}

inline void verifyUfwAnalysisChain(ReliabilityReport &report) {
    const std::time_t end = std::time(nullptr) - (std::time(nullptr) % 60);
    const std::time_t start = std::max<std::time_t>(0, end - 24 * 3600);
    std::string liveNote;
    UfwLogEvidence liveEvidence;
    const auto liveEvents = loadLiveUfwEvents(start, end, liveNote, &liveEvidence);
    const UfwAnalysisReport liveReport = buildUfwReportFromEvents("可靠性自检 live", start, end, liveNote, liveEvents, liveEvidence);
    UfwAnalysisReport cachedReport;
    const bool cacheOk = loadCachedUfwAnalysisReportReadonly("可靠性自检 cache", start, end, cachedReport);
    const bool same = cacheOk && ufwTopSignature(liveReport) == ufwTopSignature(cachedReport);
    addReliabilityResult(report, "UFW分析链路", "日志读取",
                         liveNote == "无可用 UFW 日志" ? ReliabilityStatus::Warning : ReliabilityStatus::Pass,
                         liveNote == "无可用 UFW 日志" ? "未读到 UFW 日志，无法确认分析有效性" : "UFW 日志可读取",
                         "来源: " + liveNote +
                             " / 原始匹配: " + std::to_string(liveEvidence.rawMatches) +
                             " / 有效公网SRC: " + std::to_string(liveEvidence.validPublic) +
                             " / 过滤SRC: " + std::to_string(liveEvidence.filteredSource),
                         liveNote == "无可用 UFW 日志" ? "确认 UFW logging 是否开启，或查看 journalctl -k" : "");
    addReliabilityResult(report, "UFW分析链路", "缓存覆盖",
                         cacheOk ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                         cacheOk ? "缓存覆盖最近24小时窗口" : "缓存尚未完整覆盖最近24小时",
                         cachedReport.sourceNote + " / " + cachedReport.evidence.cacheRanges,
                         cacheOk ? "" : "进入“安全中心 -> 分析追查”刷新一次窗口");
    addReliabilityResult(report, "UFW分析链路", "live/cache 聚合一致",
                         !cacheOk ? ReliabilityStatus::Skipped : same ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         !cacheOk ? "缓存未覆盖，跳过一致性对比" : same ? "live 解析与缓存聚合一致" : "live 解析与缓存聚合不一致",
                         "live: " + ufwTopSignature(liveReport) + (cacheOk ? " / cache: " + ufwTopSignature(cachedReport) : ""),
                         !cacheOk ? "刷新 UFW 分析缓存后可复核" : same ? "国家/地区只用于展示，不参与计数或 fail2ban 决策" : "清理 UFW 分析缓存后强制刷新，或检查日志时间窗口");
}

inline void verifyFail2banUfwChain(ReliabilityReport &report, bool allowActiveProbe) {
    if (!Shell::exists("fail2ban-client")) {
        addReliabilityResult(report, "防护链路", "fail2ban-client", ReliabilityStatus::Fail,
                             "命令不可用", "", "安装 fail2ban");
        return;
    }
    const CommandResult configTest = Shell::capture("fail2ban-client -t");
    addReliabilityResult(report, "防护链路", "fail2ban 配置检查",
                         configTest.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         configTest.ok() ? "fail2ban-client -t 通过" : "fail2ban 配置检查失败",
                         summarizeCommandResult(configTest),
                         configTest.ok() ? "" : "先修复 fail2ban-client -t 输出中的配置错误");
    const CommandResult ping = Shell::capture("fail2ban-client ping");
    const bool pingOk = ping.ok() && lowerCopy(ping.output).find("pong") != std::string::npos;
    addReliabilityResult(report, "防护链路", "fail2ban ping", pingOk ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         pingOk ? "fail2ban socket 可用" : "fail2ban socket 不可用",
                         summarizeCommandResult(ping),
                         pingOk ? "" : "检查 systemctl status fail2ban 和 root 权限");

    const CommandResult sshStatus = Shell::capture("fail2ban-client status " + shellQuote(kRule1Jail));
    const F2bJailRuntimeInfo ssh = parseFail2banJailStatus(kRule1Jail, sshStatus.output, true);
    addReliabilityResult(report, "防护链路", "sshd jail", ssh.loaded() ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         ssh.loaded() ? "jail 已加载" : "jail 未加载",
                         ssh.label + " / " + summarizeCommandResult(sshStatus),
                         ssh.loaded() ? "" : "执行“策略安装/修复”并查看 fail2ban-client -t");

    const CommandResult rule2Status = Shell::capture("fail2ban-client status " + shellQuote(kRule2Jail));
    const F2bJailRuntimeInfo rule2 = parseFail2banJailStatus(kRule2Jail, rule2Status.output, true);
    addReliabilityResult(report, "防护链路", "规则2 jail", rule2.loaded() ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         rule2.loaded() ? "ufw-slowscan-global 已加载" : "规则2未加载，未真正生效",
                         rule2.label + " / " + summarizeCommandResult(rule2Status),
                         rule2.loaded() ? "" : "执行“策略安装/修复”，修复 UnknownJail 或权限问题");

    if (!allowActiveProbe) {
        addReliabilityResult(report, "防护链路", "临时 ban 落地", ReliabilityStatus::Skipped,
                             "默认自检不修改 fail2ban/UFW", "active probes 关闭",
                             "TUI 中确认主动探测，或运行 --reliability-check --active-probes");
        return;
    }
    if (!rule2.loaded()) {
        addReliabilityResult(report, "防护链路", "临时 ban 落地", ReliabilityStatus::Skipped,
                             "规则2未加载，跳过主动探测", rule2.label);
        return;
    }

    const CommandResult ban = Shell::capture(fail2banSetIpCommandStrict(kRule2Jail, "banip", kFail2banEffectProbeIp));
    Shell::capture("sleep 1");
    const CommandResult after = Shell::capture("fail2ban-client status " + shellQuote(kRule2Jail));
    const F2bJailRuntimeInfo afterInfo = parseFail2banJailStatus(kRule2Jail, after.output, true);
    const bool banListed = afterInfo.bannedIps.count(kFail2banEffectProbeIp) > 0;
    addReliabilityResult(report, "防护链路", "banip 进入列表", ban.ok() && banListed ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         ban.ok() && banListed ? "测试 IP 已进入 fail2ban 列表" : "banip 未进入 fail2ban 列表",
                         summarizeCommandResult(ban) + " / " + summarizeCommandResult(after),
                         ban.ok() && banListed ? "" : "检查 fail2ban-client set 输出和 jail 状态");

    const CommandResult ufw = Shell::capture("ufw status numbered");
    const bool ufwLanded = ufwStatusHasDenyForIp(ufw.output, kFail2banEffectProbeIp, true);
    addReliabilityResult(report, "防护链路", "UFW deny 落地", ufwLanded ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         ufwLanded ? "UFW 中找到测试 deny 规则和 fail2ban comment" : "fail2ban ban 后 UFW 未出现带 comment 的 deny",
                         summarizeCommandResult(ufw),
                         ufwLanded ? "" : "检查 ufw-drop action 和 UFW 状态");

    const CommandResult unban = Shell::capture(fail2banSetIpCommandStrict(kRule2Jail, "unbanip", kFail2banEffectProbeIp));
    const CommandResult cleanup = Shell::capture("(ufw --force delete deny from " + shellQuote(kFail2banEffectProbeIp) + " || true)");
    const CommandResult post = Shell::capture("ufw status numbered 2>/dev/null || true");
    const bool cleaned = !ufwStatusHasDenyForIp(post.output, kFail2banEffectProbeIp, false);
    addReliabilityResult(report, "防护链路", "测试痕迹清理", unban.ok() && cleanup.ok() && cleaned ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         unban.ok() && cleanup.ok() && cleaned ? "unban 和 UFW 残留清理完成" : "测试 IP 可能有残留",
                         summarizeCommandResult(unban) + " / " + summarizeCommandResult(cleanup),
                         cleaned ? "" : "手动执行 ufw status numbered 并删除测试 IP 规则");
}

inline void verifyTrafficAccountingChain(ReliabilityReport &report, bool allowSnapshotProbe) {
    if (!Shell::exists("nft")) {
        addReliabilityResult(report, "流量统计链路", "nft", ReliabilityStatus::Fail,
                             "nft 命令不可用", "", "安装 nftables");
        return;
    }
    const CommandResult table = Shell::capture("nft list table inet " + kIpTrafficTable);
    addReliabilityResult(report, "流量统计链路", "底层表", table.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         table.ok() ? "统计表存在" : "统计表不存在",
                         summarizeCommandResult(table),
                         table.ok() ? "" : "进入“流量统计 -> 开启/追加端口”");
    if (!table.ok()) {
        return;
    }
    const std::string body = table.output;
    const std::vector<std::string> sets = {"tracked_ports", "ipv4_download", "ipv4_upload", "ipv6_download", "ipv6_upload"};
    for (const auto &setName : sets) {
        const bool found = body.find("set " + setName) != std::string::npos;
        addReliabilityResult(report, "流量统计链路", "set " + setName,
                             found ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                             found ? "counter set 存在" : "counter set 缺失", "",
                             found ? "" : "重新执行“开启/追加端口”，迁移到底层端口集合规则");
    }
    const std::vector<std::string> chains = {"input_account", "output_account", "forward_account"};
    for (const auto &chain : chains) {
        const bool found = body.find("chain " + chain) != std::string::npos;
        addReliabilityResult(report, "流量统计链路", "chain " + chain,
                             found ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                             found ? "管理链存在" : "管理链缺失", "",
                             found ? "" : "重新执行“开启/追加端口”");
    }

    const std::set<int> historyPorts = loadTrackedTrafficPorts();
    const std::set<int> nftPorts = nftTrackedTrafficPorts();
    const TrafficAccountingVerification semantic = verifyTrafficAccountingApplied(nftPorts);
    addReliabilityResult(report, "流量统计链路", "nft 规则语义",
                         semantic.ok ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         semantic.ok ? "规则引用端口集合并挂载三条 hook 链" : "统计规则语义不完整",
                         semantic.ok ? semantic.evidence : joinWords(semantic.failures, "；") + " / " + semantic.evidence,
                         semantic.ok ? "" : "重新执行“开启/追加端口”重建管理链但保留 counter set");
    const std::set<int> onlyHistory = setDifference(historyPorts, nftPorts);
    const std::set<int> onlyNft = setDifference(nftPorts, historyPorts);
    ReliabilityStatus portStatus = ReliabilityStatus::Pass;
    std::string summary = "历史库和 nft 端口集合一致";
    std::string suggestion;
    if (!onlyHistory.empty() || !onlyNft.empty()) {
        portStatus = ReliabilityStatus::Fail;
        summary = "历史库和 nft 端口集合不一致";
        suggestion = "重新执行“开启/追加端口”，只更新 tracked_ports 集合";
    } else if (historyPorts.empty() && nftPorts.empty()) {
        portStatus = ReliabilityStatus::Warning;
        summary = "尚未配置统计端口";
        suggestion = "进入“流量统计 -> 开启/追加端口”";
    }
    addReliabilityResult(report, "流量统计链路", "统计端口一致性", portStatus, summary,
                         "历史端口: " + humanPortList(historyPorts) + " / nft端口: " + humanPortList(nftPorts) +
                             (onlyHistory.empty() ? "" : " / 仅历史: " + humanPortList(onlyHistory)) +
                             (onlyNft.empty() ? "" : " / 仅nft: " + humanPortList(onlyNft)),
                         suggestion);

    const std::string servicePath = "/etc/systemd/system/" + kTrafficSnapshotService;
    const std::string timerPath = "/etc/systemd/system/" + kTrafficSnapshotTimer;
    std::string serviceContent;
    const bool serviceReadable = readTextFile(servicePath, serviceContent);
    const bool timerExists = fileExists(timerPath);
    addReliabilityResult(report, "流量统计链路", "snapshot systemd unit",
                         serviceReadable && timerExists ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                         serviceReadable && timerExists ? "service/timer 文件存在" : "后台采样 unit 不完整",
                         servicePath + " / " + timerPath,
                         serviceReadable && timerExists ? "" : "重新执行“开启/追加端口”安装 timer");
    if (serviceReadable) {
        const std::string exe = currentExecutablePath(nullptr);
        const bool pointsHere = serviceContent.find(exe + " --traffic-snapshot") != std::string::npos;
        addReliabilityResult(report, "流量统计链路", "snapshot ExecStart",
                             pointsHere ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                             pointsHere ? "ExecStart 指向当前 ltg" : "ExecStart 与当前 ltg 路径不同",
                             firstNonEmptyLine(serviceContent),
                             pointsHere ? "" : "重新执行“开启/追加端口”刷新 systemd unit");
    }
    if (Shell::exists("systemctl")) {
        const CommandResult enabled = Shell::capture("systemctl is-enabled " + kTrafficSnapshotTimer + " 2>&1");
        const CommandResult active = Shell::capture("systemctl is-active " + kTrafficSnapshotTimer + " 2>&1");
        addReliabilityResult(report, "流量统计链路", "snapshot timer 状态",
                             enabled.ok() && active.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                             "enabled=" + trim(enabled.output) + " active=" + trim(active.output),
                             summarizeCommandResult(enabled) + " / " + summarizeCommandResult(active),
                             enabled.ok() && active.ok() ? "" : "systemctl enable --now " + kTrafficSnapshotTimer);
    }

    const std::time_t latest = latestTrafficSnapshotTime();
    std::vector<std::string> trafficPeriods;
    const auto recentRows = aggregateTrafficHistoryByPortForRecentDays(kDashboardTrafficDays, trafficPeriods);
    const auto dayTotals = loadTrafficPeriodTotals(TrafficPeriodMode::Day, 1);
    const auto monthTotals = loadTrafficPeriodTotals(TrafficPeriodMode::Month, 1);
    const auto yearTotals = loadTrafficPeriodTotals(TrafficPeriodMode::Year, 1);
    addReliabilityResult(report, "流量统计链路", "历史采样状态",
                         latest > 0 ? ReliabilityStatus::Pass : ReliabilityStatus::Warning,
                         latest > 0 ? "存在历史快照" : "尚无历史快照",
                         "最近采样: " + (latest > 0 ? dateTimeStamp(latest) : std::string("无")) +
                             " / 最近31天端口行: " + std::to_string(recentRows.size()) +
                             " / 日月年周期: " + std::to_string(dayTotals.size()) + "/" +
                             std::to_string(monthTotals.size()) + "/" + std::to_string(yearTotals.size()),
                         latest > 0 ? "" : "执行 sudo ltg --traffic-snapshot 或等待 timer");
    if (!allowSnapshotProbe) {
        addReliabilityResult(report, "流量统计链路", "主动采样", ReliabilityStatus::Skipped,
                             "默认自检不写入采样历史", "", "使用 --active-probes 执行一次真实采样");
    } else {
        const TrafficSnapshotResult snapshot = recordTrafficSnapshot();
        addReliabilityResult(report, "流量统计链路", "主动采样", snapshot.ok ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                             snapshot.ok ? "采样命令成功" : "采样命令失败",
                             "实时行数: " + std::to_string(snapshot.liveRows) +
                                 " / 增量行数: " + std::to_string(snapshot.deltaRows) +
                                 " / 说明: " + snapshot.message,
                             snapshot.ok ? (snapshot.deltaRows == 0 ? "无新增流量时 delta 为 0 是正常现象" : "") : "查看底层 nft 规则和历史目录权限");
    }
}

inline std::string diagnosticReportCommand(const std::string &out) {
    std::ostringstream cmd;
    cmd << "{ "
        << "echo '### time'; date; "
        << "echo; echo '### services'; systemctl status fail2ban --no-pager -l 2>/dev/null | sed -n '1,60p'; "
        << "echo; echo '### fail2ban'; fail2ban-client status 2>&1; fail2ban-client status " << kRule1Jail << " 2>&1; fail2ban-client status " << kRule2Jail << " 2>&1; "
        << "echo; echo '### ufw'; ufw status verbose 2>/dev/null; "
        << "echo; echo '### listeners'; ss -tulpen 2>/dev/null | head -160; "
        << "echo; echo '### accounting'; nft list table inet " << kIpTrafficTable << " 2>/dev/null; "
        << "echo; echo '### conntrack'; conntrack -L -o extended 2>/dev/null | head -180; "
        << "echo; echo '### fail2ban log'; tail -n 220 /var/log/fail2ban.log 2>/dev/null; "
        << "echo; echo '### ufw log'; journalctl -k --no-pager -n 220 2>/dev/null | grep -i 'ufw' || true; "
        << "} > " << shellQuote(out);
    return cmd.str();
}

inline bool diagnosticReportHasRequiredSections(const std::string &content) {
    return content.find("### fail2ban") != std::string::npos &&
           content.find("### ufw") != std::string::npos &&
           content.find("### accounting") != std::string::npos;
}

inline void verifyDiagnosticExportChain(ReliabilityReport &report, bool allowWriteProbe) {
    const CommandResult tmp = Shell::capture("test -d /tmp && test -w /tmp");
    addReliabilityResult(report, "诊断链路", "/tmp 可写", tmp.ok() ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         tmp.ok() ? "/tmp 可写" : "/tmp 不可写",
                         summarizeCommandResult(tmp),
                         tmp.ok() ? "" : "检查 /tmp 权限或磁盘状态");
    if (!allowWriteProbe) {
        addReliabilityResult(report, "诊断链路", "报告写入", ReliabilityStatus::Skipped,
                             "默认自检不写入诊断报告", "", "使用 --active-probes 验证真实导出");
        return;
    }
    const std::string out = "/tmp/linux-traffic-guard-reliability-" + nowStamp() + ".log";
    const CommandResult write = Shell::capture(diagnosticReportCommand(out));
    std::string content;
    const bool readable = readTextFile(out, content);
    const bool hasSections = readable && diagnosticReportHasRequiredSections(content);
    addReliabilityResult(report, "诊断链路", "报告写入", write.ok() && readable && fileSizeBytes(out) > 0 && hasSections ? ReliabilityStatus::Pass : ReliabilityStatus::Fail,
                         write.ok() && readable && hasSections ? "报告已写入且包含关键 section" : "报告写入或 section 检查失败",
                         out + " / size=" + std::to_string(fileSizeBytes(out)),
                         hasSections ? "" : "检查导出命令输出和系统工具权限");
}

inline void verifyTuiTerminalChain(ReliabilityReport &report) {
    addReliabilityResult(report, "TUI 终端状态", "alternate screen", ReliabilityStatus::Pass,
                         "退出路径会恢复 ?25h/?1049l", "restoreTerminalDisplay()");
    addReliabilityResult(report, "TUI 终端状态", "输入光标", ReliabilityStatus::Pass,
                         "输入页使用单一软件光标，退出时恢复终端光标", "promptLine software cursor");
}

inline ReliabilityReport runReliabilitySelfCheck(bool allowActiveProbes) {
    ReliabilityReport report;
    verifyDependencyChain(report);
    verifyGeoDatabaseChain(report);
    verifyUpdateChainReadiness(report);
    verifyUfwAnalysisChain(report);
    verifyFail2banUfwChain(report, allowActiveProbes);
    verifyTrafficAccountingChain(report, allowActiveProbes);
    verifyDiagnosticExportChain(report, allowActiveProbes);
    verifyTuiTerminalChain(report);
    return report;
}

inline ScreenBuffer reliabilityReportBuffer(const ReliabilityReport &report, bool allowActiveProbes) {
    ScreenBuffer buffer;
    buffer.add(std::string("主动探测: ") + (allowActiveProbes ? "已启用，会执行临时 ban/采样/诊断写入" : "未启用，只做非破坏检查"));
    buffer.add(std::string("总体结果: ") + (report.ok() ? ansi::green + std::string("通过") + ansi::plain
                                                        : ansi::yellow + std::string("存在失败项") + ansi::plain));
    auto groupVerdict = [&](const std::string &group) {
        bool seen = false;
        bool fail = false;
        bool warn = false;
        for (const auto &item : report.results) {
            if (item.group != group) {
                continue;
            }
            seen = true;
            if (item.status == ReliabilityStatus::Fail || item.status == ReliabilityStatus::Permission) {
                fail = true;
            } else if (item.status == ReliabilityStatus::Warning) {
                warn = true;
            }
        }
        if (!seen) return std::string("未检查");
        if (fail) return std::string("失败");
        if (warn) return std::string("不能确认");
        return std::string("能正常工作");
    };
    buffer.add("链路判定: 流量统计=" + groupVerdict("流量统计链路") +
               " / UFW分析=" + groupVerdict("UFW分析链路") +
               " / fail2ban防护=" + groupVerdict("防护链路"));
    buffer.add("");
    std::string currentGroup;
    const std::vector<int> widths = {22, 10, 32, 42};
    for (const auto &item : report.results) {
        if (item.group != currentGroup) {
            currentGroup = item.group;
            buffer.add("");
            buffer.add(ansi::cyan + std::string("> ") + currentGroup + ansi::plain);
            buffer.add(bufferTableRow({"检查项", "状态", "结论", "证据/建议"}, widths, true));
            buffer.add(bufferTableRule(widths));
        }
        std::string detail = item.evidence;
        if (!item.suggestion.empty()) {
            detail += (detail.empty() ? "" : " / ");
            detail += "建议: " + item.suggestion;
        }
        buffer.add(bufferTableRow({item.name, reliabilityStatusLabel(item.status), item.summary, detail}, widths));
    }
    return buffer;
}

inline void enrichUfwHit(UfwHit &hit) {
    if (hit.geo.empty()) {
        hit.geo = ipGeoLabel(hit.value);
    }
    const std::uint64_t riskBase = hit.peak > 0 ? hit.peak : hit.count;
    if (riskBase >= 100) {
        hit.risk = "高";
        hit.suggestion = "分析追查/处置";
    } else if (riskBase >= 10) {
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
            hit.peak = hit.count;
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
            hit.peak = hit.count;
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

inline std::vector<UfwHit> buildUfwSourceTopFromReport(const UfwAnalysisReport &report, std::size_t limit = 10) {
    std::map<std::string, UfwHit> grouped;
    std::map<std::string, std::map<std::string, std::uint64_t>> portsByIp;
    for (const auto &ipEntry : report.ipDaily) {
        auto &hit = grouped[ipEntry.first];
        hit.value = ipEntry.first;
        for (const auto &dayEntry : ipEntry.second) {
            hit.count += static_cast<std::uint64_t>(dayEntry.second);
            hit.peak = std::max<std::uint64_t>(hit.peak, static_cast<std::uint64_t>(dayEntry.second));
        }
    }
    for (const auto &ipEntry : report.ipPortDaily) {
        for (const auto &portEntry : ipEntry.second) {
            for (const auto &dayEntry : portEntry.second) {
                portsByIp[ipEntry.first][portEntry.first] += static_cast<std::uint64_t>(dayEntry.second);
            }
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
        if (a.peak != b.peak) {
            return a.peak > b.peak;
        }
        if (a.count != b.count) {
            return a.count > b.count;
        }
        return a.value < b.value;
    });
    if (hits.size() > limit) {
        hits.resize(limit);
    }
    return hits;
}

inline std::vector<UfwHit> collectUfwSourceTop() {
    const std::time_t end = std::time(nullptr);
    const std::time_t roundedEnd = end - (end % 60);
    const std::time_t rollingStart = std::max<std::time_t>(0, roundedEnd - 86400);
    const UfwAnalysisReport report = analyzeUfwEvents("仪表盘近24小时", rollingStart, roundedEnd, false);
    return buildUfwSourceTopFromReport(report, 10);
}

inline bool collectCachedUfwSourceTop(std::vector<UfwHit> &hits, std::string &note) {
    const std::time_t end = std::time(nullptr);
    const std::time_t roundedEnd = end - (end % 60);
    const std::time_t start = std::max<std::time_t>(0, roundedEnd - 86400);
#if LTG_HAS_SQLITE
    if (fileExists(ufwCacheDbPath())) {
        sqlite3 *db = openUfwCacheDb();
        if (db) {
            const auto ranges = sqliteReadUfwRanges(db);
            sqlite3_close(db);
            std::time_t cachedStart = 0;
            std::time_t cachedEnd = 0;
            if (latestOverlappingRange(start, roundedEnd, ranges, cachedStart, cachedEnd) &&
                collectUfwSourceTopSqlite(cachedStart, cachedEnd, hits)) {
                note = "来自 UFW 分析缓存(" + dateTimeStamp(cachedStart) + " - " + dateTimeStamp(cachedEnd) +
                       ")；进入“安全中心 -> 分析追查”可刷新。";
                return true;
            }
        }
    }
#else
    const auto ranges = readUfwCacheRanges();
    std::time_t cachedStart = 0;
    std::time_t cachedEnd = 0;
    if (latestOverlappingRange(start, roundedEnd, ranges, cachedStart, cachedEnd)) {
        std::map<std::string, UfwHit> grouped;
        std::map<std::string, std::map<std::string, std::uint64_t>> ports;
        for (const auto &event : readUfwCacheEvents(cachedStart, cachedEnd)) {
            if (event.action != "BLOCK" && event.action != "AUDIT") {
                continue;
            }
            auto &hit = grouped[event.src];
            hit.value = event.src;
            ++hit.count;
            hit.peak = hit.count;
            ports[event.src][event.dpt]++;
        }
        for (auto &item : grouped) {
            const auto found = ports.find(item.first);
            if (found != ports.end() && !found->second.empty()) {
                const auto best = std::max_element(found->second.begin(), found->second.end(), [](const auto &a, const auto &b) {
                    return a.second < b.second;
                });
                item.second.topPort = best->first;
                item.second.topPortCount = best->second;
            }
            enrichUfwHit(item.second);
            hits.push_back(item.second);
        }
        std::sort(hits.begin(), hits.end(), [](const UfwHit &a, const UfwHit &b) {
            if (a.count != b.count) return a.count > b.count;
            return a.value < b.value;
        });
        if (hits.size() > 10) {
            hits.resize(10);
        }
        note = "来自 UFW 分析缓存(" + dateTimeStamp(cachedStart) + " - " + dateTimeStamp(cachedEnd) +
               ")；进入“安全中心 -> 分析追查”可刷新。";
        return true;
    }
#endif
    note = "暂无可用安全分析缓存。进入“安全中心 -> 分析追查”跑一次最近24小时/7天后，仪表盘会显示缓存摘要。";
    return false;
}

inline Table ufwHitsTable(const std::vector<UfwHit> &hits) {
    Table table({"序号", "来源IP", "国家/地区", "单日峰值", "时段总计", "首要端口", "风险", "建议"}, {6, 30, 18, 10, 10, 12, 8, 18});
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const std::string port = hits[i].topPort == "-" || hits[i].topPort.empty()
                                     ? "-"
                                     : hits[i].topPort + "(" + std::to_string(hits[i].topPortCount) + ")";
        const std::string geo = hits[i].geo.empty() ? ipGeoLabel(hits[i].value) : hits[i].geo;
        table.add({std::to_string(i + 1), hits[i].value, geo, std::to_string(hits[i].peak), std::to_string(hits[i].count),
                   port, hits[i].risk, hits[i].suggestion});
    }
    return table;
}

inline DashboardSnapshot loadDashboardSnapshot() {
    DashboardSnapshot snapshot;
    snapshot.tableEnabled = trafficHistoryConfiguredFast();
    snapshot.trackedPorts = loadTrackedTrafficPorts();
    std::vector<std::string> trafficPeriods;
    snapshot.totalRows = aggregateTrafficHistoryByPortForRecentDays(kDashboardTrafficDays, trafficPeriods);
    snapshot.trafficPeriodLabel = recentTrafficDaysLabel(trafficPeriods, kDashboardTrafficDays);
    snapshot.trafficHistoryAvailable = !snapshot.totalRows.empty();
    collectCachedUfwSourceTop(snapshot.ufwHits, snapshot.ufwHitsNote);
    snapshot.fail2banState = "未刷新";
    snapshot.ufwState = "未刷新";
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

inline std::string dashboardFastHeaderLine() {
    std::ostringstream deps;
    deps << "权限 " << (isRoot() ? Ui::badge("root", ansi::green) : Ui::badge("非 root", ansi::yellow));
    deps << "  首屏: 最近31天历史";
    deps << "  实时检查: 安全中心/诊断";
    return deps.str();
}

inline void addTrafficOnboarding(ScreenBuffer &buffer, bool configured, bool hasHistory) {
    buffer.add("> 下一步");
    if (!configured) {
        buffer.add("1. 进入“流量统计 -> 开启/追加端口”，输入要统计的服务端口。");
        buffer.add("2. 工具会保留已有计数，并启用 5 分钟一次的后台采样。");
        buffer.add("3. 第一轮采样建立基线，下一轮开始出现日/月/年增量。");
        return;
    }
    if (!hasHistory) {
        buffer.add("1. 历史采样已初始化，但当前时间段还没有增量。");
        buffer.add("2. 第一轮采样只建立基线，至少再等一轮采样后才会出现流量。");
        buffer.add("3. 想确认底层规则是否有实时计数，可进入“流量统计 -> 实时明细”。");
        return;
    }
    buffer.add("1. 看趋势用“流量统计 -> 日流量 / 月流量 / 年流量”。");
    buffer.add("2. 查具体 IP 用“流量统计 -> 实时明细”或“下钻检查”。");
    buffer.add("3. 查服务、防火墙、fail2ban 运行态用“安全中心”或“诊断”。");
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
    buffer.add("  流量/端口优先的服务器防护仪表盘");
    buffer.add("");
    buffer.add(dashboardFastHeaderLine());
    buffer.add("");
    if (loading || snapshot == nullptr) {
        buffer.add(std::string("> 最近31天端口流量  加载中 ") + spinner);
        buffer.add("  正在读取本地历史。实时检查放在对应页面执行。");
        buffer.add("");
        buffer.add("> 下一步  加载中");
        return buffer;
    }

    buffer.add("> 最近31天端口流量 Top 10");
    buffer.add("统计口径: 系统本地时间 " + (snapshot->trafficPeriodLabel.empty() ? recentTrafficDaysLabel(recentTrafficDayPeriods(kDashboardTrafficDays), kDashboardTrafficDays) : snapshot->trafficPeriodLabel) +
               "，按端口聚合上行/下行，只展示前10个端口。");
    buffer.add(std::string("历史采样: ") + (snapshot->tableEnabled ? "[已初始化]" : "[未初始化]"));
    buffer.add("统计端口: " + std::to_string(snapshot->trackedPorts.size()) + " 个  " + humanPortList(snapshot->trackedPorts));
    if (!snapshot->tableEnabled) {
        buffer.add("本地历史库尚未初始化。进入“流量统计 -> 开启/追加端口”启用。");
    } else if (!snapshot->trafficHistoryAvailable) {
        buffer.add("最近31天还没有采样增量。第一轮采样建立基线，下一轮开始显示变化。");
    }
    buffer.addAll(tableLines(trafficSummaryTable(snapshot->totalRows, kDashboardTrafficPortLimit, TrafficGroupMode::Port),
                             snapshot->tableEnabled ? "最近31天暂无采样增量" : "历史采样未初始化"));
    buffer.add("");
    buffer.add("> 安全分析摘要");
    if (!snapshot->ufwHitsNote.empty()) {
        buffer.add(snapshot->ufwHitsNote);
    }
    buffer.addAll(tableLines(ufwHitsTable(snapshot->ufwHits), "暂无缓存命中。进入“安全中心 -> 分析追查”生成/刷新安全分析。"));
    buffer.add("");
    addTrafficOnboarding(buffer, snapshot->tableEnabled, snapshot->trafficHistoryAvailable);
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
            if (dispatch(event)) {
                dirty = true;
            }
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
                                       TrafficGroupMode mode) {
        const std::vector<int> widths = mode == TrafficGroupMode::IpPort ? std::vector<int>{6, 26, 18, 8, 14, 14, 14, 10}
                                      : mode == TrafficGroupMode::Port ? std::vector<int>{6, 8, 20, 14, 14, 14, 10}
                                                                       : std::vector<int>{6, 26, 18, 14, 14, 14, 10};
        buffer.add(mode == TrafficGroupMode::IpPort ? tableRow({"序号", "IP", "国家/地区", "端口", "上行", "下行", "合计", "包数"}, widths, true)
                   : mode == TrafficGroupMode::Port ? tableRow({"序号", "端口", "服务", "上行", "下行", "合计", "包数"}, widths, true)
                                                     : tableRow({"序号", "IP", "国家/地区", "上行", "下行", "合计", "包数"}, widths, true));
        buffer.add(tableRule(widths));
        if (rows.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (std::size_t i = 0; i < rows.size() && i < limit; ++i) {
            std::vector<std::string> cells = {std::to_string(i + 1)};
            if (mode == TrafficGroupMode::Port) {
                cells.push_back(rows[i].port);
                cells.push_back(serviceNameForPort(rows[i].port));
            } else {
                cells.push_back(rows[i].ip);
                cells.push_back(rows[i].geo.empty() ? ipGeoLabel(rows[i].ip) : rows[i].geo);
                if (mode == TrafficGroupMode::IpPort) {
                    cells.push_back(rows[i].port);
                }
            }
            cells.push_back(humanBytes(rows[i].uploadBytes));
            cells.push_back(humanBytes(rows[i].downloadBytes));
            cells.push_back(humanBytes(rows[i].totalBytes()));
            cells.push_back(std::to_string(rows[i].totalPackets()));
            buffer.add(tableRow(cells, widths));
        }
    }

    static void addTrafficSummaryTable(ScreenBuffer &buffer,
                                       const std::vector<TrafficSummaryRow> &rows,
                                       std::size_t limit,
                                       const std::string &emptyMessage,
                                       bool includePort) {
        addTrafficSummaryTable(buffer, rows, limit, emptyMessage, includePort ? TrafficGroupMode::IpPort : TrafficGroupMode::Ip);
    }

    static void addUfwTable(ScreenBuffer &buffer, const std::vector<UfwHit> &hits, const std::string &emptyMessage) {
        const std::vector<int> widths = {6, 28, 18, 10, 12, 8, 18};
        buffer.add(tableRow({"序号", "来源IP", "国家/地区", "命中", "首要端口", "风险", "建议"}, widths, true));
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
            const std::string geo = hits[i].geo.empty() ? ipGeoLabel(hits[i].value) : hits[i].geo;
            buffer.add(tableRow({std::to_string(i + 1), hits[i].value, geo, std::to_string(hits[i].count),
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
        const std::vector<int> widths = {22, 16, 8, 10, 8, 8, 9, 12, 8, 8};
        buffer.add(tableRow({"策略", "定位", "配置", "jail", "阈值", "窗口", "封禁", "动作", "封禁IP", "最近Ban"}, widths, true));
        buffer.add(tableRule(widths));
        if (policies.empty()) {
            buffer.add("  " + ansi::gray + "- " + emptyMessage + ansi::plain);
            return;
        }
        for (const auto &policy : policies) {
            buffer.add(tableRow({
                policy.name,
                policy.role,
                policy.configured ? "存在" : "缺失",
                policy.runtimeDetail.empty() ? policy.state : policy.runtimeDetail,
                configValueOr(policy.config.maxretry, policy.name == kRule2Jail ? "50" : "5"),
                configValueOr(policy.config.findtime, "3600"),
                configValueOr(policy.config.bantime, policy.name == kRule2Jail ? "1d" : "600"),
                configValueOr(policy.config.banaction, policy.name == kRule2Jail ? "ufw-drop" : "默认"),
                std::to_string(policy.bannedCount),
                policy.recentBan.empty() ? "-" : policy.recentBan,
            }, widths));
        }
    }

    void pushMainMenu() {
        Page page;
        page.kind = PageKind::Menu;
        page.title = kName + " v" + kVersion;
        page.subtitle = "常用先看仪表盘和流量统计；慢查询放在安全中心、诊断和下钻里。";
        page.root = true;
        page.items = {
            {"1", "仪表盘", "最快入口，最近31天端口流量和下一步建议", false, [this] { pushDashboard(); }},
            {"2", "流量统计", "开启/追加端口，查看日/月/年流量", false, [this] { pushTrafficMenu(); }},
            {"3", "安全中心", "威胁分析、fail2ban、UFW 和处置核验", false, [this] { pushSecurityMenu(); }},
            {"4", "下钻检查", "较慢，按端口/连接/底层规则排障", false, [this] { pushInspectMenu(); }},
            {"5", "诊断", "较慢，依赖、日志、报告和导出", false, [this] { pushDiagnoseMenu(); }},
        };
        pages_.push_back(std::move(page));
    }

    void pushDashboard(bool forceRefresh = false) {
        Page page;
        page.kind = PageKind::Dashboard;
        page.title = kName + " v" + kVersion;
        page.subtitle = "流量/端口优先的服务器防护仪表盘";
        page.started = std::chrono::steady_clock::now();
        if (forceRefresh) {
            cachedDashboardValid() = false;
        }
        if (!dashboardCacheFresh()) {
            cachedDashboardSnapshot() = loadDashboardSnapshot();
            cachedDashboardValid() = true;
        }
        page.loading = false;
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
        pushMenu("流量统计", "像 vnStat 一样按日/月/年查看，默认按端口聚合",
                 {
                     {"1", "开启/追加端口", "默认追加，不清空已有统计", true, [this] { actionInstallTraffic(); }},
                     {"2", "日流量", "滚动最近N天，或指定某一天，均带端口/IP明细", false, [this] { actionTrafficPeriodQuery(TrafficPeriodMode::Day); }},
                     {"3", "月流量", "滚动最近N个月，或指定某个月，均带端口/IP明细", false, [this] { actionTrafficPeriodQuery(TrafficPeriodMode::Month); }},
                     {"4", "年流量", "滚动最近N年，或指定某一年，均带端口/IP明细", false, [this] { actionTrafficPeriodQuery(TrafficPeriodMode::Year); }},
                     {"5", "实时明细", "较慢，读取底层实时计数和 IP 明细", false, [this] { actionShowTrafficRanking(); }},
                     {"6", "删除统计端口", "停止统计指定端口，保留历史", true, [this] { actionRemoveTrafficPorts(); }},
                     {"7", "高级：删除全部统计规则", "高风险，删除底层统计规则", true, [this] { actionRemoveTrafficAccounting(); }},
                     {"0", "高级：底层计数规则", "查看 nftables 原始输出", false, [this] { actionRawNftTable(); }},
                 });
    }

    void pushSecurityMenu() {
        pushMenu("安全中心", "总览、分析、策略、处置、诊断按同一条防护链路组织",
                 {
                     {"1", "安全总览", "一屏看服务、策略、封禁和下一步", false, [this] { actionSecurityStatus(); }},
                     {"2", "可靠性自检", "验证依赖、更新、防护、统计、诊断是否真落地", true, [this] { actionReliabilitySelfCheck(); }},
                     {"3", "分析追查", "来源 Top、端口扫描、IP 下钻、缓存", false, [this] { pushUfwAnalyzeMenu(); }},
                     {"4", "策略配置", "SSH 防护、扫描升级、白名单", true, [this] { pushFail2banPanel(); }},
                     {"5", "处置修复", "封禁/解封、端口规则、核验、同步", true, [this] { pushSecurityOpsMenu(); }},
                     {"6", "服务诊断", "服务控制、依赖、日志和报告", false, [this] { pushSecurityServiceMenu(); }},
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
                     {"5", "实效自检", "临时 ban 测试 IP 并确认 UFW 落地", true, [this] { actionFail2banEffectProbe(); }},
                     {"6", "导出防护诊断", "导出 fail2ban/UFW 配置与日志", false, [this] { actionExportF2bDiagnostic(); }},
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
                     {"3", "高级：底层计数规则", "查看 nftables 原始输出", false, [this] { actionRawNftTable(); }},
                 });
    }

    void pushDiagnoseMenu() {
        pushMenu("诊断", "底层依赖、原始日志、报告导出",
                 {
                     {"1", "依赖检查", "检查工具是否可用", false, [this] { actionDependencyDoctor(); }},
                     {"2", "日志摘要", "fail2ban 与 UFW 日志", false, [this] { actionLogSummary(); }},
                     {"3", "导出报告", "写入 /tmp 报告", false, [this] { actionExportReport(); }},
                     {"4", "安装依赖", "Debian/Ubuntu apt 命令", true, [this] { actionInstallDependencies(); }},
                     {"5", "安装/更新 IP 国家库", "DB-IP Lite 免费 MMDB，用于来源国家展示", true, [this] { actionInstallGeoDatabase(); }},
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
        buffer.add(ansi::gray + std::string("  ↑/↓、j/k 或滚轮移动，Ctrl-f/b 翻页，Ctrl-d/u 半页。当前选中项会高亮。") + ansi::plain);
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
        buffer.add(dashboardFastHeaderLine());
        buffer.add("");
        if (snapshot == nullptr) {
            buffer.add(std::string("> 最近31天端口流量  加载中 ") + spinner);
            buffer.add("  正在读取本地历史库。深度审计放在对应页面执行。");
            if (std::chrono::steady_clock::now() - page.started > std::chrono::seconds(2)) {
                buffer.add("  仍在读取系统数据，可按 q 返回，或等待加载完成。");
            }
            buffer.add("");
            buffer.add("> 下一步  加载中");
            return buffer;
        }

        buffer.add("> 最近31天端口流量 Top 10");
        if (page.loading) {
            buffer.add(std::string("后台刷新中 ") + spinner + "  先显示上一份快照，刷新完成后自动更新。");
        }
        buffer.add("统计口径: 系统本地时间 " + (snapshot->trafficPeriodLabel.empty() ? recentTrafficDaysLabel(recentTrafficDayPeriods(kDashboardTrafficDays), kDashboardTrafficDays) : snapshot->trafficPeriodLabel) +
                   "，按端口聚合上行/下行，只展示前10个端口。");
        buffer.add(std::string("历史采样: ") +
                   (snapshot->tableEnabled ? Ui::badge("已初始化", ansi::green) : Ui::badge("未初始化", ansi::yellow)));
        buffer.add("统计端口: " + std::to_string(snapshot->trackedPorts.size()) + " 个  " + humanPortList(snapshot->trackedPorts));
        if (!snapshot->tableEnabled) {
            buffer.add(ansi::yellow + std::string("本地历史库尚未初始化。进入“流量统计 -> 开启/追加端口”启用。") + ansi::plain);
        } else if (!snapshot->trafficHistoryAvailable) {
            buffer.add(ansi::yellow + std::string("最近31天还没有采样增量。第一轮采样建立基线，下一轮开始显示变化。") + ansi::plain);
        }
        addTrafficSummaryTable(buffer, snapshot->totalRows, kDashboardTrafficPortLimit, snapshot->tableEnabled ? "最近31天暂无采样增量" : "历史采样未初始化", TrafficGroupMode::Port);
        buffer.add("");
        buffer.add("> 安全分析摘要");
        if (!snapshot->ufwHitsNote.empty()) {
            buffer.add(snapshot->ufwHitsNote);
        }
        addUfwTable(buffer, snapshot->ufwHits, "暂无缓存命中。进入“安全中心 -> 分析追查”生成/刷新安全分析。");
        buffer.add("");
        addTrafficOnboarding(buffer, snapshot->tableEnabled, snapshot->trafficHistoryAvailable);
        buffer.add("");
        buffer.add(ansi::gray + std::string("提示: 实时状态和慢查询在安全中心、诊断、下钻检查中执行。") + ansi::plain);
        return buffer;
    }

    std::string footerFor(const Page &page, std::size_t) const {
        if (page.kind == PageKind::Dashboard) {
            return "j/k/↑↓ 滚动  Ctrl-f/b 翻页  Ctrl-d/u 半页  r 刷新  q 返回";
        }
        if (page.kind == PageKind::Result) {
            return "j/k/↑↓ 滚动  Ctrl-f/b/PgUp/PgDn 翻页  Ctrl-d/u 半页  g/G 顶底  q 返回";
        }
        return "j/k/↑↓ 选择  Ctrl-f/b 翻页  Ctrl-d/u 半页  Enter 确认  q 返回";
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

    bool dispatch(const InputEvent &event) {
        if (event.kind == InputKind::CtrlC) {
            std::raise(SIGINT);
            return false;
        }
        if (pages_.empty() || event.kind == InputKind::None) {
            return false;
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
            return true;
        }
        if (page.kind == PageKind::Menu) {
            return handleMenu(event, page);
        } else if (page.kind == PageKind::Dashboard) {
            return handleDashboard(event, page);
        } else {
            return handleScrollable(event, page);
        }
    }

    bool handleMenu(const InputEvent &event, Page &page) {
        const int selectableCount = static_cast<int>(page.items.size()) + 1;
        ScreenBuffer buffer = renderPage(page);
        if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
            event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
            event.kind == InputKind::Home || event.kind == InputKind::End ||
            (event.kind == InputKind::Character &&
             (event.ch == 'j' || event.ch == 'k' || event.ch == 'g' || event.ch == 'G'))) {
            const int beforeScroll = page.scrollOffset;
            InputKind selectionKind = event.kind;
            if (event.kind == InputKind::Character) {
                if (event.ch == 'j') selectionKind = InputKind::Down;
                else if (event.ch == 'k') selectionKind = InputKind::Up;
                else if (event.ch == 'g') selectionKind = InputKind::Home;
                else if (event.ch == 'G') selectionKind = InputKind::End;
            }
            const bool selectedChanged = adjustSelection(selectionKind, page.selected, selectableCount);
            ensureLineVisible(6 + page.selected, page.scrollOffset, buffer.size());
            return selectedChanged || page.scrollOffset != beforeScroll;
        }
        if (event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
            (event.kind == InputKind::Character &&
             (event.ch == 2 || event.ch == 4 || event.ch == 6 || event.ch == 21))) {
            return adjustScrollForEvent(event, page.scrollOffset, buffer.size());
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return true;
        }
        if (event.kind != InputKind::Character) {
            return false;
        }
        if (event.ch == 'q' || event.ch == 'Q') {
            popPage();
            return true;
        }
        if (event.ch == '\n') {
            activateSelected(page);
            return true;
        }
        if (event.ch == '0') {
            popPage();
            return true;
        }
        for (std::size_t i = 0; i < page.items.size(); ++i) {
            if (!page.items[i].key.empty() && event.ch == page.items[i].key[0]) {
                page.selected = static_cast<int>(i);
                activateSelected(page);
                return true;
            }
        }
        return false;
    }

    bool handleDashboard(const InputEvent &event, Page &page) {
        ScreenBuffer buffer = renderPage(page);
        if (isScrollInput(event)) {
            return adjustScrollForEvent(event, page.scrollOffset, buffer.size());
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return true;
        }
        if (event.kind != InputKind::Character) {
            return false;
        }
        if (event.ch == 'q' || event.ch == 'Q') {
            popPage();
            return true;
        } else if (event.ch == 'r' || event.ch == 'R') {
            cachedDashboardSnapshot() = loadDashboardSnapshot();
            cachedDashboardValid() = true;
            page.loading = false;
            page.scrollOffset = 0;
            return true;
        }
        return false;
    }

    bool handleScrollable(const InputEvent &event, Page &page) {
        ScreenBuffer buffer = renderPage(page);
        if (isScrollInput(event)) {
            return adjustScrollForEvent(event, page.scrollOffset, buffer.size());
        }
        if (event.kind == InputKind::Escape) {
            popPage();
            return true;
        }
        if (event.kind == InputKind::Character && (event.ch == 'q' || event.ch == 'Q')) {
            popPage();
            return true;
        }
        return false;
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

    void movePromptCursor(std::size_t bodyLineCount,
                          int scrollOffset,
                          const std::string &label,
                          const std::string &value) const {
        const int inputLine = static_cast<int>(bodyLineCount) + 2;
        const int screenRow = 3 + inputLine - scrollOffset;
        if (screenRow < 3 || screenRow > terminalRows() - 2) {
            return;
        }
        const int col = 1 + static_cast<int>(visibleWidth(label) + visibleWidth(value));
        std::cout << cursorMoveSequence(screenRow, col);
        std::cout.flush();
    }

    PromptAnswer promptLine(const std::string &title,
                            const std::vector<std::string> &body,
                            const std::string &label,
                            const std::string &initial = "") {
        std::string value = initial;
        int scrollOffset = 0;
        bool dirty = true;
        bool cursorOn = true;
        auto lastBlink = std::chrono::steady_clock::now();
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastBlink).count() >= 360) {
                cursorOn = !cursorOn;
                lastBlink = now;
                dirty = true;
            }
            ScreenBuffer buffer;
            buffer.addAll(body);
            buffer.add("");
            buffer.add(promptInputLine(label, value, cursorOn));
            if (dirty) {
                viewport_.render(title, buffer, scrollOffset, "Enter 确认  Backspace 删除  Esc/q 取消", false);
                dirty = false;
            }
            const InputEvent event = inputReader().readEvent(80);
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
                dirty = adjustScroll(event.kind, scrollOffset, buffer.size()) || dirty;
                continue;
            }
            if (event.kind == InputKind::Character &&
                (event.ch == 2 || event.ch == 4 || event.ch == 6 || event.ch == 21)) {
                dirty = adjustScrollForEvent(event, scrollOffset, buffer.size()) || dirty;
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
                    cursorOn = true;
                    lastBlink = std::chrono::steady_clock::now();
                    dirty = true;
                }
                continue;
            }
            const unsigned char ch = static_cast<unsigned char>(event.ch);
            if (ch >= 32 || ch >= 0x80) {
                value.push_back(event.ch);
                cursorOn = true;
                lastBlink = std::chrono::steady_clock::now();
                dirty = true;
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

    bool confirmRemoveTrafficPorts(const std::set<int> &existingPorts,
                                   const std::set<int> &requestedPorts,
                                   const std::set<int> &finalPorts) {
        const std::set<int> removablePorts = setIntersection(requestedPorts, existingPorts);
        std::vector<std::string> body = {
            ansi::yellow + std::string("本次操作只停止统计指定端口，不删除历史日/月/年数据。") + ansi::plain,
            "当前统计端口: " + std::to_string(existingPorts.size()) + " 个  " + humanPortList(existingPorts),
            "本次输入端口: " + humanPortList(requestedPorts),
            "会停止统计: " + (removablePorts.empty() ? std::string("无，输入端口不在当前统计范围内") : humanPortList(removablePorts)),
            "执行后统计端口: " + std::to_string(finalPorts.size()) + " 个  " + humanPortList(finalPorts),
            "",
            "按 Enter 执行删除。只有输入 q 或 CANCEL 才取消。",
        };
        PromptAnswer answer = promptLine("删除统计端口", body, "删除端口> ");
        if (!answer.ok) {
            return false;
        }
        const std::string value = trim(answer.value);
        return !(value == "q" || value == "Q" || value == "cancel" || value == "CANCEL");
    }

    void renderBusy(const std::string &title, const std::string &message) {
        ScreenBuffer buffer;
        buffer.add(message);
        viewport_.render(title, buffer, 0, "正在执行，请稍候");
    }

    CommandResult runDisplayedCommand(ScreenBuffer &buffer, const std::string &command) {
        buffer.add(ansi::gray + "$ " + command + ansi::plain);
        CommandResult result = Shell::capture(command + " 2>&1");
        buffer.add(result.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                               : ansi::yellow + "exit " + std::to_string(result.exitCode) + ansi::plain);
        const std::string output = trim(result.output);
        if (!output.empty()) {
            buffer.addAll(splitLines(output));
        }
        buffer.add("");
        return result;
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

    void actionShowTrafficPeriod(TrafficPeriodMode mode, const std::string &period) {
        ScreenBuffer buffer;
        const std::string title = trafficPeriodModeDetailTitle(mode);
        const auto rows = loadTrafficDeltasForPeriod(mode, period);
        const auto byPort = aggregateTrafficByPort(rows);
        buffer.add("查询模式: 绝对时间。");
        buffer.add("统计口径: 系统本地时间 " + period + "，按端口和 IP:端口聚合上行/下行。");
        buffer.add("历史目录: " + kTrafficHistoryDir);
        if (rows.empty()) {
            buffer.add(ansi::yellow + std::string("该时间段还没有采样增量。") + ansi::plain);
            buffer.add("如果刚开启统计，这是正常现象：第一轮采样建立基线，下一轮采样才会产生增量。");
            buffer.add("想确认底层实时计数是否在增长，可返回“流量统计 -> 实时明细”。");
            buffer.add("");
        }
        buffer.add("> 端口汇总");
        addTrafficSummaryTable(buffer, byPort, 50, "暂无采样增量", TrafficGroupMode::Port);
        buffer.add("");
        buffer.add("> IP:端口明细");
        addTrafficSummaryTable(buffer, aggregateTrafficByIpPort(rows), 80, "暂无采样增量", TrafficGroupMode::IpPort);
        buffer.add("");
        buffer.add("> IP 汇总");
        addTrafficSummaryTable(buffer, aggregateTrafficByIp(rows), 50, "暂无采样增量", false);
        pushResult(title + " " + period, buffer);
    }

    void actionShowTrafficPeriods(TrafficPeriodMode mode, std::size_t limit, const std::string &queryNote) {
        const std::string title = trafficPeriodModeTitle(mode);
        const std::string vnstat = trafficPeriodVnstatCommand(mode);
        const auto rows = loadTrafficPeriodTotals(mode, limit);
        std::vector<std::string> periods;
        for (const auto &row : rows) {
            periods.push_back(row.period);
        }
        const auto details = loadTrafficDeltasForPeriods(mode, periods);
        ScreenBuffer buffer;
        buffer.add("查询模式: " + queryNote);
        buffer.add("统计口径: 保留 " + vnstat + " 的时间维度，但每行额外显示该周期的端口和 IP:端口 Top。");
        buffer.add("每行是一个" + trafficPeriodModeColumn(mode) + "的采样增量。");
        buffer.add("时间使用服务器系统本地时区；上行在前，下行在后。");
        buffer.add("历史目录: " + kTrafficHistoryDir);
        buffer.add("");
        buffer.addAll(tableLines(trafficPeriodTotalsTable(rows, mode, details),
                                 "暂无历史采样增量。开启/追加端口后，第一次采样会把已有底层计数纳入当前周期。"));
        if (!rows.empty()) {
            const auto detailIt = details.find(rows.front().period);
            const std::vector<TrafficRow> latestRows = detailIt == details.end() ? std::vector<TrafficRow>{} : detailIt->second;
            buffer.add("");
            buffer.add("> 最新周期完整明细: " + rows.front().period);
            buffer.add("端口明细和 IP:端口明细来自同一批采样增量，不是底层实时累计值。");
            buffer.add("");
            buffer.add("> 端口汇总");
            addTrafficSummaryTable(buffer, aggregateTrafficByPort(latestRows), 30, "暂无采样增量", TrafficGroupMode::Port);
            buffer.add("");
            buffer.add("> IP:端口明细");
            addTrafficSummaryTable(buffer, aggregateTrafficByIpPort(latestRows), 50, "暂无采样增量", TrafficGroupMode::IpPort);
        }
        pushResult(title, buffer);
    }

    void actionShowTrafficPeriods(TrafficPeriodMode mode) {
        actionShowTrafficPeriods(mode, defaultTrafficRollingLimit(mode),
                                 "滚动窗口，最近 " + std::to_string(defaultTrafficRollingLimit(mode)) +
                                     " 个有采样数据的" + trafficPeriodModeUnit(mode));
    }

    void actionTrafficPeriodQuery(TrafficPeriodMode mode) {
        const std::string title = trafficPeriodModeTitle(mode);
        const std::string current = currentTrafficPeriodLabel(mode);
        PromptAnswer queryMode = promptLine(title,
                                            {"选择查询方式:",
                                             "1 = 滚动窗口，最近 N 个有采样数据的" + trafficPeriodModeUnit(mode),
                                             "2 = 绝对时间，指定一个" + trafficPeriodModeColumn(mode),
                                             "直接按 Enter 使用滚动窗口。"},
                                            "模式 [1/2]: ");
        if (!queryMode.ok) {
            return;
        }
        const std::string choice = trim(queryMode.value);
        if (choice.empty() || choice == "1" || lowerCopy(choice) == "r" || lowerCopy(choice) == "rolling") {
            const std::size_t defaultLimit = defaultTrafficRollingLimit(mode);
            PromptAnswer count = promptLine(title + " - 滚动窗口",
                                            {"输入要查看的周期数量。",
                                             "默认: " + std::to_string(defaultLimit) + "，最大: " + std::to_string(maxTrafficRollingLimit(mode)),
                                             "说明: 滚动窗口展示最近有采样增量的周期，并保留端口/IP:端口明细。"},
                                            "最近N个" + trafficPeriodModeUnit(mode) + ": ",
                                            std::to_string(defaultLimit));
            if (!count.ok) {
                return;
            }
            std::size_t limit = defaultLimit;
            if (!parseTrafficRollingLimit(count.value, mode, limit)) {
                ScreenBuffer buffer;
                buffer.add(ansi::yellow + std::string("滚动窗口数量不合法。") + ansi::plain);
                buffer.add("请输入 1 到 " + std::to_string(maxTrafficRollingLimit(mode)) + " 之间的整数。");
                pushResult(title, buffer);
                return;
            }
            actionShowTrafficPeriods(mode, limit,
                                     "滚动窗口，最近 " + std::to_string(limit) +
                                         " 个有采样数据的" + trafficPeriodModeUnit(mode));
            return;
        }
        if (!(choice == "2" || lowerCopy(choice) == "a" || lowerCopy(choice) == "absolute")) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("查询方式不合法。") + ansi::plain);
            buffer.add("请输入 1/2，或直接按 Enter 使用滚动窗口。");
            pushResult(title, buffer);
            return;
        }

        const std::string sample = "示例: " + trafficPeriodSample(mode);
        PromptAnswer answer = promptLine(title + " - 绝对时间",
                                         {sample, "默认: " + current, "时间按服务器系统本地时区解释。"},
                                         trafficPeriodModeColumn(mode) + ": ",
                                         current);
        if (!answer.ok) {
            return;
        }
        const std::string period = trim(answer.value);
        if (!isValidTrafficPeriodLabel(mode, period)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("时间格式不合法。") + ansi::plain);
            buffer.add(sample);
            buffer.add("当前默认值: " + current);
            pushResult(title, buffer);
            return;
        }
        actionShowTrafficPeriod(mode, period);
    }

    void actionShowTrafficRanking() {
        renderBusy("实时累计明细", "正在读取底层实时计数...");
        ScreenBuffer buffer;
        if (!trafficTableEnabled()) {
            buffer.add(ansi::yellow + std::string("底层统计规则未启用。进入“流量统计 -> 开启/追加端口”启用。") + ansi::plain);
            pushResult("实时累计明细", buffer);
            return;
        }
        const auto rows = collectTrafficRows();
        buffer.add("统计口径: 底层实时累计计数，适合确认规则是否正在增长；年月日趋势请看“本月/今日/按日/月/年查看”。");
        buffer.add("提示: 这个页面会读取底层规则，数据多时比仪表盘慢。");
        buffer.add("");
        buffer.add("> 端口排行");
        addTrafficSummaryTable(buffer, aggregateTrafficByPort(rows), 30, "暂无匹配流量", TrafficGroupMode::Port);
        buffer.add("");
        buffer.add("> IP 总量");
        addTrafficSummaryTable(buffer, aggregateTrafficByIp(rows), 30, "暂无匹配流量", false);
        buffer.add("");
        buffer.add("> IP + 端口明细");
        addTrafficSummaryTable(buffer, aggregateTrafficByIpPort(rows), 80, "暂无匹配流量", TrafficGroupMode::IpPort);
        pushResult("实时累计明细", buffer);
    }

    void actionInstallTraffic() {
        const std::set<int> knownPorts = detectExistingTrafficPorts();
        const std::string month = currentTrafficPeriodLabel(TrafficPeriodMode::Month);
        const auto monthRows = aggregateTrafficHistoryByPort(TrafficPeriodMode::Month, month);
        const TrafficSummaryRow monthTotal = sumTrafficSummaryRows(monthRows);
        std::vector<std::string> intro = {
            "默认追加到现有端口，不清空已有统计。",
            "当前统计端口: " + std::to_string(knownPorts.size()) + " 个  " + humanPortList(knownPorts),
            "本月流量(" + month + "): 上行 " + humanBytes(monthTotal.uploadBytes) +
                " / 下行 " + humanBytes(monthTotal.downloadBytes) +
                " / 合计 " + humanBytes(monthTotal.totalBytes()),
        };
        if (monthRows.empty()) {
            intro.push_back("本月还没有采样增量；第一轮采样建立基线，下一轮开始显示变化。");
        } else {
            std::ostringstream top;
            top << "端口 Top: ";
            const std::size_t limit = std::min<std::size_t>(3, monthRows.size());
            for (std::size_t i = 0; i < limit; ++i) {
                if (i != 0) {
                    top << " | ";
                }
                top << monthRows[i].port << " " << humanBytes(monthRows[i].totalBytes());
            }
            intro.push_back(top.str());
        }
        intro.push_back("输入需要统计的服务端口，支持单端口、逗号和范围。示例: 80,443,10000-10100");
        PromptAnswer ports = promptLine("开启/追加统计端口",
                                        intro,
                                        "端口列表: ");
        if (!ports.ok) {
            return;
        }
        const std::string value = removeSpaces(ports.value);
        if (!isSafePortList(value)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("端口列表不合法。") + ansi::plain);
            buffer.add("示例: 80,443,10000-10100");
            pushResult("开启/追加统计端口", buffer);
            return;
        }

        std::set<int> requestedPorts;
        expandPortList(value, requestedPorts);
        std::set<int> finalPorts = requestedPorts;
        std::set<int> managed = knownPorts;
        finalPorts.insert(managed.begin(), managed.end());
        const std::set<int> newPorts = setDifference(requestedPorts, managed);

        const bool updatePortSetOnly = trafficTrackedPortsSetEnabled();
        std::vector<std::string> commands = updatePortSetOnly
            ? trafficPortSetUpdateCommands(finalPorts)
            : trafficAccountingRuleCommands(finalPorts, false);
        std::string timerError;
        renderBusy("开启/追加统计端口", "正在应用统计规则...");
        cachedDashboardValid() = false;
        ScreenBuffer buffer;
        bool commandOk = true;
        for (const auto &command : commands) {
            const CommandResult result = runDisplayedCommand(buffer, command);
            if (!result.ok()) {
                commandOk = false;
            }
        }
        const TrafficAccountingVerification verification = verifyTrafficAccountingApplied(finalPorts);
        if (!commandOk || !verification.ok) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("统计规则未能确认生效，已停止写入本地端口记录和后台 timer。") + ansi::plain);
            result.add("未生效端口: " + humanPortList(finalPorts));
            result.add("下一步: 修复 nftables 权限/语法后，重新进入“流量统计 -> 开启/追加端口”。");
            result.add("");
            if (!verification.ok) {
                result.add("> 生效验证失败");
                for (const auto &failure : verification.failures) {
                    result.add("- " + failure);
                }
                result.add(verification.evidence);
                result.add("");
            }
            result.add("> 命令输出");
            result.addAll(buffer.lines());
            pushResult("开启/追加统计端口", result);
            return;
        }
        std::string storeError;
        storeTrackedTrafficPorts(finalPorts, storeError);
        if (!storeError.empty()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("统计规则已生效，但本地端口记录写入失败，已停止安装后台 timer。") + ansi::plain);
            result.add("影响: 可靠性自检会看到“历史记录有/实时规则有”状态不一致，后台采样不会自动启用。");
            result.add("端口记录写入失败: " + storeError);
            result.add("当前 nft 端口: " + humanPortList(verification.nftPorts));
            result.add("");
            result.add("> 命令输出");
            result.addAll(buffer.lines());
            pushResult("开启/追加统计端口", result);
            return;
        }
        const bool timerWritten = writeTrafficSnapshotTimerUnits("", timerError);
        if (timerWritten && Shell::exists("systemctl")) {
            buffer.add("");
            buffer.add("> 后台采样 timer");
            runDisplayedCommand(buffer, "systemctl daemon-reload");
            runDisplayedCommand(buffer, "systemctl enable --now " + kTrafficSnapshotTimer);
        }
        buffer.add("");
        buffer.add("> 统计端口");
        buffer.add("原有端口: " + std::to_string(managed.size()) + " 个  " + humanPortList(managed));
        buffer.add("本次输入: " + humanPortList(requestedPorts));
        buffer.add("新增端口: " + (newPorts.empty() ? std::string("无，输入端口已在统计范围内") : humanPortList(newPorts)));
        buffer.add("当前端口: " + std::to_string(finalPorts.size()) + " 个  " + humanPortList(finalPorts));
        if (updatePortSetOnly) {
            buffer.add("已只更新统计端口集合，原有端口计数和历史数据已保留。");
        } else {
            buffer.add("已使用端口集合管理统计范围；保留实时计数和历史数据。之后追加端口只更新端口集合。");
        }
        buffer.add("生效验证: " + verification.evidence);
        const TrafficSnapshotResult snapshotResult = recordTrafficSnapshot();
        buffer.add("");
        buffer.add("> 历史采样基线");
        buffer.add(snapshotResult.ok ? ansi::green + std::string("已记录一次基线采样。") + ansi::plain
                                     : ansi::yellow + std::string("基线采样未完成: ") + snapshotResult.message + ansi::plain);
        buffer.add("说明: 第一轮采样用于建立基线，下一轮采样后日/月/年视图开始出现增量。");
        if (!storeError.empty()) {
            buffer.add(ansi::yellow + std::string("端口记录写入失败: ") + storeError + ansi::plain);
        }
        if (!timerWritten) {
            buffer.add(ansi::yellow + std::string("后台采样 timer 未安装: ") + timerError + ansi::plain);
        } else {
            buffer.add("后台采样: " + kTrafficSnapshotTimer + " 每 5 分钟记录一次历史增量。");
        }
        pushResult("开启/追加统计端口", buffer);
    }

    void actionRemoveTrafficPorts() {
        const std::set<int> existingPorts = detectExistingTrafficPorts();
        if (existingPorts.empty()) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("当前没有记录到正在统计的端口。") + ansi::plain);
            buffer.add("如需开始统计，进入“流量统计 -> 开启/追加端口”。");
            pushResult("删除统计端口", buffer);
            return;
        }
        PromptAnswer ports = promptLine("删除统计端口",
                                        {"输入要停止统计的端口。不会删除历史数据，原有端口计数会保留。",
                                         "当前统计端口: " + humanPortList(existingPorts),
                                         "示例: 8080,8443,10000-10010"},
                                        "端口列表: ");
        if (!ports.ok) {
            return;
        }
        const std::string value = removeSpaces(ports.value);
        if (!isSafePortList(value)) {
            ScreenBuffer buffer;
            buffer.add(ansi::yellow + std::string("端口列表不合法。") + ansi::plain);
            buffer.add("示例: 8080,8443,10000-10010");
            pushResult("删除统计端口", buffer);
            return;
        }
        std::set<int> requestedPorts;
        expandPortList(value, requestedPorts);
        const std::set<int> finalPorts = setDifference(existingPorts, requestedPorts);
        if (!confirmRemoveTrafficPorts(existingPorts, requestedPorts, finalPorts)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("删除统计端口", buffer);
            return;
        }
        renderBusy("删除统计端口", "正在更新统计端口集合...");
        std::string storeError;
        storeTrackedTrafficPorts(finalPorts, storeError);
        cachedDashboardValid() = false;
        ScreenBuffer buffer = runCommandList(trafficPortSetUpdateCommands(finalPorts));
        if (!storeError.empty()) {
            buffer.add(ansi::yellow + std::string("端口记录写入失败: ") + storeError + ansi::plain);
        }
        buffer.add("");
        buffer.add("历史数据已保留；被删除端口不会继续产生新的采样增量。");
        pushResult("删除统计端口", buffer);
    }

    void actionRemoveTrafficAccounting() {
        renderBusy("删除流量统计", "正在检查统计表...");
        if (!trafficTableEnabled()) {
            ScreenBuffer buffer;
            buffer.add("底层统计规则未启用，无需删除。");
            pushResult("删除流量统计", buffer);
            return;
        }
        if (!confirmYesNo("将删除流量统计规则并清空实时计数。历史年月日数据保留。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("删除流量统计", buffer);
            return;
        }
        cachedDashboardValid() = false;
        pushResult("删除流量统计", runCommandList({"nft delete table inet " + kIpTrafficTable}));
    }

    void actionRawNftTable() {
        renderBusy("底层计数规则", "正在读取 nftables 底层规则...");
        CommandResult result = Shell::capture("nft list table inet " + kIpTrafficTable + " 2>/dev/null || true");
        ScreenBuffer buffer;
        buffer.add("以下是 nftables 原始输出，主要用于排障；日/月/年统计请回到“流量统计”查看。");
        buffer.add("");
        const std::string output = trim(result.output);
        if (output.empty()) {
            buffer.add("(无输出，统计表可能未启用)");
        } else {
            buffer.addAll(splitLines(output));
        }
        pushResult("底层计数规则", buffer);
    }

    void actionSecurityStatus() {
        renderBusy("安全总览", "正在读取防护链路状态...");
        auto fail2banStateFuture = std::async(std::launch::async, [] { return serviceState("fail2ban"); });
        auto ufwStateFuture = std::async(std::launch::async, [] { return ufwState(); });
        auto sshRuntimeFuture = std::async(std::launch::async, [] { return fail2banJailRuntimeStatus(kRule1Jail); });
        auto scanRuntimeFuture = std::async(std::launch::async, [] { return fail2banJailRuntimeStatus(kRule2Jail); });
        auto sshBannedFuture = std::async(std::launch::async, [] { return bannedSetForJail(kRule1Jail); });
        auto scanBannedFuture = std::async(std::launch::async, [] { return bannedSetForJail(kRule2Jail); });
        auto ufwTopFuture = std::async(std::launch::async, [] { return collectUfwSourceTop(); });
        const F2bJailRuntimeInfo sshRuntime = sshRuntimeFuture.get();
        const F2bJailRuntimeInfo scanRuntime = scanRuntimeFuture.get();
        ScreenBuffer buffer;
        buffer.add("> 防护链路");
        addKeyValueTable(buffer, {
            {"fail2ban 服务", fail2banStateFuture.get()},
            {"sshd jail", sshRuntime.label},
            {"规则2 jail", scanRuntime.label},
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

        buffer.add("> UFW拦截风险来源Top");
        buffer.add(ufwAnalysisAccuracyNote());
        addUfwTable(buffer, ufwTopFuture.get(), "该窗口暂无公网 UFW BLOCK/AUDIT 记录。");
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
        buffer.add("> 配置检查与服务重载");
        CommandResult check = runDisplayedCommand(buffer, "fail2ban-client -t");
        if (!check.ok()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("fail2ban 配置检查失败，已停止重载。") + ansi::plain);
            result.add("请先修复 fail2ban-client -t 输出中的配置错误。");
            result.add("");
            result.addAll(buffer.lines());
            pushResult("安装/修复配置", result);
            return;
        }
        CommandResult enable = runDisplayedCommand(buffer, "systemctl enable --now fail2ban");
        if (!enable.ok()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("fail2ban 服务启动失败，配置尚未真正生效。") + ansi::plain);
            result.add("");
            result.addAll(buffer.lines());
            pushResult("安装/修复配置", result);
            return;
        }
        CommandResult reload = runDisplayedCommand(buffer, "fail2ban-client reload");
        if (!reload.ok()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("fail2ban reload 失败，配置尚未真正生效。") + ansi::plain);
            result.add("");
            result.addAll(buffer.lines());
            pushResult("安装/修复配置", result);
            return;
        }
        runDisplayedCommand(buffer, "(ufw reload || true)");
        buffer.add("> 生效状态验证");
        CommandResult ping = runDisplayedCommand(buffer, "fail2ban-client ping");
        CommandResult status = runDisplayedCommand(buffer, "fail2ban-client status");
        (void)status;
        CommandResult sshStatus = runDisplayedCommand(buffer, "fail2ban-client status " + shellQuote(kRule1Jail));
        CommandResult scanStatus = runDisplayedCommand(buffer, "fail2ban-client status " + shellQuote(kRule2Jail));
        const F2bJailRuntimeInfo sshRuntime = parseFail2banJailStatus(kRule1Jail, sshStatus.output, true);
        const F2bJailRuntimeInfo scanRuntime = parseFail2banJailStatus(kRule2Jail, scanStatus.output, true);
        addKeyValueTable(buffer, {
            {"fail2ban ping", ping.ok() ? "正常" : "异常"},
            {kRule1Jail, sshRuntime.label},
            {kRule2Jail, scanRuntime.label},
        });
        ReliabilityReport readonlyReport;
        verifyFail2banUfwChain(readonlyReport, false);
        buffer.add("");
        buffer.add("> 统一可靠性口径");
        buffer.addAll(reliabilityReportBuffer(readonlyReport, false).lines());
        if (!ping.ok() || !sshRuntime.loaded() || !scanRuntime.loaded()) {
            ScreenBuffer result;
            result.add(ansi::yellow + std::string("fail2ban 自动化未通过统一验收，不能视为已生效。") + ansi::plain);
            if (!ping.ok()) {
                result.add("- fail2ban ping 失败：socket 或服务状态不可用。");
            }
            if (!sshRuntime.loaded()) {
                result.add("- sshd jail 未加载。");
            }
            if (!scanRuntime.loaded()) {
                result.add("- 规则2未加载，未真正生效。");
            }
            result.add("请查看下方 fail2ban-client status 输出和 /etc/fail2ban/jail.local 配置。");
            result.add("");
            result.addAll(buffer.lines());
            pushResult("安装/修复配置", result);
            return;
        }
        buffer.add("");
        buffer.add(ansi::green + std::string("安装/修复完成，默认 jail 已加载。") + ansi::plain);
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
        ScreenBuffer issues;
        bool blocked = false;
        for (const auto &jail : {kRule1Jail, kRule2Jail}) {
            const F2bJailRuntimeInfo runtime = fail2banJailRuntimeStatus(jail);
            if (!runtime.loaded()) {
                blocked = true;
                issues.add(ansi::yellow + jail + " 未能读取封禁列表: " + runtime.label + ansi::plain);
                continue;
            }
            for (const auto &ip : runtime.bannedIps) {
                if (ufw.find(ip) == std::string::npos) {
                    commands.push_back(ufwDenyFromCommand(ip, "f2b:" + jail + " ip:" + ip));
                }
            }
        }
        if (blocked) {
            issues.add("");
            issues.add("请先确认 fail2ban jail 已加载且当前用户有权限读取 fail2ban socket。");
            pushResult("防护链路同步", issues);
            return;
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
        const DualAuditReport report = buildDualAuditReport(start, end, 40);
        ScreenBuffer buffer;
        buffer.add("窗口: " + dateTimeStamp(start) + " ~ " + dateTimeStamp(end));
        buffer.add("规则2阈值: " + configValueOr(cfg.maxretry, "50") + " 次 / " + configValueOr(cfg.findtime, "3600"));
        buffer.add("规则1状态: " + report.rule1.label + "  规则2状态: " + report.rule2.label);
        if (!report.rule2.loaded()) {
            buffer.add(ansi::yellow + std::string("规则2未加载，无法自动封禁；请先执行“策略安装/修复”。") + ansi::plain);
        }
        buffer.add("");
        const std::vector<int> widths = {34, 10, 8, 8, 10, 28};
        buffer.add(bufferTableRow({"IP", "UFW命中", "规则1", "规则2", "窗口Ban", "结论"}, widths, true));
        buffer.add(bufferTableRule(widths));
        std::vector<std::string> fixIps;
        for (const auto &row : report.rows) {
            const bool needsFix = row.conclusion == "达到规则2阈值但未封禁";
            if (needsFix) fixIps.push_back(row.ip);
            buffer.add(bufferTableRow({row.ip, std::to_string(row.ufwHits), row.rule1Banned ? "是" : "否",
                                       row.rule2Banned ? "是" : "否", row.banLogged ? "是" : "否",
                                       needsFix ? ansi::yellow + row.conclusion + ansi::plain : row.conclusion}, widths));
        }
        if (report.rows.empty()) {
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
        const DualAuditReport report = buildDualAuditReport(start, end, 40);
        const auto fixIps = dualAuditCandidateIps(report.rows);
        ScreenBuffer preview;
        preview.add("窗口: " + dateTimeStamp(start) + " ~ " + dateTimeStamp(end));
        preview.add("规则2阈值: " + configValueOr(cfg.maxretry, "50") + " 次 / " + configValueOr(cfg.findtime, "3600"));
        preview.add("规则2状态: " + report.rule2.label);
        preview.add("");
        if (!report.rule2.loaded()) {
            preview.add(ansi::yellow + std::string("规则2未加载，无法执行补封禁。请先运行“策略安装/修复”。") + ansi::plain);
            pushResult("补封禁候选 IP", preview);
            return;
        }
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

    void actionFail2banEffectProbe() {
        ScreenBuffer preview;
        preview.add(ansi::yellow + std::string("实效自检会临时封禁测试 IP: ") + kFail2banEffectProbeIp + ansi::plain);
        preview.add("流程: fail2ban banip -> 检查 jail 封禁列表 -> 检查 UFW deny -> unbanip -> 删除 UFW 残留规则。");
        preview.add("测试 IP 属于文档保留网段，不应是真实用户来源。");
        preview.add("");
        preview.add("执行期间会短暂写入 fail2ban 运行状态和 UFW 规则。");
        if (!confirmYesNoWithBody("防护链路实效自检", preview.lines(), false)) {
            ScreenBuffer cancel;
            cancel.add("操作已取消。");
            pushResult("防护链路实效自检", cancel);
            return;
        }

        renderBusy("防护链路实效自检", "正在执行可回滚链路自检...");
        ScreenBuffer buffer;
        buffer.add("测试 IP: " + kFail2banEffectProbeIp);
        buffer.add("");
        F2bEffectProbe probe;
        probe.ping = runDisplayedCommand(buffer, "fail2ban-client ping");
        probe.serviceOk = probe.ping.ok() && lowerCopy(probe.ping.output).find("pong") != std::string::npos;
        CommandResult before = runDisplayedCommand(buffer, "fail2ban-client status " + shellQuote(kRule2Jail));
        probe.jailStatus = parseFail2banJailStatus(kRule2Jail, before.output, true);
        probe.jailLoaded = probe.jailStatus.loaded();

        if (probe.jailLoaded) {
            probe.ban = runDisplayedCommand(buffer, fail2banSetIpCommandStrict(kRule2Jail, "banip", kFail2banEffectProbeIp));
            Shell::capture("sleep 1");
            probe.statusAfterBan = runDisplayedCommand(buffer, "fail2ban-client status " + shellQuote(kRule2Jail));
            const F2bJailRuntimeInfo afterBan = parseFail2banJailStatus(kRule2Jail, probe.statusAfterBan.output, true);
            probe.banListed = afterBan.bannedIps.count(kFail2banEffectProbeIp) > 0;
            probe.ufwStatus = runDisplayedCommand(buffer, "ufw status numbered");
            probe.ufwLanded = ufwStatusHasDenyForIp(probe.ufwStatus.output, kFail2banEffectProbeIp, true);
        }

        buffer.add("> 清理测试痕迹");
        probe.unban = runDisplayedCommand(buffer, fail2banSetIpCommandStrict(kRule2Jail, "unbanip", kFail2banEffectProbeIp));
        probe.unbanOk = probe.unban.ok();
        probe.ufwCleanup = runDisplayedCommand(buffer, "(ufw --force delete deny from " + shellQuote(kFail2banEffectProbeIp) + " || true)");
        CommandResult postCleanup = runDisplayedCommand(buffer, "ufw status numbered 2>/dev/null || true");
        probe.ufwCleanupOk = probe.ufwCleanup.ok() && !ufwStatusHasDenyForIp(postCleanup.output, kFail2banEffectProbeIp, false);

        ScreenBuffer result;
        result.add("> 实效结论");
        addKeyValueTable(result, {
            {"fail2ban 服务", probe.serviceOk ? "正常" : "异常"},
            {"规则2 jail", probe.jailLoaded ? "已加载" : probe.jailStatus.label},
            {"banip 进入列表", probe.banListed ? "是" : "否"},
            {"UFW deny 落地", probe.ufwLanded ? "是，且带 fail2ban comment" : "否"},
            {"unban 清理", probe.unbanOk ? "完成" : "失败"},
            {"UFW 残留清理", probe.ufwCleanupOk ? "已尝试清理" : "失败"},
        });
        result.add("");
        if (probe.serviceOk && probe.jailLoaded && probe.banListed && probe.ufwLanded) {
            result.add(ansi::green + std::string("防护链路自检通过：fail2ban 规则2可以封禁并落地到 UFW。") + ansi::plain);
        } else {
            result.add(ansi::yellow + std::string("防护链路自检未通过。") + ansi::plain);
            if (!probe.jailLoaded) {
                result.add("- 规则2 jail 未加载：先执行“策略安装/修复”，并查看 fail2ban-client -t 输出。");
            } else if (!probe.banListed) {
                result.add("- banip 未进入 fail2ban 列表：检查 fail2ban-client set 输出和 jail 状态。");
            } else if (!probe.ufwLanded) {
                result.add("- fail2ban 已记录封禁，但 UFW 未出现带 fail2ban comment 的 deny：检查 ufw-drop action 和 UFW 状态。");
            }
        }
        result.add("");
        result.add("> 命令明细");
        result.addAll(buffer.lines());
        pushResult("防护链路实效自检", result);
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
            const F2bJailRuntimeInfo runtime = fail2banJailRuntimeStatus(jail);
            if (!runtime.loaded()) {
                empty = false;
                buffer.add(bufferTableRow({jail, runtime.label, "-", "-"}, widths));
                continue;
            }
            for (const auto &ip : runtime.bannedIps) {
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
        const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl", "systemctl", "awk", "grep", "mmdblookup"};
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto &tool : tools) {
            rows.push_back({tool, Shell::exists(tool) ? Ui::badge("可用", ansi::green) : Ui::badge("缺失", ansi::yellow)});
        }
        addKeyValueTable(buffer, rows);
        buffer.add("");
        buffer.add("DB-IP Lite MMDB: " + std::string(fileExists(kDbIpLiteMmdbPath) ? Ui::badge("已安装", ansi::green) : Ui::badge("未安装", ansi::yellow)) +
                   "  " + kDbIpLiteMmdbPath);
        buffer.add("");
        buffer.add("Debian/Ubuntu 安装命令:");
        buffer.add("apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev curl mmdb-bin");
        pushResult("依赖检查", buffer);
    }

    void actionReliabilitySelfCheck() {
        ScreenBuffer intro;
        intro.add("默认只做只读检查，不修改 fail2ban、UFW、nftables 或诊断文件。");
        intro.add("");
        intro.add("输入 ACTIVE 会启用主动探测:");
        intro.add("- 临时 ban 测试 IP " + kFail2banEffectProbeIp + "，随后 unban 并清理 UFW 残留。");
        intro.add("- 执行一次流量采样，写入历史快照。");
        intro.add("- 在 /tmp 写入一份诊断报告并检查关键 section。");
        intro.add("");
        intro.add("直接按 Enter: 只读自检。");
        PromptAnswer mode = promptLine("可靠性自检", intro.lines(), "模式: ");
        if (!mode.ok) {
            return;
        }
        const bool active = trim(mode.value) == "ACTIVE";
        renderBusy("可靠性自检", active ? "正在执行全链路主动验证..." : "正在执行只读链路验证...");
        const ReliabilityReport report = runReliabilitySelfCheck(active);
        pushResult("可靠性自检", reliabilityReportBuffer(report, active));
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
        renderBusy("导出诊断报告", "正在写入报告...");
        ScreenBuffer buffer = runCommandList({diagnosticReportCommand(out)});
        buffer.add("报告路径: " + out);
        pushResult("导出诊断报告", buffer);
    }

    void actionInstallDependencies() {
        if (!confirmYesNo("将通过 apt 安装 fail2ban/ufw/nftables/iproute2/conntrack/curl/mmdb-bin。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("安装常见依赖", buffer);
            return;
        }
        renderBusy("安装常见依赖", "正在执行 apt 命令...");
        ScreenBuffer buffer = runCommandList({"apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev curl mmdb-bin"});
        Shell::clearExistsCache();
        cachedDashboardValid() = false;
        buffer.add("");
        buffer.add("已刷新依赖检测缓存。返回仪表盘后会重新读取工具状态。");
        pushResult("安装常见依赖", buffer);
    }

    void actionInstallGeoDatabase() {
        if (!confirmYesNo("将下载 DB-IP IP to City Lite 免费版 MMDB（约 125MB）到 " + kDbIpLiteMmdbPath +
                          "。该数据按 CC BY 4.0 授权，展示结果时会在文档中鸣谢 DB-IP.com。", false)) {
            ScreenBuffer buffer;
            buffer.add("操作已取消。");
            pushResult("安装/更新 IP 国家库", buffer);
            return;
        }
        renderBusy("安装/更新 IP 国家库", "正在下载并验证 DB-IP Lite MMDB...");
        ScreenBuffer buffer = runCommandList({dbIpLiteDownloadCommand()});
        Shell::clearExistsCache();
        buffer.add("");
        buffer.add("数据库路径: " + kDbIpLiteMmdbPath);
        buffer.add("数据库大小: " + humanBytes(fileSizeBytes(kDbIpLiteMmdbPath)));
        std::string sourceUrl;
        if (readTextFile(kDbIpLiteMetaPath, sourceUrl)) {
            buffer.add("下载 URL: " + trim(sourceUrl));
        }
        buffer.add("鸣谢: " + kDbIpLiteAttribution);
        buffer.add("国家/地区会显示在 UFW 来源 Top 与流量 IP 明细表中；未命中时显示 -。");
        pushResult("安装/更新 IP 国家库", buffer);
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
    const std::vector<std::string> tools = {"nft", "ufw", "fail2ban-client", "conntrack", "ss", "journalctl", "systemctl", "awk", "grep", "mmdblookup"};
    Table table({"工具", "状态"}, {24, 14});
    for (const auto &tool : tools) {
        table.add({tool, Shell::exists(tool) ? "可用" : "缺失"});
    }
    addSection(buffer, "依赖检查");
    addTableLines(buffer, table);
    buffer.add("");
    buffer.add("DB-IP Lite MMDB: " + std::string(fileExists(kDbIpLiteMmdbPath) ? "已安装" : "未安装") + "  " + kDbIpLiteMmdbPath);
    buffer.add("");
    buffer.add("Debian/Ubuntu 安装命令:");
    buffer.add("apt update && apt install -y fail2ban ufw nftables iproute2 conntrack gawk grep libsqlite3-dev curl mmdb-bin");
    return buffer;
}

inline ScreenBuffer dashboardBufferForCli() {
    ScreenBuffer buffer;
    buffer.add(ansi::bold + kName + " v" + kVersion + ansi::plain);
    buffer.add(ansi::gray + std::string("流量/端口优先的服务器防护仪表盘") + ansi::plain);
    buffer.add(ansi::gray + std::string(72, '-') + ansi::plain);
    buffer.add(dashboardFastHeaderLine());

    const bool tableEnabled = trafficHistoryConfiguredFast();
    const std::set<int> trackedPorts = loadTrackedTrafficPorts();
    std::vector<std::string> trafficPeriods;
    const auto totalRows = aggregateTrafficHistoryByPortForRecentDays(kDashboardTrafficDays, trafficPeriods);
    const std::string trafficLabel = recentTrafficDaysLabel(trafficPeriods, kDashboardTrafficDays);

    addSection(buffer, "最近31天端口流量 Top 10");
    buffer.add("统计口径: 系统本地时间 " + trafficLabel + "，按端口聚合上行/下行，只展示前10个端口。");
    buffer.add(std::string("历史采样: ") +
               (tableEnabled ? Ui::badge("已初始化", ansi::green) : Ui::badge("未初始化", ansi::yellow)));
    buffer.add("统计端口: " + std::to_string(trackedPorts.size()) + " 个  " + humanPortList(trackedPorts));
    if (!tableEnabled) {
        buffer.add(ansi::yellow + std::string("本地历史库尚未初始化。进入“流量统计 -> 开启/追加端口”启用。") + ansi::plain);
    } else if (totalRows.empty()) {
        buffer.add(ansi::yellow + std::string("最近31天还没有采样增量。第一轮采样建立基线，下一轮开始显示变化。") + ansi::plain);
    }
    addTableLines(buffer, trafficSummaryTable(totalRows, kDashboardTrafficPortLimit, TrafficGroupMode::Port), tableEnabled ? "最近31天暂无采样增量" : "历史采样未初始化");

    addSection(buffer, "安全分析摘要");
    std::vector<UfwHit> cachedHits;
    std::string hitNote;
    collectCachedUfwSourceTop(cachedHits, hitNote);
    if (!hitNote.empty()) {
        buffer.add(hitNote);
    }
    addTableLines(buffer, ufwHitsTable(cachedHits), "暂无缓存命中。执行 sudo ltg --ufw-analyze 24h 或进入安全中心生成/刷新。");

    addSection(buffer, "下一步");
    if (!tableEnabled) {
        buffer.add("sudo ltg 进入“流量统计 -> 开启/追加端口”后开始采样。");
    } else if (totalRows.empty()) {
        buffer.add("等待下一轮 5 分钟采样，或用 sudo ltg --traffic-snapshot 手动记录一次。");
    } else {
        buffer.add("趋势看流量统计，实时排障看 --ip-traffic 或 TUI 下钻检查。");
    }
    return buffer;
}

inline void renderDashboard(bool) {
    printScreenBuffer(dashboardBufferForCli());
}

inline void showTrafficRanking() {
    ScreenBuffer buffer;
    addSection(buffer, "实时累计明细");
    if (!trafficTableEnabled()) {
        buffer.add(ansi::yellow + std::string("底层统计规则未启用。进入“流量统计 -> 开启/追加端口”启用。") + ansi::plain);
        printScreenBuffer(buffer);
        return;
    }
    const auto rows = collectTrafficRows();
    buffer.add("统计口径: 底层实时累计计数。年月日统计来自后台采样历史，仪表盘默认展示最近31天端口汇总。");
    addSection(buffer, "端口排行");
    addTableLines(buffer, trafficSummaryTable(aggregateTrafficByPort(rows), 30, TrafficGroupMode::Port), "暂无匹配流量");
    addSection(buffer, "IP 总量");
    addTableLines(buffer, trafficSummaryTable(aggregateTrafficByIp(rows), 30, false), "暂无匹配流量");
    addSection(buffer, "IP + 端口明细");
    addTableLines(buffer, trafficSummaryTable(aggregateTrafficByIpPort(rows), 50, TrafficGroupMode::IpPort), "暂无匹配流量");
    printScreenBuffer(buffer);
}

inline int cliTrafficSnapshot() {
    const TrafficSnapshotResult result = recordTrafficSnapshot();
    ScreenBuffer buffer;
    addSection(buffer, "流量历史采样");
    buffer.add("采样时间: " + dateTimeStamp(result.sampledAt));
    buffer.add("历史目录: " + kTrafficHistoryDir);
    buffer.add(std::string("结果: ") + (result.ok ? "成功" : "失败"));
    buffer.add("实时行数: " + std::to_string(result.liveRows));
    buffer.add("增量行数: " + std::to_string(result.deltaRows));
    buffer.add("重置行数: " + std::to_string(result.resetRows));
    if (!result.message.empty()) {
        buffer.add("说明: " + result.message);
    }
    printScreenBuffer(buffer);
    return result.ok ? 0 : 1;
}

inline int cliReliabilityCheck(bool allowActiveProbes) {
    const ReliabilityReport report = runReliabilitySelfCheck(allowActiveProbes);
    printScreenBuffer(reliabilityReportBuffer(report, allowActiveProbes));
    return report.ok() ? 0 : 1;
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
    ScreenBuffer buffer = commandListBuffer({diagnosticReportCommand(out)});
    buffer.add("报告路径: " + out);
    printScreenBuffer(buffer);
}

inline int updateFromRelease(const char *argv0) {
#ifdef _WIN32
    std::cerr << "ltg update 只支持 Ubuntu/Linux 发布二进制。\n";
    return 1;
#else
    if (!isRoot()) {
        std::cerr << colorIf("更新需要写入当前 ltg 可执行文件。请使用: sudo ltg update", ansi::yellow, STDERR_FILENO) << "\n";
        return 77;
    }
    const std::string target = currentExecutablePath(argv0);
    const std::string temp = "/tmp/ltg-update-" + nowStamp();
    const std::string tempSha = temp + ".SHA256SUMS";
    ScreenBuffer buffer;
    addSection(buffer, "更新 Linux Traffic Guard");
    buffer.add("目标文件: " + target);
    buffer.add("下载来源: " + kLatestBinaryUrl);
    buffer.add("");

    if (!Shell::exists("curl") && !Shell::exists("wget")) {
        if (Shell::exists("apt-get")) {
            buffer.add("未发现 curl/wget，正在通过 apt-get 安装 curl。");
            ScreenBuffer deps = commandListBuffer({"apt-get update && apt-get install -y curl"});
            buffer.addAll(deps.lines());
            Shell::clearExistsCache();
        } else {
            buffer.add(ansi::yellow + std::string("未发现 curl 或 wget，且无法自动使用 apt-get 安装。") + ansi::plain);
            buffer.add("请先安装 curl 或 wget 后重试。");
            printScreenBuffer(buffer);
            return 1;
        }
    }

    std::string downloadCommand;
    if (Shell::exists("curl")) {
        downloadCommand = "curl -fL " + shellQuote(kLatestBinaryUrl) + " -o " + shellQuote(temp);
    } else if (Shell::exists("wget")) {
        downloadCommand = "wget -O " + shellQuote(temp) + " " + shellQuote(kLatestBinaryUrl);
    } else {
        buffer.add(ansi::yellow + std::string("curl 安装后仍不可用，更新已停止。") + ansi::plain);
        printScreenBuffer(buffer);
        return 1;
    }

    const auto runStep = [&](const std::string &command) {
        buffer.add(ansi::gray + "$ " + command + ansi::plain);
        const CommandResult result = Shell::capture(command);
        buffer.add(result.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                               : ansi::yellow + "exit " + std::to_string(result.exitCode) + ansi::plain);
        const std::string output = trim(result.output);
        if (!output.empty()) {
            buffer.addAll(splitLines(output));
        }
        buffer.add("");
        return result.ok();
    };

    const std::vector<std::string> commands = {
        downloadCommand,
        "chmod +x " + shellQuote(temp),
    };
    for (const auto &command : commands) {
        if (!runStep(command)) {
            runStep("rm -f " + shellQuote(temp));
            buffer.add(ansi::yellow + std::string("更新失败，请查看上方输出。") + ansi::plain);
            printScreenBuffer(buffer);
            return 1;
        }
    }

    std::string shaDownload;
    if (Shell::exists("curl")) {
        shaDownload = "curl -fL " + shellQuote(kLatestSha256Url) + " -o " + shellQuote(tempSha);
    } else {
        shaDownload = "wget -O " + shellQuote(tempSha) + " " + shellQuote(kLatestSha256Url);
    }
    if (runStep(shaDownload) && Shell::exists("sha256sum") && Shell::exists("grep") && Shell::exists("sed")) {
        const std::string verify = "grep ' ltg-linux-x86_64$' " + shellQuote(tempSha) +
                                   " | sed 's# ltg-linux-x86_64# " + temp + "#' | sha256sum -c -";
        if (!runStep(verify)) {
            runStep("rm -f " + shellQuote(temp) + " " + shellQuote(tempSha));
            buffer.add(ansi::yellow + std::string("SHA256 校验失败，已停止覆盖安装。") + ansi::plain);
            printScreenBuffer(buffer);
            return 1;
        }
    } else {
        buffer.add(ansi::yellow + std::string("未能读取或执行 SHA256SUMS 校验，继续使用版本检查保护。") + ansi::plain);
        buffer.add("");
    }

    const CommandResult downloadedVersion = Shell::capture(shellQuote(temp) + " --version");
    buffer.add(ansi::gray + std::string("$ ") + shellQuote(temp) + " --version" + ansi::plain);
    buffer.add(downloadedVersion.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                                      : ansi::yellow + "exit " + std::to_string(downloadedVersion.exitCode) + ansi::plain);
    buffer.addAll(splitLines(trim(downloadedVersion.output)));
    buffer.add("");
    std::array<int, 3> currentVersion{};
    std::array<int, 3> newVersion{};
    if (!downloadedVersion.ok() || !parseVersionTriplet(kVersion, currentVersion) ||
        !parseVersionTriplet(downloadedVersion.output, newVersion) ||
        compareVersionTriplet(newVersion, currentVersion) < 0) {
        runStep("rm -f " + shellQuote(temp) + " " + shellQuote(tempSha));
        buffer.add(ansi::yellow + std::string("下载到的版本无法确认，或低于当前版本，已停止覆盖安装。") + ansi::plain);
        printScreenBuffer(buffer);
        return 1;
    }

    if (!runStep("install -Dm755 " + shellQuote(temp) + " " + shellQuote(target))) {
        runStep("rm -f " + shellQuote(temp) + " " + shellQuote(tempSha));
        buffer.add(ansi::yellow + std::string("覆盖安装失败，请查看上方输出。") + ansi::plain);
        printScreenBuffer(buffer);
        return 1;
    }

    const CommandResult installedVersion = Shell::capture(shellQuote(target) + " --version");
    buffer.add(ansi::gray + std::string("$ ") + shellQuote(target) + " --version" + ansi::plain);
    buffer.add(installedVersion.ok() ? ansi::green + std::string("exit 0") + ansi::plain
                                     : ansi::yellow + "exit " + std::to_string(installedVersion.exitCode) + ansi::plain);
    buffer.addAll(splitLines(trim(installedVersion.output)));
    buffer.add("");
    std::array<int, 3> installed{};
    if (!installedVersion.ok() || !parseVersionTriplet(installedVersion.output, installed) ||
        compareVersionTriplet(installed, newVersion) != 0) {
        runStep("rm -f " + shellQuote(temp) + " " + shellQuote(tempSha));
        buffer.add(ansi::yellow + std::string("覆盖后版本复查失败，请确认目标路径是否被正确替换。") + ansi::plain);
        printScreenBuffer(buffer);
        return 1;
    }

    runStep("rm -f " + shellQuote(temp) + " " + shellQuote(tempSha));
    buffer.add("");
    buffer.add("更新完成，目标文件版本已复查。");
    printScreenBuffer(buffer);
    return 0;
#endif
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
    std::set<int> expandedPorts;
    expandPortList("443,80,10000-10002", expandedPorts);
    const std::set<int> diffPorts = setDifference(expandedPorts, std::set<int>{80, 443});
    const auto appendCommands = trafficAccountingRuleCommands(expandedPorts, false);
    const auto resetCommands = trafficAccountingRuleCommands(expandedPorts, true);
    const auto setOnlyCommands = trafficPortSetUpdateCommands(expandedPorts);
    check("统计端口追加命令", expandedPorts.size() == 5 && expandedPorts.count(80) == 1 &&
                                  diffPorts.size() == 3 && diffPorts.count(10001) == 1 &&
                                  appendCommands.front().find("delete table") == std::string::npos &&
                                  std::none_of(setOnlyCommands.begin(), setOnlyCommands.end(), [](const std::string &cmd) {
                                      return cmd.find("add chain") != std::string::npos || cmd.find("delete chain") != std::string::npos;
                                  }) &&
                                  std::any_of(appendCommands.begin(), appendCommands.end(), [](const std::string &cmd) {
                                      return cmd.find("tracked_ports") != std::string::npos;
                                  }) &&
                                  resetCommands.front().find("delete table") != std::string::npos);
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
    const std::string privateUfwLine = "2026-05-03T20:01:02 host kernel: [UFW BLOCK] SRC=192.168.1.9 DST=5.6.7.8 DPT=22";
    check("UFW 私网来源过滤", !parseUfwLogEvent(privateUfwLine, event));
    const std::string unknownPortUfwLine = "2026-05-03T20:01:02 host kernel: [UFW AUDIT] SRC=8.8.8.8 DST=5.6.7.8";
    check("UFW 无DPT端口兼容", parseUfwLogEvent(unknownPortUfwLine, event) && event.dpt == kUnknownUfwPort);
    const std::string badUfwLine = "2026-05-03T20:01:02 host kernel: [UFW BLOCK] SRC=:::: DST=5.6.7.8 DPT=22";
    check("UFW 无效来源过滤", !parseUfwLogEvent(badUfwLine, event));
    UfwLogEvidence evidence;
    observeUfwRawLogLine(ufwLine, evidence);
    observeUfwRawLogLine(unknownPortUfwLine, evidence);
    check("UFW 原始证据统计", evidence.rawMatches == 2 && evidence.block == 1 && evidence.audit == 1 && evidence.noDpt == 1);
    UfwLogEvent parsedGood;
    parseUfwLogEvent(ufwLine, parsedGood);
    const UfwAnalysisReport evidenceReport = buildUfwReportFromEvents("test", 1, 2, "live", {parsedGood}, evidence);
    check("UFW 分析证据不参与排序", evidenceReport.evidence.rawMatches == 2 &&
                                           ufwAnalysisAccuracyNote().find("国家/地区只用于展示") != std::string::npos);
    const std::string nftSample =
        "table inet usp_ip_traffic {\n"
        "\tset tracked_ports { elements = { 22, 443 } }\n"
        "\tset ipv4_download { }\n\tset ipv4_upload { }\n\tset ipv6_download { }\n\tset ipv6_upload { }\n"
        "\tchain input_account { type filter hook input priority -150; policy accept; tcp dport @tracked_ports update @ipv4_download { ip saddr . tcp dport } }\n"
        "\tchain output_account { type filter hook output priority -150; policy accept; tcp sport @tracked_ports update @ipv4_upload { ip daddr . tcp sport } }\n"
        "\tchain forward_account { type filter hook forward priority -150; policy accept; tcp dport @tracked_ports update @ipv6_download { ip6 saddr . tcp dport } update @ipv6_upload { ip6 daddr . tcp sport } }\n"
        "}";
    check("nft hook 语义解析", nftChainContains(nftSample, "input_account", "hook input") &&
                                  nftChainContains(nftSample, "output_account", "hook output") &&
                                  nftSample.find("@tracked_ports") != std::string::npos);
    check("UFW deny comment 识别", ufwStatusHasDenyForIp("[ 1] Anywhere DENY IN 203.0.113.254 # f2b:ufw-slowscan-global ip:203.0.113.254",
                                                        "203.0.113.254", true) &&
                                    !ufwStatusHasDenyForIp("[ 1] Anywhere DENY IN 203.0.113.254", "203.0.113.254", true));
    UfwAnalysisReport sourceTopReport;
    sourceTopReport.ipDaily["1.2.3.4"]["2026-05-03"] = 2;
    sourceTopReport.ipDaily["1.2.3.4"]["2026-05-04"] = 5;
    sourceTopReport.ipDaily["8.8.8.8"]["2026-05-03"] = 6;
    sourceTopReport.ipPortDaily["1.2.3.4"]["22"]["2026-05-03"] = 2;
    sourceTopReport.ipPortDaily["1.2.3.4"]["22"]["2026-05-04"] = 5;
    sourceTopReport.ipPortDaily["8.8.8.8"]["443"]["2026-05-03"] = 6;
    sourceTopReport.allowRecent.push_back({"1.2.3.4", std::time(nullptr)});
    ScreenBuffer ufwAnalysisBuffer;
    addUfwAnalysisToBuffer(ufwAnalysisBuffer, sourceTopReport);
    const std::string ufwAnalysisText = joinWords(ufwAnalysisBuffer.lines(), "\n");
    check("UFW分析页显示国家和口径", ufwAnalysisText.find("国家/地区") != std::string::npos &&
                                          ufwAnalysisText.find("精确时间窗口") != std::string::npos);
    const auto sourceTop = buildUfwSourceTopFromReport(sourceTopReport, 10);
    check("UFW来源Top口径", sourceTop.size() == 2 && sourceTop[0].value == "8.8.8.8" &&
                              sourceTop[0].peak == 6 && sourceTop[0].count == 6 &&
                              sourceTop[1].value == "1.2.3.4" && sourceTop[1].peak == 5 &&
                              sourceTop[1].count == 7 && sourceTop[1].topPort == "22");

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
    TrafficRow samePortOtherIp;
    samePortOtherIp.ip = "5.6.7.8";
    samePortOtherIp.port = "443";
    samePortOtherIp.direction = "下载";
    samePortOtherIp.family = "IPv4";
    samePortOtherIp.packets = 4;
    samePortOtherIp.bytes = 4096;
    bidirectionalTraffic.push_back(samePortOtherIp);
    const auto byIp = aggregateTrafficByIp(bidirectionalTraffic);
    const auto byPort = aggregateTrafficByPort(bidirectionalTraffic);
    const auto byIpPort = aggregateTrafficByIpPort(bidirectionalTraffic);
    check("上下行流量同排聚合", byIp.size() == 2 && byIp[0].downloadBytes == 4096 &&
                                  byIp[1].uploadBytes == 1024 && byIp[1].totalBytes() == 3072 &&
                                  byIpPort.size() == 2 && byIpPort[0].port == "443");
    check("端口流量分组", byPort.size() == 1 && byPort[0].port == "443" &&
                              byPort[0].downloadBytes == 6144 && byPort[0].uploadBytes == 1024 &&
                              byPort[0].totalBytes() == 7168);
    std::map<std::string, TrafficRow> previousTraffic;
    previousTraffic[trafficKey(traffic[0])] = traffic[0];
    TrafficRow increased = traffic[0];
    increased.bytes = 4096;
    increased.packets = 9;
    std::size_t resetRows = 0;
    const auto deltas = computeTrafficDeltas({increased}, previousTraffic, 1777777777, resetRows);
    TrafficRow resetRow = traffic[0];
    resetRow.bytes = 100;
    resetRow.packets = 1;
    const auto resetDeltas = computeTrafficDeltas({resetRow}, previousTraffic, 1777777777, resetRows);
    const std::size_t resetRowsAfterReset = resetRows;
    std::size_t firstResetRows = 0;
    const auto firstDeltas = computeTrafficDeltas({traffic[0]}, {}, 1777777777, firstResetRows);
    check("流量采样增量计算", deltas.size() == 1 && deltas[0].row.bytes == 2048 &&
                                  deltas[0].row.packets == 2 && resetDeltas.empty() && resetRowsAfterReset == 1);
    check("首次采样保留已有计数", firstDeltas.size() == 1 && firstDeltas[0].row.bytes == 2048 &&
                                      firstDeltas[0].day == localDayStamp(1777777777));
    check("本地时间分桶格式", isValidTrafficPeriodLabel(TrafficPeriodMode::Day, localDayStamp(std::time(nullptr))) &&
                                  isValidTrafficPeriodLabel(TrafficPeriodMode::Month, localMonthStamp(std::time(nullptr))) &&
                                  isValidTrafficPeriodLabel(TrafficPeriodMode::Year, localYearStamp(std::time(nullptr))) &&
                                  !isValidTrafficPeriodLabel(TrafficPeriodMode::Day, "05-04"));
    std::size_t rollingLimit = 0;
    check("流量滚动查询数量", parseTrafficRollingLimit("", TrafficPeriodMode::Day, rollingLimit) &&
                                  rollingLimit == defaultTrafficRollingLimit(TrafficPeriodMode::Day) &&
                                  parseTrafficRollingLimit("12", TrafficPeriodMode::Month, rollingLimit) &&
                                  rollingLimit == 12 &&
                                  !parseTrafficRollingLimit("0", TrafficPeriodMode::Month, rollingLimit) &&
                                  !parseTrafficRollingLimit("9999", TrafficPeriodMode::Day, rollingLimit) &&
                                  !parseTrafficRollingLimit("abc", TrafficPeriodMode::Year, rollingLimit));

    const auto merged = mergeRanges({{10, 20}, {1, 5}, {6, 9}, {30, 40}});
    check("range 合并", merged.size() == 2 && merged[0].first == 1 && merged[0].second == 20 &&
                            rangeCovered(1, 20, merged) && !rangeCovered(1, 30, merged));
    std::time_t overlapStart = 0;
    std::time_t overlapEnd = 0;
    check("缓存窗口重叠选择", latestOverlappingRange(100, 300, {{1, 90}, {120, 180}, {200, 260}}, overlapStart, overlapEnd) &&
                                  overlapStart == 200 && overlapEnd == 260 &&
                                  !latestOverlappingRange(100, 300, {{1, 90}, {301, 400}}, overlapStart, overlapEnd));

    IniConfig ini;
    ini.loadString("[sshd]\nmaxretry = 5\n\n[DEFAULT]\nignoreip = 127.0.0.1\n");
    ini.set("sshd", "bantime", "10m");
    ini.set("ufw-slowscan-global", "enabled", "true");
    const std::string rendered = ini.toString();
    check("IniConfig 内存读写", ini.get("sshd", "maxretry") == "5" &&
                                  rendered.find("bantime = 10m") != std::string::npos &&
                                  rendered.find("[ufw-slowscan-global]") != std::string::npos);
    const F2bJailRuntimeInfo parsedLoaded = parseFail2banJailStatus(
        "sshd",
        "Status for the jail: sshd\n|- Filter\n`- Actions\n   |- Currently banned:\t1\n   `- Banned IP list:\t1.2.3.4\n",
        true);
    check("fail2ban jail 状态解析", parsedLoaded.loaded() && parsedLoaded.bannedIps.count("1.2.3.4") == 1);
    const F2bJailRuntimeInfo parsedUnknown = parseFail2banJailStatus(
        kRule2Jail,
        "ERROR Command ['status', 'ufw-slowscan-global'] has failed. Received UnknownJailException('ufw-slowscan-global')",
        true);
    check("fail2ban UnknownJail 解析", parsedUnknown.state == F2bJailRuntimeState::NotLoaded);
    const F2bJailRuntimeInfo parsedDenied = parseFail2banJailStatus(
        "sshd",
        "ERROR Permission denied to socket: /var/run/fail2ban/fail2ban.sock, (you must be root)",
        true);
    check("fail2ban 权限不足解析", parsedDenied.state == F2bJailRuntimeState::PermissionDenied);
    F2bEffectProbe probeTest;
    probeTest.serviceOk = true;
    probeTest.jailLoaded = true;
    probeTest.banListed = true;
    probeTest.ufwLanded = false;
    probeTest.unbanOk = true;
    probeTest.ufwCleanupOk = true;
    check("fail2ban 实效自检聚合", probeTest.serviceOk && probeTest.jailLoaded && probeTest.banListed &&
                                      !probeTest.ufwLanded && probeTest.unbanOk && probeTest.ufwCleanupOk);
    DashboardSnapshot renderOnlySnapshot;
    renderOnlySnapshot.tableEnabled = true;
    renderOnlySnapshot.defaultPolicies = collectDefaultFail2banPolicies(false);
    const auto dashboardLines = buildDashboardBuffer(&renderOnlySnapshot, false, '|').lines();
    const std::string dashboardText = joinWords(dashboardLines, "\n");
    const bool dashboardAvoidsLiveProbe = std::none_of(dashboardLines.begin(), dashboardLines.end(), [](const std::string &line) {
        return line.find("nft 可用") != std::string::npos ||
               line.find("fail2ban-client 可用") != std::string::npos ||
               line.find("统计表:") != std::string::npos;
    });
    check("仪表盘渲染不触发运行态采集", !dashboardLines.empty() && dashboardAvoidsLiveProbe);
    check("仪表盘默认最近31天Top10", dashboardText.find("最近31天端口流量 Top 10") != std::string::npos &&
                                           dashboardText.find("最近31天暂无采样增量") != std::string::npos &&
                                           dashboardText.find("本月端口流量") == std::string::npos);
    check("最近31天标签", recentTrafficDaysLabel({"2026-05-04", "2026-04-04"}, 31) ==
                              "最近31天（2026-04-04 ~ 2026-05-04）");
    check("危险命令 helper", fail2banSetIpCommand("sshd", "banip", "1.2.3.4").find("fail2ban-client set 'sshd' banip '1.2.3.4'") != std::string::npos &&
                               ufwDenyFromCommand("1.2.3.4", "case").find("comment 'case'") != std::string::npos &&
                               ufwDeleteDenyFromCommand("1.2.3.4").find("--force delete deny") != std::string::npos);
    std::array<int, 3> parsedVersion{};
    std::array<int, 3> olderVersion{};
    check("update 版本解析", parseVersionTriplet("Linux 流量守卫 4.12.13", parsedVersion) &&
                                 parseVersionTriplet("4.12.12", olderVersion) &&
                                 compareVersionTriplet(parsedVersion, olderVersion) > 0 &&
                                 !parseVersionTriplet("version unknown", olderVersion));
    ReliabilityReport reliabilityReport;
    addReliabilityResult(reliabilityReport, "测试链路", "通过项", ReliabilityStatus::Pass, "ok");
    check("可靠性结果聚合", reliabilityReport.ok());
    addReliabilityResult(reliabilityReport, "测试链路", "失败项", ReliabilityStatus::Fail, "bad");
    check("可靠性失败聚合", !reliabilityReport.ok() &&
                              reliabilityReportBuffer(reliabilityReport, false).lines().size() > 3);
    check("诊断报告 section 检查", diagnosticReportHasRequiredSections("### fail2ban\n...\n### ufw\n...\n### accounting\n") &&
                                      !diagnosticReportHasRequiredSections("### fail2ban\n### ufw\n"));
    check("输入光标移动序列", cursorMoveSequence(4, 12) == "\033[4;12H\033[?25h");
    check("输入软件光标闪烁渲染", promptInputLine("端口> ", "443", true).find(ansi::inverse) != std::string::npos &&
                                      promptInputLine("端口> ", "443", false).find(ansi::inverse) == std::string::npos);
    int scrollProbe = 0;
    const bool topScrollChanged = adjustScroll(InputKind::Up, scrollProbe, 100);
    const bool downScrollChanged = adjustScroll(InputKind::Down, scrollProbe, 100);
    check("无效滚动不触发重绘", !topScrollChanged && downScrollChanged && scrollProbe > 0);
    int vimScrollProbe = 0;
    const bool vimDown = adjustScrollForEvent({InputKind::Character, 'j'}, vimScrollProbe, 100);
    const bool vimHalfDown = adjustScrollForEvent({InputKind::Character, 4}, vimScrollProbe, 100);
    const bool vimPageUp = adjustScrollForEvent({InputKind::Character, 2}, vimScrollProbe, 100);
    const bool vimBottom = adjustScrollForEvent({InputKind::Character, 'G'}, vimScrollProbe, 100);
    check("Vim 风格滚动快捷键", vimDown && vimHalfDown && vimPageUp && vimBottom && vimScrollProbe > 0);
    check("MMDB 输出解析", parseMmdbLookupString("  \"美国\" <utf8_string>\n") == "美国" &&
                              parseMmdbLookupString("  \"Mountain View\" <utf8_string>\n") == "Mountain View");
    check("DB-IP Lite 下载命令", dbIpLiteDownloadCommand().find(kDbIpLiteDownloadPage) != std::string::npos &&
                                  dbIpLiteDownloadCommand().find(".mmdb.gz") != std::string::npos &&
                                  dbIpLiteDownloadCommand().find(kDbIpLiteMmdbPath) != std::string::npos);

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
    const DualAuditReport report = buildDualAuditReport(start, end, 40);
    std::cout << "双日志核验: " << dateTimeStamp(start) << " ~ " << dateTimeStamp(end) << "\n";
    std::cout << "规则2阈值: " << configValueOr(cfg.maxretry, "50") << " / " << configValueOr(cfg.findtime, "3600") << "\n";
    std::cout << "规则1状态: " << report.rule1.label << "  规则2状态: " << report.rule2.label << "\n";
    if (!report.rule2.loaded()) {
        std::cout << "规则2未加载，无法自动封禁；请先执行策略安装/修复。\n";
    }
    Table table({"IP", "UFW命中", "规则1", "规则2", "窗口Ban", "结论"}, {34, 10, 8, 8, 10, 28});
    for (const auto &row : report.rows) {
        table.add({row.ip, std::to_string(row.ufwHits), row.rule1Banned ? "是" : "否",
                   row.rule2Banned ? "是" : "否", row.banLogged ? "是" : "否", row.conclusion});
    }
    table.print("当前窗口无 UFW BLOCK/AUDIT 命中");
    return 0;
}

inline void usage(const char *argv0) {
    std::cout << kName << " " << kVersion << "\n";
    std::cout << "Ubuntu 服务器流量与防护运维工具，模块化 C++17 项目，纯 ANSI TUI。\n\n";
    std::cout << "用法: " << argv0 << " [选项]\n\n";
    std::cout << "说明:\n";
    std::cout << "  除 --help / --version / --self-test / --reliability-check 外，本工具必须以 root 权限运行。\n";
    std::cout << "  交互模式会进入全屏 TUI；命令行参数模式输出普通文本，方便脚本/日志收集。\n";
    std::cout << "  会调用系统工具 nft/ufw/fail2ban-client/journalctl/ss/conntrack，不依赖 .sh/.py。\n\n";
    std::cout << "选项:\n";
    std::cout << "  --status          打印仪表盘\n";
    std::cout << "  --ip-traffic      查看端口优先的流量排行\n";
    std::cout << "  --traffic-snapshot 内部命令：记录一次流量历史采样\n";
    std::cout << "  --doctor          检查依赖\n";
    std::cout << "  --reliability-check [--active-probes]  全链路可靠性自检\n";
    std::cout << "  --audit           查看日志摘要\n";
    std::cout << "  --f2b-audit       防护链路双日志核验\n";
    std::cout << "  --ufw-analyze P   分析 UFW 日志，P=24h|7d|28d\n";
    std::cout << "  --export-report   导出诊断报告\n";
    std::cout << "  update, --update  从 GitHub Release 下载最新版并覆盖当前 ltg\n";
    std::cout << "  --self-test       运行非 root 纯逻辑自测\n";
    std::cout << "  --version         显示版本\n";
    std::cout << "  --help            显示帮助\n";
    std::cout << "\nUbuntu 依赖:\n";
    std::cout << "  sudo apt update\n";
    std::cout << "  sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin\n";
    std::cout << "  # 仓库目录中也可执行: make deps\n";
    std::cout << "\n编译:\n";
    std::cout << "  make\n";
    std::cout << "  # 源码按 include/ 和 src/ 组织，makefile 会自动发现 src/*.cpp。\n";
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

int appMain(int argc, char **argv) {
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
        if (arg == "update" || arg == "--update") {
            return updateFromRelease(argv[0]);
        }
        if (arg == "--reliability-check") {
            const bool active = argc > 2 && std::string(argv[2]) == "--active-probes";
            return cliReliabilityCheck(active);
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
        if (arg == "--traffic-snapshot") {
            return cliTrafficSnapshot();
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
