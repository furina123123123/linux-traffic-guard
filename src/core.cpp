#include "ltg/core.hpp"

#include "ltg/ui.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>

#ifndef _WIN32
#include <sys/wait.h>
#endif

namespace linux_traffic_guard {
namespace {
static_assert(sizeof(CommandResult) > 0, "CommandResult must remain a complete core type");

std::map<std::string, bool> &toolExistsCache() {
    static std::map<std::string, bool> cache;
    return cache;
}

std::mutex &toolExistsCacheMutex() {
    static std::mutex mutex;
    return mutex;
}

} // namespace

std::string nowStamp() {
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

std::string dateStamp(std::time_t value) {
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

std::string dateTimeStamp(std::time_t value) {
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

std::time_t makeLocalTime(std::tm tm) {
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

bool isLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

bool isValidCalendarDateParts(int year, int month, int day) {
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

bool parseYmdDate(const std::string &text, bool endOfDay, std::time_t &out) {
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

std::string truncateText(const std::string &value, std::size_t width) {
    if (value.size() <= width) {
        return value;
    }
    if (width <= 3) {
        return value.substr(0, width);
    }
    return value.substr(0, width - 3) + "...";
}

std::string humanBytes(std::uint64_t bytes) {
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

std::string firstNonEmptyLine(const std::string &text) {
    for (const auto &line : splitLines(text)) {
        const std::string value = trim(stripAnsi(line));
        if (!value.empty()) {
            return value;
        }
    }
    return "";
}

std::string summarizeCommandResult(const CommandResult &result, std::size_t maxLen) {
    std::string summary = firstNonEmptyLine(result.output);
    if (summary.empty()) {
        summary = result.ok() ? "exit 0" : "exit " + std::to_string(result.exitCode);
    }
    return truncateText(summary, maxLen);
}

bool parseVersionTriplet(const std::string &text, std::array<int, 3> &version) {
    const std::regex pattern(R"((\d+)\.(\d+)\.(\d+))");
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return false;
    }
    version = {std::stoi(match[1].str()), std::stoi(match[2].str()), std::stoi(match[3].str())};
    return true;
}

int compareVersionTriplet(const std::array<int, 3> &a, const std::array<int, 3> &b) {
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

int normalizedExitCode(int raw) {
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

CommandResult Shell::capture(const std::string &command) {
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

CommandResult Shell::run(const std::string &command) {
    std::cout << colorIf("$ " + command, ansi::gray) << "\n";
    const int raw = std::system(command.c_str());
    return {normalizedExitCode(raw), ""};
}

bool Shell::exists(const std::string &name) {
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

void Shell::clearExistsCache() {
    std::lock_guard<std::mutex> lock(toolExistsCacheMutex());
    toolExistsCache().clear();
}

bool backupFileIfExists(const std::string &path, std::string &backupPath) {
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

bool IniConfig::load(const std::string &path) {
    path_ = path;
    lines_.clear();
    std::string content;
    if (!readTextFile(path, content)) {
        return true;
    }
    lines_ = splitLines(content);
    return true;
}

void IniConfig::loadString(const std::string &content, const std::string &virtualPath) {
    path_ = virtualPath;
    lines_ = splitLines(content);
}

std::string IniConfig::toString() const {
    return joinWords(lines_, "\n") + (lines_.empty() ? "" : "\n");
}

std::string IniConfig::get(const std::string &section, const std::string &key) const {
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

std::vector<std::string> IniConfig::sections() const {
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

void IniConfig::set(const std::string &section, const std::string &key, const std::string &value) {
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

bool IniConfig::save(std::string &backupPath) const {
    if (!backupFileIfExists(path_, backupPath)) {
        return false;
    }
    return writeTextFile(path_, toString());
}

} // namespace linux_traffic_guard
