#include "ltg/core.hpp"

#include "ltg/ui.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
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

std::string coreNowStamp() {
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
} // namespace

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
    backupPath = path + ".ltg." + coreNowStamp() + ".bak";
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
