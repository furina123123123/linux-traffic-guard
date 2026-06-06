#include "ltg/core.hpp"

#include "ltg/ui.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>

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

} // namespace linux_traffic_guard
