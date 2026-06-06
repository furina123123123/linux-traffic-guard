#pragma once

#include <cstddef>
#include <cstdlib>
#include <string>
#include <vector>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
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

inline bool fdIsTty(int fd) {
#ifdef _WIN32
    return _isatty(fd) != 0;
#else
    return isatty(fd) != 0;
#endif
}

inline bool shouldUseColor(int fd = STDOUT_FILENO) {
    if (std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
    return fdIsTty(fd);
}

inline std::string colorIf(const std::string &text, const std::string &color, int fd = STDOUT_FILENO) {
    return shouldUseColor(fd) ? color + text + ansi::plain : text;
}

inline std::string uiSection(const std::string &title) {
    return ansi::bold + ansi::cyan + "> " + title + ansi::plain;
}

inline std::string uiGood(const std::string &text) {
    return ansi::green + text + ansi::plain;
}

inline std::string uiWarn(const std::string &text) {
    return ansi::yellow + text + ansi::plain;
}

inline std::string uiInbound(const std::string &text) {
    return ansi::green + text + ansi::plain;
}

inline std::string uiOutbound(const std::string &text) {
    return ansi::cyan + text + ansi::plain;
}

inline std::string uiTotal(const std::string &text) {
    return ansi::bold + ansi::yellow + text + ansi::plain;
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

class Ui {
public:
    static std::string badge(const std::string &label, const std::string &color) {
        return color + "[" + label + "]" + ansi::plain;
    }

    static std::string statusBadge(bool ok, const std::string &okText = "可用", const std::string &badText = "缺失") {
        return ok ? badge(okText, ansi::green) : badge(badText, ansi::yellow);
    }
};

} // namespace linux_traffic_guard
