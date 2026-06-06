#include "ltg/fail2ban_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

namespace linux_traffic_guard {
namespace {

std::string trimCopy(const std::string &value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

std::string lowerCopyLocal(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::vector<std::string> splitLinesLocal(const std::string &text) {
    std::vector<std::string> lines;
    std::stringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    if (!text.empty() && text.back() == '\n') {
        lines.push_back("");
    }
    return lines;
}

std::vector<std::string> splitWordsLocal(const std::string &text) {
    std::vector<std::string> words;
    std::istringstream stream(text);
    std::string word;
    while (stream >> word) {
        words.push_back(word);
    }
    return words;
}

bool isIpv4Token(const std::string &token) {
    int parts = 0;
    std::size_t start = 0;
    while (start <= token.size()) {
        const std::size_t dot = token.find('.', start);
        const std::size_t end = dot == std::string::npos ? token.size() : dot;
        if (end == start || end - start > 3) {
            return false;
        }
        int value = 0;
        for (std::size_t i = start; i < end; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(token[i]))) {
                return false;
            }
            value = value * 10 + (token[i] - '0');
        }
        if (value > 255) {
            return false;
        }
        ++parts;
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    return parts == 4;
}

bool isIpv6LikeToken(const std::string &token) {
    if (token.find(':') == std::string::npos) {
        return false;
    }
    bool hasHex = false;
    for (char ch : token) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isxdigit(uch)) {
            hasHex = true;
            continue;
        }
        if (ch == ':' || ch == '.') {
            continue;
        }
        return false;
    }
    return hasHex;
}

bool looksLikeIpAddressToken(const std::string &token) {
    if (token.empty() || token.find('/') != std::string::npos) {
        return false;
    }
    return isIpv4Token(token) || isIpv6LikeToken(token);
}

} // namespace

std::string f2bRuntimeStateLabel(F2bJailRuntimeState state) {
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

F2bJailRuntimeInfo parseFail2banJailStatus(const std::string &jail,
                                           const std::string &rawOutput,
                                           bool clientExists) {
    F2bJailRuntimeInfo info;
    info.jail = jail;
    info.raw = trimCopy(rawOutput);
    const std::string lower = lowerCopyLocal(info.raw);
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

    for (const auto &line : splitLinesLocal(info.raw)) {
        const std::size_t pos = line.find("Banned IP list:");
        if (pos == std::string::npos) {
            continue;
        }
        std::string list = line.substr(pos + std::string("Banned IP list:").size());
        std::replace(list.begin(), list.end(), ',', ' ');
        for (const auto &ip : splitWordsLocal(list)) {
            if (looksLikeIpAddressToken(ip)) {
                info.bannedIps.insert(ip);
            }
        }
    }
    return info;
}

bool defaultFail2banRuntimeReady(const F2bJailRuntimeInfo &ssh,
                                 const F2bJailRuntimeInfo &scan,
                                 bool requireScanRule) {
    return ssh.loaded() && (!requireScanRule || scan.loaded());
}

bool f2bEffectProbeFullyPassed(const F2bEffectProbe &probe) {
    return probe.serviceOk &&
           probe.jailLoaded &&
           probe.banListed &&
           probe.ufwLanded &&
           probe.unbanOk &&
           probe.ufwCleanupOk;
}

} // namespace linux_traffic_guard
