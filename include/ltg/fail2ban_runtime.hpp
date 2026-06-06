#pragma once

#include <set>
#include <string>

namespace linux_traffic_guard {

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

std::string f2bRuntimeStateLabel(F2bJailRuntimeState state);
F2bJailRuntimeInfo parseFail2banJailStatus(const std::string &jail,
                                           const std::string &rawOutput,
                                           bool clientExists = true);
bool defaultFail2banRuntimeReady(const F2bJailRuntimeInfo &ssh,
                                 const F2bJailRuntimeInfo &scan,
                                 bool requireScanRule);

} // namespace linux_traffic_guard
