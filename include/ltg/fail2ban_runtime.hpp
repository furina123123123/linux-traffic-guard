#pragma once

#include "ltg/core.hpp"

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

bool f2bEffectProbeFullyPassed(const F2bEffectProbe &probe);

} // namespace linux_traffic_guard
