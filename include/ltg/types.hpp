#pragma once

#include "ltg/fail2ban_runtime.hpp"
#include "ltg/traffic_accounting.hpp"
#include "ltg/ufw_analysis.hpp"

#include <chrono>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace linux_traffic_guard {

struct MenuItem {
    std::string key;
    std::string title;
    std::string detail;
    bool needsRoot = false;
    std::function<void()> run;
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

} // namespace linux_traffic_guard
