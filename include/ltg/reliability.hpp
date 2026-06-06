#pragma once

#include <string>
#include <vector>

namespace linux_traffic_guard {

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

    bool ok() const;
};

std::string reliabilityStatusLabel(ReliabilityStatus status);
void addReliabilityResult(ReliabilityReport &report,
                          const std::string &group,
                          const std::string &name,
                          ReliabilityStatus status,
                          const std::string &summary,
                          const std::string &evidence = "",
                          const std::string &suggestion = "");

} // namespace linux_traffic_guard
