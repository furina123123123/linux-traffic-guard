#include "ltg/reliability.hpp"

#include <algorithm>

namespace linux_traffic_guard {

bool ReliabilityReport::ok() const {
    return std::none_of(results.begin(), results.end(), [](const ReliabilityCheckResult &result) {
        return result.status == ReliabilityStatus::Fail || result.status == ReliabilityStatus::Permission;
    });
}

std::string reliabilityStatusLabel(ReliabilityStatus status) {
    switch (status) {
    case ReliabilityStatus::Pass:
        return "通过";
    case ReliabilityStatus::Fail:
        return "失败";
    case ReliabilityStatus::Warning:
        return "不能确认";
    case ReliabilityStatus::Permission:
        return "权限不足";
    case ReliabilityStatus::Skipped:
    default:
        return "跳过";
    }
}

void addReliabilityResult(ReliabilityReport &report,
                          const std::string &group,
                          const std::string &name,
                          ReliabilityStatus status,
                          const std::string &summary,
                          const std::string &evidence,
                          const std::string &suggestion) {
    report.results.push_back({group, name, status, summary, evidence, suggestion});
}

} // namespace linux_traffic_guard
