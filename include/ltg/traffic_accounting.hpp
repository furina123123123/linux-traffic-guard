#pragma once

#include <set>
#include <string>
#include <vector>

namespace linux_traffic_guard {

inline const std::string kIpTrafficTable = "usp_ip_traffic";
inline const std::string kTrafficHistoryDir = "/var/tmp/linux_traffic_guard_traffic_history_v1";
inline const std::string kTrafficSnapshotService = "linux-traffic-guard-traffic-snapshot.service";
inline const std::string kTrafficSnapshotTimer = "linux-traffic-guard-traffic-snapshot.timer";

std::string trafficHistoryPath(const std::string &name);
std::string nftPortElements(const std::set<int> &ports);
std::string nftCommand(const std::string &body);
std::string nftCommandIgnoreError(const std::string &body);
std::vector<std::string> trafficAccountingRuleCommands(const std::set<int> &ports, bool resetTable);
std::vector<std::string> trafficPortSetUpdateCommands(const std::set<int> &ports);

} // namespace linux_traffic_guard
