#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace linux_traffic_guard {

inline const std::string kIpTrafficTable = "usp_ip_traffic";
inline const std::string kTrafficHistoryDir = "/var/tmp/linux_traffic_guard_traffic_history_v1";
inline const std::string kTrafficSnapshotService = "linux-traffic-guard-traffic-snapshot.service";
inline const std::string kTrafficSnapshotTimer = "linux-traffic-guard-traffic-snapshot.timer";

struct TrafficRow {
    std::string ip;
    std::string port;
    std::string direction;
    std::string family;
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
};

struct TrafficSummaryRow {
    std::string ip;
    std::string port;
    std::string geo;
    std::uint64_t downloadBytes = 0;
    std::uint64_t uploadBytes = 0;
    std::uint64_t downloadPackets = 0;
    std::uint64_t uploadPackets = 0;

    std::uint64_t totalBytes() const {
        return downloadBytes + uploadBytes;
    }

    std::uint64_t totalPackets() const {
        return downloadPackets + uploadPackets;
    }
};

struct TrafficDelta {
    TrafficRow row;
    std::time_t sampledAt = 0;
    std::string day;
    std::string month;
    std::string year;
};

struct TrafficSnapshotResult {
    bool ok = false;
    std::time_t sampledAt = 0;
    std::size_t liveRows = 0;
    std::size_t deltaRows = 0;
    std::size_t resetRows = 0;
    std::string message;
};

struct TrafficPeriodTotal {
    std::string period;
    std::uint64_t downloadBytes = 0;
    std::uint64_t uploadBytes = 0;
    std::uint64_t downloadPackets = 0;
    std::uint64_t uploadPackets = 0;

    std::uint64_t totalBytes() const {
        return downloadBytes + uploadBytes;
    }

    std::uint64_t totalPackets() const {
        return downloadPackets + uploadPackets;
    }
};

struct TrafficPeriodPortRow {
    std::string period;
    std::string port;
    std::uint64_t downloadBytes = 0;
    std::uint64_t uploadBytes = 0;
    std::uint64_t downloadPackets = 0;
    std::uint64_t uploadPackets = 0;

    std::uint64_t totalBytes() const {
        return downloadBytes + uploadBytes;
    }

    std::uint64_t totalPackets() const {
        return downloadPackets + uploadPackets;
    }
};

enum class TrafficPeriodMode {
    Day,
    Month,
    Year
};

enum class TrafficGroupMode {
    Ip,
    Port,
    IpPort
};

std::string trafficHistoryPath(const std::string &name);
std::string nftPortElements(const std::set<int> &ports);
std::string nftCommand(const std::string &body);
std::string nftCommandIgnoreError(const std::string &body);
std::vector<std::string> trafficAccountingRuleCommands(const std::set<int> &ports, bool resetTable);
std::vector<std::string> trafficPortSetUpdateCommands(const std::set<int> &ports);
std::string localDayStamp(std::time_t value);
std::string localMonthStamp(std::time_t value);
std::string localYearStamp(std::time_t value);
std::string currentTrafficPeriodLabel(TrafficPeriodMode mode);
std::string recentTrafficDaysLabel(const std::vector<std::string> &periods, std::size_t days);
std::string trafficPeriodModeTitle(TrafficPeriodMode mode);
std::string trafficPeriodModeDetailTitle(TrafficPeriodMode mode);
std::string trafficPeriodModeUnit(TrafficPeriodMode mode);
std::string trafficPeriodModeColumn(TrafficPeriodMode mode);
std::string trafficPeriodVnstatCommand(TrafficPeriodMode mode);
std::string trafficPeriodSample(TrafficPeriodMode mode);
std::size_t defaultTrafficRollingLimit(TrafficPeriodMode mode);
std::size_t maxTrafficRollingLimit(TrafficPeriodMode mode);
bool parseTrafficRollingLimit(const std::string &text, TrafficPeriodMode mode, std::size_t &limit);
std::vector<std::string> recentTrafficDayPeriods(std::size_t days);
bool isValidTrafficPeriodLabel(TrafficPeriodMode mode, const std::string &value);
std::string trafficKey(const TrafficRow &row);
bool sameOrHigherCounters(const TrafficRow &current, const TrafficRow &previous);
std::vector<TrafficDelta> computeTrafficDeltasForBuckets(const std::vector<TrafficRow> &current,
                                                         const std::map<std::string, TrafficRow> &previous,
                                                         std::time_t sampledAt,
                                                         const std::string &day,
                                                         const std::string &month,
                                                         const std::string &year,
                                                         std::size_t &resetRows);
std::vector<TrafficSummaryRow> sortTrafficSummaryRows(std::vector<TrafficSummaryRow> rows);
std::vector<TrafficSummaryRow> aggregateTraffic(const std::vector<TrafficRow> &rows, TrafficGroupMode mode);
std::vector<TrafficSummaryRow> aggregateTrafficByIp(const std::vector<TrafficRow> &rows);
std::vector<TrafficSummaryRow> aggregateTrafficByPort(const std::vector<TrafficRow> &rows);
std::vector<TrafficSummaryRow> aggregateTrafficByIpPort(const std::vector<TrafficRow> &rows);
std::vector<TrafficRow> filterTrafficRowsByPort(const std::vector<TrafficRow> &rows, const std::string &port);
TrafficSummaryRow sumTrafficSummaryRows(const std::vector<TrafficSummaryRow> &rows);

} // namespace linux_traffic_guard
