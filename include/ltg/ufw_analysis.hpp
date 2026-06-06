#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace linux_traffic_guard {

inline const std::string kUnknownUfwPort = "UNKNOWN";

struct UfwHit {
    std::string value;
    std::string geo;
    std::uint64_t count = 0;
    std::uint64_t peak = 0;
    std::string topPort;
    std::uint64_t topPortCount = 0;
    std::string risk;
    std::string suggestion;
};

struct UfwLogEvent {
    std::time_t ts = 0;
    std::string day;
    std::string action;
    std::string src;
    std::string dpt;
};

struct UfwLogEvidence {
    std::size_t rawMatches = 0;
    std::size_t validPublic = 0;
    std::size_t filteredSource = 0;
    std::size_t noDpt = 0;
    std::size_t block = 0;
    std::size_t audit = 0;
    std::size_t allow = 0;
    bool cacheCovered = false;
    std::string cacheRanges;
    std::string liveSource;
};

struct UfwAnalysisReport {
    std::string title;
    std::time_t start = 0;
    std::time_t end = 0;
    std::size_t validLines = 0;
    std::string sourceNote;
    UfwLogEvidence evidence;
    std::map<std::string, std::map<std::string, int>> ipDaily;
    std::map<std::string, std::map<std::string, int>> portDaily;
    std::map<std::string, std::map<std::string, std::map<std::string, int>>> ipPortDaily;
    std::vector<std::pair<std::string, std::time_t>> allowRecent;
};

void observeUfwRawLogLine(const std::string &line, UfwLogEvidence &evidence);
std::string ufwEventKey(const UfwLogEvent &event);
UfwAnalysisReport buildUfwReportFromEvents(const std::string &title,
                                           std::time_t start,
                                           std::time_t end,
                                           const std::string &sourceNote,
                                           const std::vector<UfwLogEvent> &events,
                                           const UfwLogEvidence &evidence = {});
int dailyTotal(const std::map<std::string, int> &daily);
int dailyPeak(const std::map<std::string, int> &daily);
std::string topPortsText(const UfwAnalysisReport &report, const std::string &ip, std::size_t topN = 5);
std::string ufwTopSignature(const UfwAnalysisReport &report);

} // namespace linux_traffic_guard
