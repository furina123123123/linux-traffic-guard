#include "ltg/ufw_analysis.hpp"

#include <algorithm>
#include <regex>
#include <sstream>

namespace linux_traffic_guard {

void observeUfwRawLogLine(const std::string &line, UfwLogEvidence &evidence) {
    std::smatch match;
    static const std::regex actionPattern(R"(\[UFW (BLOCK|AUDIT|ALLOW)\])");
    static const std::regex dptPattern(R"(\bDPT=([0-9]+)\b)");
    if (!std::regex_search(line, match, actionPattern)) {
        return;
    }
    ++evidence.rawMatches;
    const std::string action = match[1].str();
    if (action == "BLOCK") {
        ++evidence.block;
    } else if (action == "AUDIT") {
        ++evidence.audit;
    } else if (action == "ALLOW") {
        ++evidence.allow;
    }
    if (!std::regex_search(line, dptPattern)) {
        ++evidence.noDpt;
    }
}

std::string ufwEventKey(const UfwLogEvent &event) {
    return std::to_string(static_cast<long long>(event.ts)) + "|" + event.action + "|" + event.src + "|" + event.dpt;
}

UfwAnalysisReport buildUfwReportFromEvents(const std::string &title,
                                           std::time_t start,
                                           std::time_t end,
                                           const std::string &sourceNote,
                                           const std::vector<UfwLogEvent> &events,
                                           const UfwLogEvidence &evidence) {
    UfwAnalysisReport report;
    report.title = title;
    report.start = start;
    report.end = end;
    report.sourceNote = sourceNote;
    report.validLines = events.size();
    report.evidence = evidence;
    if (report.evidence.validPublic == 0 && !events.empty()) {
        report.evidence.validPublic = events.size();
    }
    const std::time_t allowWindowStart = std::time(nullptr) - 3 * 86400;
    for (const auto &event : events) {
        if (event.action == "ALLOW") {
            if (event.ts >= allowWindowStart) {
                report.allowRecent.push_back({event.src, event.ts});
            }
            continue;
        }
        report.ipDaily[event.src][event.day] += 1;
        if (!event.dpt.empty()) {
            report.portDaily[event.dpt][event.day] += 1;
            report.ipPortDaily[event.src][event.dpt][event.day] += 1;
        }
    }
    return report;
}

int dailyTotal(const std::map<std::string, int> &daily) {
    int total = 0;
    for (const auto &item : daily) {
        total += item.second;
    }
    return total;
}

int dailyPeak(const std::map<std::string, int> &daily) {
    int peak = 0;
    for (const auto &item : daily) {
        peak = std::max(peak, item.second);
    }
    return peak;
}

std::string topPortsText(const UfwAnalysisReport &report, const std::string &ip, std::size_t topN) {
    std::vector<std::pair<std::string, int>> ports;
    const auto ipFound = report.ipPortDaily.find(ip);
    if (ipFound == report.ipPortDaily.end()) {
        return "-";
    }
    for (const auto &port : ipFound->second) {
        ports.push_back({port.first, dailyTotal(port.second)});
    }
    std::sort(ports.begin(), ports.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });
    std::ostringstream out;
    for (std::size_t i = 0; i < ports.size() && i < topN; ++i) {
        if (i != 0) {
            out << " ";
        }
        out << "(" << ports[i].first << "," << ports[i].second << ")";
    }
    return out.str().empty() ? "-" : out.str();
}

std::string ufwTopSignature(const UfwAnalysisReport &report) {
    std::ostringstream out;
    out << "valid=" << report.validLines << ";src=";
    std::vector<std::pair<std::string, int>> sources;
    for (const auto &entry : report.ipDaily) {
        sources.push_back({entry.first, dailyTotal(entry.second)});
    }
    std::sort(sources.begin(), sources.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    for (std::size_t i = 0; i < sources.size() && i < 5; ++i) {
        out << sources[i].first << ":" << sources[i].second << ",";
    }
    out << ";ports=";
    std::vector<std::pair<std::string, int>> ports;
    for (const auto &entry : report.portDaily) {
        ports.push_back({entry.first, dailyTotal(entry.second)});
    }
    std::sort(ports.begin(), ports.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    for (const auto &port : ports) {
        out << port.first << ":" << port.second << ",";
    }
    return out.str();
}

} // namespace linux_traffic_guard
