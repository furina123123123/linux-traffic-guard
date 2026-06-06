#include "ltg/traffic_accounting.hpp"
#include "ltg/core.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <regex>
#include <sstream>

namespace linux_traffic_guard {

namespace {

std::string quoteShellArg(const std::string &value) {
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') {
            out += "'\\''";
        } else {
            out += ch;
        }
    }
    out += "'";
    return out;
}

std::string trimAscii(const std::string &text) {
    std::size_t first = 0;
    while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first]))) {
        ++first;
    }
    std::size_t last = text.size();
    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1]))) {
        --last;
    }
    return text.substr(first, last - first);
}

std::string localTimeFormat(std::time_t value, const char *format) {
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &value);
#else
    localtime_r(&value, &tm);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), format, &tm);
    return buf;
}

std::time_t makeLocalTrafficTime(std::tm tm) {
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

bool isTrafficLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

bool isValidTrafficCalendarDate(int year, int month, int day) {
    if (year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1) {
        return false;
    }
    static const int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int limit = daysInMonth[month - 1];
    if (month == 2 && isTrafficLeapYear(year)) {
        limit = 29;
    }
    return day <= limit;
}

bool parseTrafficDayLabel(const std::string &value) {
    std::smatch match;
    if (!std::regex_match(value, match, std::regex(R"(([0-9]{4})-([0-9]{2})-([0-9]{2}))"))) {
        return false;
    }
    const int year = std::stoi(match[1].str());
    const int month = std::stoi(match[2].str());
    const int day = std::stoi(match[3].str());
    if (!isValidTrafficCalendarDate(year, month, day)) {
        return false;
    }
    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = 12;
    const std::time_t valueTime = makeLocalTrafficTime(tm);
    if (valueTime == static_cast<std::time_t>(-1)) {
        return false;
    }
    std::tm roundTrip{};
#ifdef _WIN32
    localtime_s(&roundTrip, &valueTime);
#else
    localtime_r(&valueTime, &roundTrip);
#endif
    return roundTrip.tm_year == year - 1900 &&
           roundTrip.tm_mon == month - 1 &&
           roundTrip.tm_mday == day;
}

} // namespace

bool isSafePortList(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t comma = value.find(',', start);
        const std::string item = value.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (item.empty()) {
            return false;
        }
        const std::size_t dash = item.find('-');
        if (dash != std::string::npos && item.find('-', dash + 1) != std::string::npos) {
            return false;
        }
        const std::string first = dash == std::string::npos ? item : item.substr(0, dash);
        const std::string second = dash == std::string::npos ? "" : item.substr(dash + 1);
        const auto parsePort = [](const std::string &text, int &port) {
            if (text.empty()) {
                return false;
            }
            int value = 0;
            for (unsigned char ch : text) {
                if (!std::isdigit(ch)) {
                    return false;
                }
                value = value * 10 + (ch - '0');
                if (value > 65535) {
                    return false;
                }
            }
            if (value < 1) {
                return false;
            }
            port = value;
            return true;
        };
        int firstPort = 0;
        int secondPort = 0;
        if (!parsePort(first, firstPort) ||
            (dash != std::string::npos && !parsePort(second, secondPort))) {
            return false;
        }
        if (second.empty()) {
            secondPort = firstPort;
        }
        if (firstPort > secondPort) {
            return false;
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return true;
}

bool expandPortList(const std::string &value, std::set<int> &ports) {
    ports.clear();
    const std::string cleaned = removeSpaces(value);
    if (!isSafePortList(cleaned)) {
        return false;
    }
    std::size_t start = 0;
    while (start < cleaned.size()) {
        const std::size_t comma = cleaned.find(',', start);
        const std::string item = cleaned.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        const std::size_t dash = item.find('-');
        const int first = std::stoi(dash == std::string::npos ? item : item.substr(0, dash));
        const int last = dash == std::string::npos ? first : std::stoi(item.substr(dash + 1));
        for (int port = first; port <= last; ++port) {
            ports.insert(port);
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return true;
}

std::string joinPorts(const std::set<int> &ports, const std::string &sep) {
    std::ostringstream out;
    bool first = true;
    for (int port : ports) {
        if (!first) {
            out << sep;
        }
        first = false;
        out << port;
    }
    return out.str();
}

std::string humanPortList(const std::set<int> &ports, std::size_t limit) {
    if (ports.empty()) {
        return "未记录";
    }
    std::ostringstream out;
    std::size_t shown = 0;
    for (int port : ports) {
        if (shown > 0) {
            out << ", ";
        }
        out << port;
        ++shown;
        if (shown >= limit && ports.size() > limit) {
            out << " ... +" << (ports.size() - limit);
            break;
        }
    }
    return out.str();
}

TrafficPortInputResolution resolveTrafficPortInput(const std::string &input,
                                                   const std::set<int> &knownPorts,
                                                   const std::set<int> &recommendedPorts) {
    TrafficPortInputResolution result;
    const std::string value = removeSpaces(input);
    if (value.empty()) {
        if (!knownPorts.empty()) {
            result.ok = true;
            result.repairExisting = true;
            result.ports = knownPorts;
            return result;
        }
        if (!recommendedPorts.empty()) {
            result.ok = true;
            result.ports = recommendedPorts;
            return result;
        }
        result.error = "未发现可自动启用的监听端口，也没有输入端口。";
        return result;
    }
    if (!isSafePortList(value) || !expandPortList(value, result.ports)) {
        result.error = "端口列表不合法。";
        return result;
    }
    result.ok = true;
    return result;
}

std::set<int> setDifference(const std::set<int> &left, const std::set<int> &right) {
    std::set<int> out;
    std::set_difference(left.begin(), left.end(), right.begin(), right.end(), std::inserter(out, out.begin()));
    return out;
}

std::set<int> setIntersection(const std::set<int> &left, const std::set<int> &right) {
    std::set<int> out;
    std::set_intersection(left.begin(), left.end(), right.begin(), right.end(), std::inserter(out, out.begin()));
    return out;
}

std::set<int> setUnion(const std::set<int> &left, const std::set<int> &right) {
    std::set<int> out;
    std::set_union(left.begin(), left.end(), right.begin(), right.end(), std::inserter(out, out.begin()));
    return out;
}

void parseNftPortListInto(const std::string &text, std::set<int> &ports) {
    const std::regex rangePattern(R"(([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?)");
    for (std::sregex_iterator it(text.begin(), text.end(), rangePattern), end; it != end; ++it) {
        const int first = std::stoi((*it)[1].str());
        const int last = (*it)[2].matched ? std::stoi((*it)[2].str()) : first;
        if (first < 1 || last > 65535 || first > last) {
            continue;
        }
        for (int port = first; port <= last; ++port) {
            ports.insert(port);
        }
    }
}

bool isSafeSinglePort(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    int port = 0;
    for (unsigned char ch : value) {
        if (!std::isdigit(ch)) {
            return false;
        }
        port = port * 10 + (ch - '0');
        if (port > 65535) {
            return false;
        }
    }
    return port >= 1;
}

bool isSafePortOrEmpty(const std::string &value) {
    return value.empty() || isSafePortList(value);
}

std::string trafficHistoryPath(const std::string &name) {
    return kTrafficHistoryDir + "/" + name;
}

std::string nftPortElements(const std::set<int> &ports) {
    std::string out = "{ ";
    bool first = true;
    for (int port : ports) {
        if (!first) {
            out += ", ";
        }
        out += std::to_string(port);
        first = false;
    }
    out += " }";
    return out;
}

std::string nftCommand(const std::string &body) {
    return "nft " + quoteShellArg(body);
}

std::string nftCommandIgnoreError(const std::string &body) {
    return nftCommand(body) + " 2>/dev/null || true";
}

std::vector<std::string> trafficAccountingRuleCommands(const std::set<int> &ports, bool resetTable) {
    const std::string table = "inet " + kIpTrafficTable;
    const std::string portElements = nftPortElements(ports);
    std::vector<std::string> commands;
    if (resetTable) {
        commands.push_back(nftCommandIgnoreError("delete table " + table));
    }
    commands.push_back(nftCommandIgnoreError("add table " + table));
    commands.push_back(nftCommandIgnoreError("add set " + table + " tracked_ports { type inet_service; flags interval; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv4_download { type ipv4_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv4_upload { type ipv4_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv6_download { type ipv6_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("add set " + table + " ipv6_upload { type ipv6_addr . inet_service; flags dynamic; counter; }"));
    commands.push_back(nftCommandIgnoreError("flush set " + table + " tracked_ports"));
    commands.push_back(nftCommand("add element " + table + " tracked_ports " + portElements));
    for (const auto &chain : {"input_account", "output_account", "forward_account"}) {
        commands.push_back(nftCommandIgnoreError("flush chain " + table + " " + std::string(chain)));
        commands.push_back(nftCommandIgnoreError("delete chain " + table + " " + std::string(chain)));
    }
    commands.push_back(nftCommand("add chain " + table + " input_account { type filter hook input priority -150; policy accept; }"));
    commands.push_back(nftCommand("add chain " + table + " output_account { type filter hook output priority -150; policy accept; }"));
    commands.push_back(nftCommand("add chain " + table + " forward_account { type filter hook forward priority -150; policy accept; }"));
    commands.push_back(nftCommand("add rule " + table + " input_account tcp dport @tracked_ports update @ipv4_download { ip saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account udp dport @tracked_ports update @ipv4_download { ip saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account meta nfproto ipv6 tcp dport @tracked_ports update @ipv6_download { ip6 saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " input_account meta nfproto ipv6 udp dport @tracked_ports update @ipv6_download { ip6 saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account tcp sport @tracked_ports update @ipv4_upload { ip daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account udp sport @tracked_ports update @ipv4_upload { ip daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account meta nfproto ipv6 tcp sport @tracked_ports update @ipv6_upload { ip6 daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " output_account meta nfproto ipv6 udp sport @tracked_ports update @ipv6_upload { ip6 daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account tcp dport @tracked_ports update @ipv4_download { ip saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account udp dport @tracked_ports update @ipv4_download { ip saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account tcp sport @tracked_ports update @ipv4_upload { ip daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account udp sport @tracked_ports update @ipv4_upload { ip daddr . udp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp dport @tracked_ports update @ipv6_download { ip6 saddr . tcp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp dport @tracked_ports update @ipv6_download { ip6 saddr . udp dport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 tcp sport @tracked_ports update @ipv6_upload { ip6 daddr . tcp sport }"));
    commands.push_back(nftCommand("add rule " + table + " forward_account meta nfproto ipv6 udp sport @tracked_ports update @ipv6_upload { ip6 daddr . udp sport }"));
    return commands;
}

std::vector<std::string> trafficPortSetUpdateCommands(const std::set<int> &ports) {
    const std::string table = "inet " + kIpTrafficTable;
    std::vector<std::string> commands = {
        nftCommandIgnoreError("add set " + table + " tracked_ports { type inet_service; flags interval; }"),
        nftCommandIgnoreError("flush set " + table + " tracked_ports"),
    };
    if (!ports.empty()) {
        commands.push_back(nftCommand("add element " + table + " tracked_ports " + nftPortElements(ports)));
    }
    return commands;
}

std::string localDayStamp(std::time_t value) {
    return localTimeFormat(value, "%Y-%m-%d");
}

std::string localMonthStamp(std::time_t value) {
    return localTimeFormat(value, "%Y-%m");
}

std::string localYearStamp(std::time_t value) {
    return localTimeFormat(value, "%Y");
}

std::string currentTrafficPeriodLabel(TrafficPeriodMode mode) {
    const std::time_t now = std::time(nullptr);
    if (mode == TrafficPeriodMode::Day) {
        return localDayStamp(now);
    }
    if (mode == TrafficPeriodMode::Year) {
        return localYearStamp(now);
    }
    return localMonthStamp(now);
}

std::string recentTrafficDaysLabel(const std::vector<std::string> &periods, std::size_t days) {
    if (periods.empty()) {
        return "最近" + std::to_string(days) + "天";
    }
    const auto range = std::minmax_element(periods.begin(), periods.end());
    return "最近" + std::to_string(days) + "天（" + *range.first + " ~ " + *range.second + "）";
}

std::string trafficPeriodModeTitle(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "日流量";
    if (mode == TrafficPeriodMode::Year) return "年流量";
    return "月流量";
}

std::string trafficPeriodModeDetailTitle(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "按日流量";
    if (mode == TrafficPeriodMode::Year) return "按年流量";
    return "按月流量";
}

std::string trafficPeriodModeUnit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "天";
    if (mode == TrafficPeriodMode::Year) return "年";
    return "月";
}

std::string trafficPeriodModeColumn(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "日期";
    if (mode == TrafficPeriodMode::Year) return "年份";
    return "月份";
}

std::string trafficPeriodVnstatCommand(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "vnstat -d";
    if (mode == TrafficPeriodMode::Year) return "vnstat -y";
    return "vnstat -m";
}

std::string trafficPeriodSample(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return "2026-05-04";
    if (mode == TrafficPeriodMode::Year) return "2026";
    return "2026-05";
}

std::size_t defaultTrafficRollingLimit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return 31;
    if (mode == TrafficPeriodMode::Year) return 10;
    return 24;
}

std::size_t maxTrafficRollingLimit(TrafficPeriodMode mode) {
    if (mode == TrafficPeriodMode::Day) return 366;
    if (mode == TrafficPeriodMode::Year) return 50;
    return 120;
}

bool parseTrafficRollingLimit(const std::string &text, TrafficPeriodMode mode, std::size_t &limit) {
    const std::string value = trimAscii(text);
    if (value.empty()) {
        limit = defaultTrafficRollingLimit(mode);
        return true;
    }
    if (!std::regex_match(value, std::regex(R"([0-9]+)"))) {
        return false;
    }
    const std::size_t maxLimit = maxTrafficRollingLimit(mode);
    std::size_t parsed = 0;
    for (unsigned char ch : value) {
        const std::size_t digit = static_cast<std::size_t>(ch - '0');
        if (parsed > (maxLimit - digit) / 10) {
            return false;
        }
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0 || parsed > maxLimit) {
        return false;
    }
    limit = parsed;
    return true;
}

std::vector<std::string> recentTrafficDayPeriods(std::size_t days) {
    std::vector<std::string> periods;
    if (days == 0) {
        return periods;
    }
    const std::time_t now = std::time(nullptr);
    std::tm base{};
#ifdef _WIN32
    localtime_s(&base, &now);
#else
    localtime_r(&now, &base);
#endif
    base.tm_hour = 12;
    base.tm_min = 0;
    base.tm_sec = 0;
    for (std::size_t offset = 0; offset < days; ++offset) {
        std::tm candidate = base;
        candidate.tm_mday -= static_cast<int>(offset);
        periods.push_back(localDayStamp(makeLocalTrafficTime(candidate)));
    }
    return periods;
}

bool isValidTrafficPeriodLabel(TrafficPeriodMode mode, const std::string &value) {
    if (mode == TrafficPeriodMode::Day) {
        return parseTrafficDayLabel(value);
    }
    if (mode == TrafficPeriodMode::Month) {
        std::smatch match;
        if (!std::regex_match(value, match, std::regex(R"(([0-9]{4})-([0-9]{2}))"))) {
            return false;
        }
        const int year = std::stoi(match[1].str());
        const int month = std::stoi(match[2].str());
        return year >= 1970 && year <= 9999 && month >= 1 && month <= 12;
    }
    return std::regex_match(value, std::regex(R"([0-9]{4})"));
}

std::string trafficKey(const TrafficRow &row) {
    return row.family + "\t" + row.direction + "\t" + row.ip + "\t" + row.port;
}

bool sameOrHigherCounters(const TrafficRow &current, const TrafficRow &previous) {
    return current.bytes >= previous.bytes && current.packets >= previous.packets;
}

std::vector<TrafficDelta> computeTrafficDeltasForBuckets(const std::vector<TrafficRow> &current,
                                                         const std::map<std::string, TrafficRow> &previous,
                                                         std::time_t sampledAt,
                                                         const std::string &day,
                                                         const std::string &month,
                                                         const std::string &year,
                                                         std::size_t &resetRows) {
    std::vector<TrafficDelta> deltas;
    resetRows = 0;
    for (const auto &row : current) {
        const auto found = previous.find(trafficKey(row));
        if (found == previous.end()) {
            if (row.bytes > 0 || row.packets > 0) {
                deltas.push_back({row, sampledAt, day, month, year});
            }
            continue;
        }
        if (!sameOrHigherCounters(row, found->second)) {
            ++resetRows;
            continue;
        }
        TrafficRow delta = row;
        delta.bytes -= found->second.bytes;
        delta.packets -= found->second.packets;
        if (delta.bytes == 0 && delta.packets == 0) {
            continue;
        }
        deltas.push_back({delta, sampledAt, day, month, year});
    }
    return deltas;
}

std::vector<TrafficSummaryRow> sortTrafficSummaryRows(std::vector<TrafficSummaryRow> rows) {
    std::sort(rows.begin(), rows.end(), [](const TrafficSummaryRow &a, const TrafficSummaryRow &b) {
        if (a.totalBytes() != b.totalBytes()) {
            return a.totalBytes() > b.totalBytes();
        }
        if (a.ip != b.ip) {
            return a.ip < b.ip;
        }
        return a.port < b.port;
    });
    return rows;
}

std::vector<TrafficSummaryRow> aggregateTraffic(const std::vector<TrafficRow> &rows, TrafficGroupMode mode) {
    std::map<std::string, TrafficSummaryRow> grouped;
    for (const auto &row : rows) {
        std::string key = row.ip;
        if (mode == TrafficGroupMode::Port) {
            key = row.port;
        } else if (mode == TrafficGroupMode::IpPort) {
            key = row.ip + "\n" + row.port;
        }
        auto &slot = grouped[key];
        slot.ip = mode == TrafficGroupMode::Port ? "*" : row.ip;
        slot.port = mode == TrafficGroupMode::Ip ? "*" : row.port;
        if (row.direction == "上传") {
            slot.uploadBytes += row.bytes;
            slot.uploadPackets += row.packets;
        } else {
            slot.downloadBytes += row.bytes;
            slot.downloadPackets += row.packets;
        }
    }
    std::vector<TrafficSummaryRow> out;
    for (auto entry : grouped) {
        out.push_back(entry.second);
    }
    return sortTrafficSummaryRows(std::move(out));
}

std::vector<TrafficSummaryRow> aggregateTrafficByIp(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, TrafficGroupMode::Ip);
}

std::vector<TrafficSummaryRow> aggregateTrafficByPort(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, TrafficGroupMode::Port);
}

std::vector<TrafficSummaryRow> aggregateTrafficByIpPort(const std::vector<TrafficRow> &rows) {
    return aggregateTraffic(rows, TrafficGroupMode::IpPort);
}

std::vector<TrafficRow> filterTrafficRowsByPort(const std::vector<TrafficRow> &rows, const std::string &port) {
    std::vector<TrafficRow> out;
    for (const auto &row : rows) {
        if (row.port == port) {
            out.push_back(row);
        }
    }
    return out;
}

TrafficSummaryRow sumTrafficSummaryRows(const std::vector<TrafficSummaryRow> &rows) {
    TrafficSummaryRow total;
    total.ip = "*";
    total.port = "*";
    for (const auto &row : rows) {
        total.downloadBytes += row.downloadBytes;
        total.uploadBytes += row.uploadBytes;
        total.downloadPackets += row.downloadPackets;
        total.uploadPackets += row.uploadPackets;
    }
    return total;
}

} // namespace linux_traffic_guard
