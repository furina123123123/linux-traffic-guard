#include "ltg/traffic_accounting.hpp"

#include <algorithm>

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

} // namespace

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
