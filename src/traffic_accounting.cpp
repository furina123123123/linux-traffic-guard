#include "ltg/traffic_accounting.hpp"

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

} // namespace linux_traffic_guard
