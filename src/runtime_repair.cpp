#include "ltg/runtime_repair.hpp"

#include "ltg/core.hpp"
#include "ltg/traffic_accounting.hpp"

#include <algorithm>
#include <map>
#include <regex>

namespace linux_traffic_guard {

namespace {

std::string timeoutCommand(const std::string &command, int seconds) {
#ifdef _WIN32
    (void)seconds;
    return command;
#else
    if (seconds <= 0) {
        return command;
    }
    return "timeout --foreground " + std::to_string(seconds) + "s sh -c " + "'" + command + "'";
#endif
}

bool ssLocalAddressIsLoopback(std::string address) {
    if (!address.empty() && address.front() == '[' && address.back() == ']') {
        address = address.substr(1, address.size() - 2);
    }
    return address == "localhost" || address == "::1" || startsWith(address, "127.") ||
           startsWith(address, "[::1]") || address.find("%lo") != std::string::npos;
}

bool extractListeningPortFromSsLocalField(const std::string &localField, int &port) {
    const std::size_t colon = localField.rfind(':');
    if (colon == std::string::npos || colon + 1 >= localField.size()) {
        return false;
    }
    const std::string text = localField.substr(colon + 1);
    if (!isSafeSinglePort(text)) {
        return false;
    }
    const std::string address = localField.substr(0, colon);
    if (ssLocalAddressIsLoopback(address)) {
        return false;
    }
    port = std::stoi(text);
    return true;
}

} // namespace

bool FirstRunSetupReadiness::needsBootstrap() const {
    return !missingTools.empty() || !sshJailLoaded || !scanJailLoaded ||
           (!trafficConfigured && (!existingTrafficPorts.empty() || !recommendedTrafficPorts.empty()));
}

std::string runtimeDependencyPackageForTool(const std::string &tool) {
    if (tool == "nft") return "nftables";
    if (tool == "ss") return "iproute2";
    if (tool == "awk") return "gawk";
    if (tool == "fail2ban-client") return "fail2ban";
    if (tool == "mmdblookup") return "mmdb-bin";
    if (tool == "curl" || tool == "wget") return tool;
    return tool;
}

std::vector<std::string> coreRuntimeTools() {
    return {"nft", "ufw", "fail2ban-client", "systemctl", "journalctl", "ss", "conntrack", "awk", "grep", "curl"};
}

std::string fail2banStackInstallCommand() {
    return timeoutCommand(
        "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban ufw",
        300);
}

std::string ltgRuntimeDependencyInstallCommand() {
    return timeoutCommand(
        "DEBIAN_FRONTEND=noninteractive apt-get update && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin libsqlite3-0",
        300);
}

bool shouldOfferFail2banStackAptInstall(const F2bDependencyReadiness &readiness) {
    return std::find(readiness.missing.begin(), readiness.missing.end(), "fail2ban-client") != readiness.missing.end() ||
           std::find(readiness.missing.begin(), readiness.missing.end(), "ufw") != readiness.missing.end();
}

bool shouldInstallRuntimeDependencies(const std::vector<std::string> &missingCoreTools) {
    return !missingCoreTools.empty();
}

bool dependencyDoctorShouldOfferRepair(const std::vector<std::string> &missingCoreTools,
                                       bool trafficConfigured,
                                       const std::set<int> &recommendedPorts) {
    return !missingCoreTools.empty() || (!trafficConfigured && !recommendedPorts.empty());
}

std::map<std::string, std::string> listeningProcesses() {
    std::map<std::string, std::string> out;
    const CommandResult result = Shell::capture("ss -lntupH 2>/dev/null || true");
    static const std::regex portPattern(R"(:([0-9]+)\s)");
    static const std::regex procPattern(R"(users:\(\(\"([^\"]+)\".*pid=([0-9]+))");
    for (const auto &line : splitLines(result.output)) {
        std::smatch portMatch;
        if (!std::regex_search(line, portMatch, portPattern)) {
            continue;
        }
        std::string proc = "-";
        std::smatch procMatch;
        if (std::regex_search(line, procMatch, procPattern)) {
            proc = procMatch[1].str() + "(" + procMatch[2].str() + ")";
        }
        out[portMatch[1].str()] = proc;
    }
    return out;
}

std::set<int> recommendedTrafficPortsFromSsOutput(const std::string &output) {
    std::set<int> ports;
    const std::set<int> noisyPorts = {68, 123, 323, 5353};
    for (const auto &line : splitLines(output)) {
        const auto fields = splitWords(line);
        if (fields.size() < 5) {
            continue;
        }
        int port = 0;
        if (extractListeningPortFromSsLocalField(fields[4], port) && noisyPorts.count(port) == 0) {
            ports.insert(port);
        }
    }
    return ports;
}

std::set<int> detectRecommendedTrafficPorts() {
    if (!Shell::exists("ss")) {
        return {};
    }
    return recommendedTrafficPortsFromSsOutput(Shell::capture("ss -H -lntup 2>/dev/null || true").output);
}

} // namespace linux_traffic_guard
