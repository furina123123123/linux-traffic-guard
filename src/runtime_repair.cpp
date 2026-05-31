#include "ltg/runtime_repair.hpp"

#include <algorithm>

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

} // namespace linux_traffic_guard
