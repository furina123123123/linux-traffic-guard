#pragma once

#include <set>
#include <string>
#include <vector>

namespace linux_traffic_guard {

struct F2bDependencyReadiness {
    bool ok = false;
    std::vector<std::string> missing;
};

struct FirstRunSetupReadiness {
    std::vector<std::string> missingTools;
    bool sshJailLoaded = false;
    bool scanJailLoaded = false;
    bool geoReaderReady = false;
    bool geoDatabaseReady = false;
    bool trafficConfigured = false;
    std::set<int> existingTrafficPorts;
    std::set<int> recommendedTrafficPorts;

    bool needsBootstrap() const;
};

std::string runtimeDependencyPackageForTool(const std::string &tool);
std::vector<std::string> coreRuntimeTools();
std::string fail2banStackInstallCommand();
std::string ltgRuntimeDependencyInstallCommand();
bool shouldOfferFail2banStackAptInstall(const F2bDependencyReadiness &readiness);
bool shouldInstallRuntimeDependencies(const std::vector<std::string> &missingCoreTools);
bool dependencyDoctorShouldOfferRepair(const std::vector<std::string> &missingCoreTools,
                                       bool trafficConfigured,
                                       const std::set<int> &recommendedPorts);

} // namespace linux_traffic_guard
