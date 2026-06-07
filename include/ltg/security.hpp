#pragma once

#include "ltg/types.hpp"

#include <set>
#include <string>
#include <vector>

namespace linux_traffic_guard {

bool isValidPositiveInt(const std::string &value);
bool isStrictPositiveNumber(const std::string &value);
bool isValidPositiveNumber(const std::string &value);
bool parseTimeToSeconds(const std::string &text, long long &seconds);
bool isValidTimeToken(const std::string &value);
bool isValidIpv4Address(const std::string &address);
bool isValidIpv4OrCidr(const std::string &value);
bool isValidIpv6Address(std::string address);
bool isValidIpv6OrCidr(const std::string &value);
bool isValidIpOrCidr(const std::string &value);
bool normalizePublicIpAddress(const std::string &raw, std::string &normalized);
bool isSafeIdentifier(const std::string &value);
bool isSafeLogPath(const std::string &value);

std::string configValueOr(const std::string &value, const std::string &fallback);
F2bJailConfig readJailConfig(const std::string &jail);
std::string readJailValue(const std::string &jail, const std::string &key);
bool applyJailConfigValue(const std::string &jail,
                          const std::string &key,
                          const std::string &value,
                          std::string &backupPath,
                          std::string &error);
F2bJailRuntimeInfo fail2banJailRuntimeStatus(const std::string &jail);
std::set<std::string> bannedSetForJail(const std::string &jail);
std::string fail2banJailStatusLine(const std::string &jail);
std::string recentBanLineForJail(const std::string &jail);
std::string policyRoleForJail(const std::string &jail);
std::set<std::string> configuredFail2banJails();
std::set<std::string> runningFail2banJails();
std::vector<F2bPolicyInfo> collectFail2banPolicies(bool includeRuntimeStatus);
std::vector<F2bPolicyInfo> collectDefaultFail2banPolicies(bool includeRuntimeStatus);
std::vector<std::string> customFail2banJailNames();

} // namespace linux_traffic_guard
