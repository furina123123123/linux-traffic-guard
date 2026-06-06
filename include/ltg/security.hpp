#pragma once

#include <string>

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

} // namespace linux_traffic_guard
