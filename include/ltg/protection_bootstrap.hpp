#pragma once

#include <string>
#include <vector>

namespace linux_traffic_guard {

inline const std::string kRule1Jail = "sshd";
inline const std::string kRule2Jail = "ufw-slowscan-global";
inline const std::string kFail2banEffectProbeIp = "203.0.113.254";
inline const std::string kJailConf = "/etc/fail2ban/jail.local";
inline const std::string kRule2FilterFile = "/etc/fail2ban/filter.d/ufw-slowscan-global.conf";
inline const std::string kUfwDropActionFile = "/etc/fail2ban/action.d/ufw-drop.conf";

std::string renderRule2FilterFile();
std::string renderUfwDropActionFile();
std::vector<std::string> ensureFail2banBaselineCommands();

std::string fail2banSetIpCommand(const std::string &jail, const std::string &verb, const std::string &ip);
std::string fail2banSetIpCommandStrict(const std::string &jail, const std::string &verb, const std::string &ip);
std::string ufwDenyFromCommand(const std::string &source, const std::string &comment = "");
std::string ufwAllowFromCommand(const std::string &source);
std::string ufwDeleteDenyFromCommand(const std::string &source);
std::string ufwPortRuleCommand(const std::string &verb, const std::string &target);
std::string ufwDeletePortRuleCommand(const std::string &verb, const std::string &target);

} // namespace linux_traffic_guard
