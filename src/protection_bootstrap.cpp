#include "ltg/protection_bootstrap.hpp"

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

std::string renderRule2FilterFile() {
    return "[Definition]\n"
           "failregex = ^.*\\[UFW (BLOCK|AUDIT)\\].*SRC=<HOST>.*$\n"
           "ignoreregex =\n";
}

std::string renderUfwDropActionFile() {
    return "[Definition]\n"
           "actionstart =\n"
           "actionstop =\n"
           "actioncheck = ufw status >/dev/null\n"
           "actionban = ufw deny from <ip> to any comment 'f2b:<name> ip:<ip>'\n"
           "actionunban = ufw --force delete deny from <ip> to any\n"
           "\n[Init]\n";
}

std::vector<std::string> ensureFail2banBaselineCommands() {
    return {"systemctl enable --now fail2ban || true",
            "fail2ban-client reload || systemctl restart fail2ban",
            "ufw reload || true"};
}

std::string fail2banSetIpCommand(const std::string &jail, const std::string &verb, const std::string &ip) {
    return "fail2ban-client set " + quoteShellArg(jail) + " " + verb + " " + quoteShellArg(ip) + " || true";
}

std::string fail2banSetIpCommandStrict(const std::string &jail, const std::string &verb, const std::string &ip) {
    return "fail2ban-client set " + quoteShellArg(jail) + " " + verb + " " + quoteShellArg(ip);
}

std::string ufwDenyFromCommand(const std::string &source, const std::string &comment) {
    std::string command = "ufw deny from " + quoteShellArg(source);
    if (!comment.empty()) {
        command += " to any comment " + quoteShellArg(comment);
    }
    return command;
}

std::string ufwAllowFromCommand(const std::string &source) {
    return "ufw allow from " + quoteShellArg(source);
}

std::string ufwDeleteDenyFromCommand(const std::string &source) {
    return "ufw --force delete deny from " + quoteShellArg(source) + " 2>/dev/null || true";
}

std::string ufwPortRuleCommand(const std::string &verb, const std::string &target) {
    return "ufw " + verb + " " + quoteShellArg(target);
}

std::string ufwDeletePortRuleCommand(const std::string &verb, const std::string &target) {
    return "ufw --force delete " + verb + " " + quoteShellArg(target);
}

} // namespace linux_traffic_guard
