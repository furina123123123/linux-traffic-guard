#pragma once

#include "ltg/protection_bootstrap.hpp"
#include "ltg/fail2ban_runtime.hpp"
#include "ltg/traffic_accounting.hpp"
#include "ltg/tui_routes.hpp"
#include "ltg/runtime_repair.hpp"
#include "ltg/version.hpp"

namespace linux_traffic_guard {

int appMain(int argc, char **argv);

} // namespace linux_traffic_guard
