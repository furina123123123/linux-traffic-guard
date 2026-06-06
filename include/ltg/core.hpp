#pragma once

#include <string>

namespace linux_traffic_guard {

struct CommandResult {
    int exitCode = 1;
    std::string output;

    bool ok() const {
        return exitCode == 0;
    }
};

} // namespace linux_traffic_guard
