#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace linux_traffic_guard {

struct CommandResult {
    int exitCode = 1;
    std::string output;

    bool ok() const {
        return exitCode == 0;
    }
};

int normalizedExitCode(int raw);

class Shell {
public:
    static CommandResult capture(const std::string &command);
    static CommandResult run(const std::string &command);
    static bool exists(const std::string &name);
    static void clearExistsCache();
};

std::string nowStamp();
std::string dateStamp(std::time_t value);
std::string dateTimeStamp(std::time_t value);
std::time_t makeLocalTime(std::tm tm);
bool isLeapYear(int year);
bool isValidCalendarDateParts(int year, int month, int day);
bool parseYmdDate(const std::string &text, bool endOfDay, std::time_t &out);
std::string truncateText(const std::string &value, std::size_t width);
std::string humanBytes(std::uint64_t bytes);
std::string firstNonEmptyLine(const std::string &text);
std::string summarizeCommandResult(const CommandResult &result, std::size_t maxLen = 180);
bool parseVersionTriplet(const std::string &text, std::array<int, 3> &version);
int compareVersionTriplet(const std::array<int, 3> &a, const std::array<int, 3> &b);

inline std::string trim(std::string value) {
    const char *spaces = " \t\r\n";
    const auto first = value.find_first_not_of(spaces);
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(spaces);
    return value.substr(first, last - first + 1);
}

inline std::string removeSpaces(const std::string &value) {
    std::string out;
    for (unsigned char ch : value) {
        if (!std::isspace(ch)) {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

inline std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

inline bool startsWith(const std::string &value, const std::string &prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

inline std::vector<std::string> splitWords(const std::string &text) {
    std::vector<std::string> out;
    std::istringstream input(text);
    std::string word;
    while (input >> word) {
        out.push_back(word);
    }
    return out;
}

inline std::vector<std::string> splitByChar(const std::string &text, char sep) {
    std::vector<std::string> out;
    std::string item;
    std::istringstream input(text);
    while (std::getline(input, item, sep)) {
        out.push_back(item);
    }
    return out;
}

inline std::vector<std::string> splitLines(const std::string &text) {
    std::vector<std::string> lines;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return lines;
}

inline std::string joinWords(const std::vector<std::string> &words, const std::string &sep = " ") {
    std::ostringstream out;
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i != 0) {
            out << sep;
        }
        out << words[i];
    }
    return out.str();
}

inline std::string shellQuote(const std::string &value) {
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

inline std::string commandWithTimeout(const std::string &command, int seconds) {
#ifdef _WIN32
    (void)seconds;
    return command;
#else
    if (seconds <= 0) {
        return command;
    }
    return "timeout --foreground " + std::to_string(seconds) + "s sh -c " + shellQuote(command);
#endif
}

inline std::string curlDownloadCommand(const std::string &url, const std::string &outputPath) {
    return "curl -fsSL --connect-timeout 10 --max-time 180 --retry 2 --retry-delay 1 " +
           shellQuote(url) + " -o " + shellQuote(outputPath);
}

inline std::string wgetDownloadCommand(const std::string &url, const std::string &outputPath) {
    return "wget -q --timeout=20 --tries=2 -O " + shellQuote(outputPath) + " " + shellQuote(url);
}

inline bool readTextFile(const std::string &path, std::string &content) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    std::ostringstream out;
    out << input.rdbuf();
    content = out.str();
    return true;
}

inline bool fileExists(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    return static_cast<bool>(input);
}

bool backupFileIfExists(const std::string &path, std::string &backupPath);

inline bool writeTextFile(const std::string &path, const std::string &content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output << content;
    return static_cast<bool>(output);
}

inline bool ensureDirectory(const std::string &path) {
#ifdef _WIN32
    return std::system(("mkdir " + shellQuote(path) + " >NUL 2>NUL").c_str()) == 0;
#else
    return std::system(("mkdir -p " + shellQuote(path) + " >/dev/null 2>&1").c_str()) == 0;
#endif
}

class IniConfig {
public:
    bool load(const std::string &path);
    void loadString(const std::string &content, const std::string &virtualPath = "");
    std::string toString() const;
    std::string get(const std::string &section, const std::string &key) const;
    std::vector<std::string> sections() const;
    void set(const std::string &section, const std::string &key, const std::string &value);
    bool save(std::string &backupPath) const;

private:
    std::string path_;
    std::vector<std::string> lines_;
};

} // namespace linux_traffic_guard
