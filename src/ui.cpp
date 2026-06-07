#include "ltg/ui.hpp"

#include <algorithm>
#include <cstdint>
#include <sstream>

namespace linux_traffic_guard {

namespace {

bool readAnsiSequence(const std::string &value, std::size_t &index, std::string &sequence) {
    if (index >= value.size() || value[index] != '\033') {
        return false;
    }
    sequence.clear();
    sequence.push_back(value[index++]);
    if (index >= value.size()) {
        return true;
    }
    sequence.push_back(value[index++]);
    while (index < value.size()) {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        sequence.push_back(static_cast<char>(ch));
        ++index;
        if (ch >= 0x40 && ch <= 0x7e) {
            break;
        }
    }
    return true;
}

bool readUtf8Char(const std::string &value, std::size_t &index, std::string &bytes, std::uint32_t &codepoint) {
    if (index >= value.size()) {
        return false;
    }
    const unsigned char lead = static_cast<unsigned char>(value[index]);
    std::size_t len = 1;
    codepoint = lead;
    if ((lead & 0x80) == 0) {
        len = 1;
        codepoint = lead;
    } else if ((lead & 0xe0) == 0xc0) {
        len = 2;
        codepoint = lead & 0x1f;
    } else if ((lead & 0xf0) == 0xe0) {
        len = 3;
        codepoint = lead & 0x0f;
    } else if ((lead & 0xf8) == 0xf0) {
        len = 4;
        codepoint = lead & 0x07;
    }
    if (index + len > value.size()) {
        len = 1;
        codepoint = lead;
    }
    bytes = value.substr(index, len);
    for (std::size_t i = 1; i < len; ++i) {
        const unsigned char ch = static_cast<unsigned char>(value[index + i]);
        if ((ch & 0xc0) != 0x80) {
            bytes = value.substr(index, 1);
            codepoint = lead;
            len = 1;
            break;
        }
        codepoint = (codepoint << 6) | (ch & 0x3f);
    }
    index += len;
    return true;
}

int codepointWidth(std::uint32_t cp) {
    if (cp == 0 || cp < 32 || (cp >= 0x7f && cp < 0xa0)) {
        return 0;
    }
    if ((cp >= 0x0300 && cp <= 0x036f) ||
        (cp >= 0x1ab0 && cp <= 0x1aff) ||
        (cp >= 0x1dc0 && cp <= 0x1dff) ||
        (cp >= 0x20d0 && cp <= 0x20ff) ||
        (cp >= 0xfe20 && cp <= 0xfe2f)) {
        return 0;
    }
    if ((cp >= 0x1100 && cp <= 0x115f) ||
        (cp >= 0x2e80 && cp <= 0xa4cf) ||
        (cp >= 0xac00 && cp <= 0xd7a3) ||
        (cp >= 0xf900 && cp <= 0xfaff) ||
        (cp >= 0xfe10 && cp <= 0xfe19) ||
        (cp >= 0xfe30 && cp <= 0xfe6f) ||
        (cp >= 0xff00 && cp <= 0xff60) ||
        (cp >= 0xffe0 && cp <= 0xffe6) ||
        (cp >= 0x20000 && cp <= 0x3fffd)) {
        return 2;
    }
    return 1;
}

std::string bufferCell(const std::string &value, int width) {
    return padRightCells(fitLine(value, width), width);
}

} // namespace

int visibleWidth(const std::string &value) {
    int width = 0;
    for (std::size_t i = 0; i < value.size();) {
        if (value[i] == '\033') {
            std::string sequence;
            readAnsiSequence(value, i, sequence);
            continue;
        }
        std::string bytes;
        std::uint32_t cp = 0;
        if (!readUtf8Char(value, i, bytes, cp)) {
            break;
        }
        width += codepointWidth(cp);
    }
    return width;
}

std::string padRightCells(const std::string &value, int width) {
    const int current = visibleWidth(value);
    if (current >= width) {
        return fitLine(value, width);
    }
    return value + std::string(static_cast<std::size_t>(width - current), ' ');
}

std::string fitLine(const std::string &line, int width) {
    if (width <= 0) {
        return "";
    }
    if (visibleWidth(line) <= width) {
        return line;
    }
    std::string out;
    bool inColor = false;
    int visible = 0;
    for (std::size_t i = 0; i < line.size();) {
        if (line[i] == '\033') {
            std::string sequence;
            readAnsiSequence(line, i, sequence);
            out += sequence;
            if (!sequence.empty() && sequence.back() == 'm') {
                inColor = sequence != ansi::plain && sequence != "\033[0m";
            }
            continue;
        }
        std::string bytes;
        std::uint32_t cp = 0;
        if (!readUtf8Char(line, i, bytes, cp)) {
            break;
        }
        const int cellWidth = codepointWidth(cp);
        if (visible + cellWidth > width) {
            break;
        }
        out += bytes;
        visible += cellWidth;
    }
    if (inColor) {
        out += ansi::plain;
    }
    return out;
}

std::string menuLine(const std::string &key,
                     const std::string &title,
                     const std::string &detail,
                     bool selected) {
    std::ostringstream row;
    if (selected) {
        row << "> "
            << padRightCells(key, 4)
            << padRightCells(title, 24)
            << detail;
        return ansi::inverse + ansi::cyan + row.str() + ansi::plain;
    }
    row << "  "
        << padRightCells(ansi::cyan + key + ansi::plain, 4)
        << padRightCells(ansi::bold + title + ansi::plain, 24)
        << ansi::gray + detail + ansi::plain;
    return row.str();
}

std::string bufferTableRule(const std::vector<int> &widths) {
    int total = 2;
    for (int width : widths) {
        total += width + 2;
    }
    return ansi::gray + std::string(static_cast<std::size_t>(std::max(8, total)), '-') + ansi::plain;
}

std::string bufferTableRow(const std::vector<std::string> &values, const std::vector<int> &widths, bool strong) {
    std::ostringstream out;
    out << "  ";
    for (std::size_t i = 0; i < widths.size(); ++i) {
        const std::string value = i < values.size() ? values[i] : "";
        if (strong) {
            out << ansi::bold;
        }
        out << bufferCell(value, widths[i]);
        if (strong) {
            out << ansi::plain;
        }
        out << "  ";
    }
    return out.str();
}

} // namespace linux_traffic_guard

namespace linux_traffic_guard::translation_units {
void ui_anchor() {}
} // namespace linux_traffic_guard::translation_units
