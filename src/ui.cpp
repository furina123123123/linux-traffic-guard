#include "ltg/ui.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <regex>
#include <sstream>

#ifdef _WIN32
#include <io.h>
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#else
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#endif

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

class InputReader {
public:
    InputEvent readEvent(int timeoutMs) {
        fill(timeoutMs);
        if (buffer_.empty()) {
            return {InputKind::None, 0};
        }
        const unsigned char ch = pop();
        if (ch == 3) {
            return {InputKind::CtrlC, 0};
        }
        if (ch == '\r' || ch == '\n') {
            return {InputKind::Character, '\n'};
        }
        if (ch == 27) {
            return parseEscape();
        }
        return {InputKind::Character, static_cast<char>(ch)};
    }

private:
    std::deque<unsigned char> buffer_;

    unsigned char pop() {
        const unsigned char ch = buffer_.front();
        buffer_.pop_front();
        return ch;
    }

    void fill(int timeoutMs) {
#ifdef _WIN32
        (void)timeoutMs;
        if (buffer_.empty()) {
            char ch = 0;
            if (std::cin.get(ch)) {
                buffer_.push_back(static_cast<unsigned char>(ch));
            }
        }
#else
        fd_set set;
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        timeval timeout{};
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;
        const int ready = select(STDIN_FILENO + 1, &set, nullptr, nullptr, &timeout);
        if (ready <= 0) {
            return;
        }
        unsigned char bytes[128]{};
        const ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
        if (count <= 0) {
            return;
        }
        for (ssize_t i = 0; i < count; ++i) {
            buffer_.push_back(bytes[i]);
        }
#endif
    }

    bool needMoreEscapeBytes(const std::string &seq) const {
        if (seq.empty()) {
            return true;
        }
        if (seq[0] == '[') {
            if (seq.size() == 1) {
                return true;
            }
            if (seq[1] == '<') {
                const char last = seq.back();
                return last != 'M' && last != 'm';
            }
            const unsigned char last = static_cast<unsigned char>(seq.back());
            return !(last >= 0x40 && last <= 0x7e);
        }
        if (seq[0] == 'O') {
            return seq.size() < 2;
        }
        return false;
    }

    InputEvent parseEscape() {
        std::string seq;
        const auto start = std::chrono::steady_clock::now();
        while (seq.size() < 96) {
            if (buffer_.empty()) {
                fill(18);
                if (buffer_.empty()) {
                    break;
                }
            }
            seq.push_back(static_cast<char>(pop()));
            if (!needMoreEscapeBytes(seq)) {
                break;
            }
            if (std::chrono::steady_clock::now() - start > std::chrono::milliseconds(90)) {
                break;
            }
        }
        if (seq.empty()) {
            return {InputKind::Escape, 0};
        }
        if (seq == "[A" || seq == "OA") return {InputKind::Up, 0};
        if (seq == "[B" || seq == "OB") return {InputKind::Down, 0};
        if (seq == "[5~") return {InputKind::PageUp, 0};
        if (seq == "[6~") return {InputKind::PageDown, 0};
        if (seq == "[H" || seq == "[1~" || seq == "OH") return {InputKind::Home, 0};
        if (seq == "[F" || seq == "[4~" || seq == "OF") return {InputKind::End, 0};
        if (!seq.empty() && seq[0] == '[') {
            const char last = seq.back();
            if (last == 'A') return {InputKind::Up, 0};
            if (last == 'B') return {InputKind::Down, 0};
            if (last == 'H') return {InputKind::Home, 0};
            if (last == 'F') return {InputKind::End, 0};
            if (last == '~' && seq.size() >= 2 && seq[1] == '5') return {InputKind::PageUp, 0};
            if (last == '~' && seq.size() >= 2 && seq[1] == '6') return {InputKind::PageDown, 0};
        }

        std::smatch match;
        const std::regex mousePattern(R"(\[<([0-9]+);([0-9]+);([0-9]+)([Mm]))");
        if (std::regex_match(seq, match, mousePattern)) {
            int button = 0;
            for (unsigned char ch : match[1].str()) {
                button = button * 10 + (ch - '0');
                if (button > 1000) {
                    return {InputKind::None, 0};
                }
            }
            if (button == 64) return {InputKind::MouseUp, 0};
            if (button == 65) return {InputKind::MouseDown, 0};
        }
        return {InputKind::None, 0};
    }
};

InputReader &inputReader() {
    static InputReader reader;
    return reader;
}

bool adjustScrollByRows(int rows, int &scrollOffset, std::size_t lineCount) {
    const int before = scrollOffset;
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    scrollOffset = std::max(0, std::min(scrollOffset + rows, maxOffset));
    return scrollOffset != before;
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

int terminalRows() {
#ifndef _WIN32
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 8) {
        return ws.ws_row;
    }
#endif
    return 28;
}

int terminalCols() {
#ifndef _WIN32
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 40) {
        return ws.ws_col;
    }
#endif
    return 100;
}

InputEvent readInputEvent(int timeoutMs) {
    return inputReader().readEvent(timeoutMs);
}

std::string terminalDrawLineSequence(int row, const std::string &text, int cols) {
    std::ostringstream out;
    out << "\033[" << row << ";1H" << fitLine(text, cols) << "\033[K";
    return out.str();
}

void Viewport::render(const std::string &title,
                      const ScreenBuffer &buffer,
                      int scrollOffset,
                      const std::string &footer,
                      bool showHardwareCursor) {
    const int rows = terminalRows();
    const int cols = terminalCols();
    const int bodyRows = std::max(3, rows - 4);
    const auto &lines = buffer.lines();
    const int maxOffset = std::max(0, static_cast<int>(lines.size()) - bodyRows);
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
    const int totalPages = std::max(1, (static_cast<int>(lines.size()) + bodyRows - 1) / bodyRows);
    const int currentPage = std::min(totalPages, scrollOffset / bodyRows + 1);
    const int fromLine = lines.empty() ? 0 : scrollOffset + 1;
    const int toLine = lines.empty() ? 0 : std::min(static_cast<int>(lines.size()), scrollOffset + bodyRows);
    std::ostringstream footerLine;
    footerLine << footer << "  |  页 " << currentPage << "/" << totalPages
               << "  行 " << fromLine << "-" << toLine << "/" << lines.size();

    std::vector<std::string> physical(static_cast<std::size_t>(rows) + 1);
    physical[1] = ansi::bold + title + ansi::plain;
    physical[2] = ansi::gray + std::string(std::max(1, std::min(cols, 140)), '-') + ansi::plain;
    for (int i = 0; i < bodyRows; ++i) {
        const int idx = scrollOffset + i;
        if (idx >= 0 && idx < static_cast<int>(lines.size())) {
            physical[static_cast<std::size_t>(3 + i)] = lines[static_cast<std::size_t>(idx)];
        } else {
            physical[static_cast<std::size_t>(3 + i)] = "";
        }
    }
    physical[static_cast<std::size_t>(rows - 1)] = ansi::gray + std::string(std::max(1, std::min(cols, 140)), '-') + ansi::plain;
    physical[static_cast<std::size_t>(rows)] = footerLine.str();

    const bool resized = rows != lastRows_ || cols != lastCols_;
    if (resized) {
        lastRows_ = rows;
        lastCols_ = cols;
        lastPhysical_.clear();
    }
    if (lastPhysical_.size() != physical.size()) {
        lastPhysical_.assign(physical.size(), std::string());
    }

    std::ostringstream frame;
    frame << "\033[" << rows << ";1H\033[?25l";
    if (resized || !painted_) {
        frame << "\033[H\033[2J";
    }
    for (int row = 1; row <= rows; ++row) {
        const std::string fitted = fitLine(physical[static_cast<std::size_t>(row)], cols);
        if (!painted_ || lastPhysical_[static_cast<std::size_t>(row)] != fitted) {
            frame << terminalDrawLineSequence(row, physical[static_cast<std::size_t>(row)], cols);
            lastPhysical_[static_cast<std::size_t>(row)] = fitted;
        }
    }
    if (showHardwareCursor) {
        frame << "\033[?25h";
    } else {
        frame << "\033[" << rows << ";1H\033[?25l";
    }
    std::cout << frame.str();
    std::cout.flush();
    painted_ = true;
}

void Viewport::invalidate() {
    painted_ = false;
    lastPhysical_.clear();
}

bool adjustScroll(InputKind kind, int &scrollOffset, std::size_t lineCount) {
    const int before = scrollOffset;
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    if (kind == InputKind::Up || kind == InputKind::MouseUp) scrollOffset -= 3;
    else if (kind == InputKind::Down || kind == InputKind::MouseDown) scrollOffset += 3;
    else if (kind == InputKind::PageUp) scrollOffset -= bodyRows;
    else if (kind == InputKind::PageDown) scrollOffset += bodyRows;
    else if (kind == InputKind::Home) scrollOffset = 0;
    else if (kind == InputKind::End) scrollOffset = maxOffset;
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
    return scrollOffset != before;
}

bool adjustScrollForEvent(const InputEvent &event, int &scrollOffset, std::size_t lineCount) {
    const int bodyRows = std::max(3, terminalRows() - 4);
    if (event.kind == InputKind::Up || event.kind == InputKind::MouseUp) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind == InputKind::Down || event.kind == InputKind::MouseDown) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
        event.kind == InputKind::Home || event.kind == InputKind::End) {
        return adjustScroll(event.kind, scrollOffset, lineCount);
    }
    if (event.kind != InputKind::Character) {
        return false;
    }
    if (event.ch == 'k') return adjustScrollByRows(-3, scrollOffset, lineCount);
    if (event.ch == 'j') return adjustScrollByRows(3, scrollOffset, lineCount);
    if (event.ch == 'g') return adjustScroll(InputKind::Home, scrollOffset, lineCount);
    if (event.ch == 'G') return adjustScroll(InputKind::End, scrollOffset, lineCount);
    if (event.ch == 2) return adjustScroll(InputKind::PageUp, scrollOffset, lineCount);
    if (event.ch == 6) return adjustScroll(InputKind::PageDown, scrollOffset, lineCount);
    if (event.ch == 21) return adjustScrollByRows(-(bodyRows / 2), scrollOffset, lineCount);
    if (event.ch == 4) return adjustScrollByRows(bodyRows / 2, scrollOffset, lineCount);
    return false;
}

bool isScrollInput(const InputEvent &event) {
    if (event.kind == InputKind::Up || event.kind == InputKind::Down ||
        event.kind == InputKind::MouseUp || event.kind == InputKind::MouseDown ||
        event.kind == InputKind::PageUp || event.kind == InputKind::PageDown ||
        event.kind == InputKind::Home || event.kind == InputKind::End) {
        return true;
    }
    return event.kind == InputKind::Character &&
           (event.ch == 'j' || event.ch == 'k' || event.ch == 'g' || event.ch == 'G' ||
            event.ch == 2 || event.ch == 4 || event.ch == 6 || event.ch == 21);
}

int confirmKeyDecision(const InputEvent &event, bool defaultYes) {
    if (event.kind == InputKind::Escape) {
        return 0;
    }
    if (event.kind != InputKind::Character) {
        return -1;
    }
    if (event.ch == '\n') {
        return defaultYes ? 1 : 0;
    }
    if (event.ch == 'y' || event.ch == 'Y') {
        return 1;
    }
    if (event.ch == 'n' || event.ch == 'N' || event.ch == 'q' || event.ch == 'Q') {
        return 0;
    }
    return -1;
}

bool isResultReturnInput(const InputEvent &event) {
    if (event.kind == InputKind::Escape) {
        return true;
    }
    if (event.kind != InputKind::Character) {
        return false;
    }
    return event.ch == '\n' || event.ch == 'q' || event.ch == 'Q' ||
           event.ch == 8 || event.ch == 127;
}

std::string cursorMoveSequence(int row, int col) {
    std::ostringstream out;
    out << "\033[" << std::max(1, row) << ";" << std::max(1, col) << "H\033[?25h";
    return out.str();
}

std::string promptInputLine(const std::string &label, const std::string &value, bool cursorOn) {
    return ansi::cyan + label + ansi::plain + value +
           (cursorOn ? ansi::inverse + std::string(" ") + ansi::plain : " ");
}

bool adjustSelection(InputKind kind, int &selected, int count) {
    const int before = selected;
    if (count <= 0) {
        selected = 0;
        return selected != before;
    }
    if (kind == InputKind::Up || kind == InputKind::MouseUp) {
        selected = (selected + count - 1) % count;
    } else if (kind == InputKind::Down || kind == InputKind::MouseDown) {
        selected = (selected + 1) % count;
    } else if (kind == InputKind::Home) {
        selected = 0;
    } else if (kind == InputKind::End) {
        selected = count - 1;
    }
    return selected != before;
}

void ensureLineVisible(int line, int &scrollOffset, std::size_t lineCount) {
    const int bodyRows = std::max(3, terminalRows() - 4);
    const int maxOffset = std::max(0, static_cast<int>(lineCount) - bodyRows);
    if (line < scrollOffset) {
        scrollOffset = line;
    } else if (line >= scrollOffset + bodyRows) {
        scrollOffset = line - bodyRows + 1;
    }
    scrollOffset = std::max(0, std::min(scrollOffset, maxOffset));
}

} // namespace linux_traffic_guard

namespace linux_traffic_guard::translation_units {
void ui_anchor() {}
} // namespace linux_traffic_guard::translation_units
