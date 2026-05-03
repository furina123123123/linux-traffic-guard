CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDLIBS ?=

TARGET := ltg
SOURCE := linux_traffic_guard.hpp
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
VERSION := $(shell sed -n 's/.*kVersion = "\([^"]*\)".*/\1/p' $(SOURCE) | head -n 1)
DISTDIR := linux-traffic-guard-$(VERSION)

ifeq ($(OS),Windows_NT)
EXEEXT := .exe
RM := del /Q
NULL := 2>NUL
else
EXEEXT :=
RM := rm -f
NULL := 2>/dev/null
LDLIBS += -lsqlite3
endif

BINARY := $(TARGET)$(EXEEXT)

.PHONY: all run status doctor check check-nosqlite check-root-guard release-check install uninstall dist clean help

all: $(BINARY)

$(BINARY): $(SOURCE)
	$(CXX) $(CXXFLAGS) -x c++ $(SOURCE) -o $(BINARY) $(LDLIBS)

run: $(BINARY)
	./$(BINARY)

status: $(BINARY)
	./$(BINARY) --status

doctor: $(BINARY)
	./$(BINARY) --doctor

check: $(BINARY)
	./$(BINARY) --version
	./$(BINARY) --help >/dev/null
	./$(BINARY) --self-test

check-nosqlite:
	$(CXX) $(CXXFLAGS) -DLTG_FORCE_NO_SQLITE=1 -x c++ $(SOURCE) -o $(TARGET)-nosqlite$(EXEEXT)
	./$(TARGET)-nosqlite$(EXEEXT) --version
	./$(TARGET)-nosqlite$(EXEEXT) --self-test

check-root-guard: $(BINARY)
	@if [ "$$(id -u)" = "0" ]; then \
		echo "skip root guard check when running as root"; \
	else \
		./$(BINARY) --status >/tmp/ltg-root-guard.out 2>&1; code=$$?; \
		test "$$code" = "77"; \
	fi

release-check: check check-nosqlite check-root-guard dist

install: $(BINARY)
	install -Dm755 $(BINARY) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

dist: clean
	mkdir -p $(DISTDIR)
	cp $(SOURCE) makefile README.md LICENSE CHANGELOG.md CONTRIBUTING.md SECURITY.md .gitattributes $(DISTDIR)/
	tar -czf $(DISTDIR).tar.gz $(DISTDIR)
	rm -rf $(DISTDIR)

clean:
	-$(RM) $(TARGET) $(TARGET).exe $(TARGET)-nosqlite $(TARGET)-nosqlite.exe linux-traffic-guard-*.tar.gz $(NULL)

help:
	@echo "Linux 流量守卫 makefile"
	@echo "  make          编译 ltg"
	@echo "  make run      编译并进入交互界面"
	@echo "  make status   编译并打印仪表盘"
	@echo "  make doctor   编译并检查依赖"
	@echo "  make check    编译并做基础自检"
	@echo "  make release-check 运行发布前检查并生成源码包"
	@echo "  make install  安装到 $(BINDIR)"
	@echo "  make uninstall 删除 $(BINDIR)/$(TARGET)"
	@echo "  make dist     生成源码发布包"
	@echo "  Ubuntu依赖   sudo apt install -y libsqlite3-dev"
	@echo "  make clean    删除编译产物"
