CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
CPPFLAGS ?= -Iinclude
LDLIBS ?=

TARGET := ltg
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
VERSION := $(shell sed -n 's/.*kVersion = "\([^"]*\)".*/\1/p' include/ltg/version.hpp | head -n 1)
DISTDIR := linux-traffic-guard-$(VERSION)
DEPS := g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin
APT_GET ?= apt-get
APT_TIMEOUT ?= 180
APT_RUN ?= timeout --foreground $(APT_TIMEOUT)s

ifeq ($(OS),Windows_NT)
EXEEXT := .exe
RM := del /Q
NULL := 2>NUL
SUDO :=
RMDIR := rmdir /S /Q
else
EXEEXT :=
RM := rm -f
NULL := 2>/dev/null
LDLIBS += -lsqlite3
SUDO ?= $(shell if [ "$$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then if [ -t 0 ]; then echo sudo; else echo sudo -n; fi; fi)
RMDIR := rm -rf
endif

BINARY := $(TARGET)$(EXEEXT)
SOURCES := $(wildcard src/*.cpp)
OBJECTS := $(patsubst src/%.cpp,build/%.o,$(SOURCES))
NOSQLITE_OBJECTS := $(patsubst src/%.cpp,build-nosqlite/%.o,$(SOURCES))

.PHONY: all deps bootstrap update run status doctor check check-nosqlite check-root-guard release-check install uninstall dist clean help

all: $(BINARY)

$(BINARY): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(BINARY) $(LDLIBS)

build/%.o: src/%.cpp
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build-nosqlite/%.o: src/%.cpp
	@mkdir -p build-nosqlite
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DLTG_FORCE_NO_SQLITE=1 -c $< -o $@

deps:
ifeq ($(OS),Windows_NT)
	@echo "deps is supported on Ubuntu/Debian targets. On Windows, run it on the target Linux host or in WSL."
else
	@missing=""; \
	for pkg in $(DEPS); do \
		tool=""; \
		case "$$pkg" in \
			g++) tool="g++" ;; \
			make) tool="make" ;; \
			fail2ban) tool="fail2ban-client" ;; \
			ufw) tool="ufw" ;; \
			nftables) tool="nft" ;; \
			iproute2) tool="ss" ;; \
			conntrack) tool="conntrack" ;; \
			gawk) tool="awk" ;; \
			grep) tool="grep" ;; \
			curl) tool="curl" ;; \
			mmdb-bin) tool="mmdblookup" ;; \
		esac; \
		if [ "$$pkg" = "libsqlite3-dev" ]; then \
			dpkg-query -W -f='$${Status}' "$$pkg" 2>/dev/null | grep -q "install ok installed" || missing="$$missing $$pkg"; \
		elif [ -n "$$tool" ] && ! command -v "$$tool" >/dev/null 2>&1; then \
			missing="$$missing $$pkg"; \
		fi; \
	done; \
	if [ -z "$$missing" ]; then \
		echo "Ubuntu/Debian dependencies are already present; skipping apt install."; \
	else \
		echo "Installing missing dependencies:$$missing"; \
		$(SUDO) $(APT_RUN) $(APT_GET) update; \
		$(SUDO) $(APT_RUN) $(APT_GET) install -y $$missing; \
	fi
endif

bootstrap: deps all
ifeq ($(OS),Windows_NT)
	@echo "bootstrap is supported on Ubuntu/Debian targets."
else
	$(SUDO) install -Dm755 $(BINARY) $(DESTDIR)$(BINDIR)/$(TARGET)
	@if [ -z "$(DESTDIR)" ]; then \
		$(SUDO) $(BINDIR)/$(TARGET) bootstrap --skip-deps; \
	else \
		echo "DESTDIR is set; skip live fail2ban bootstrap"; \
	fi
endif

update:
ifeq ($(OS),Windows_NT)
	@echo "update is supported on Ubuntu/Debian targets."
else
	git pull --ff-only
	$(MAKE) deps
	$(MAKE) all
	$(SUDO) install -Dm755 $(BINARY) $(DESTDIR)$(BINDIR)/$(TARGET)
	@if [ -z "$(DESTDIR)" ]; then \
		$(SUDO) $(BINDIR)/$(TARGET) bootstrap --skip-deps; \
	else \
		echo "DESTDIR is set; skip live fail2ban bootstrap"; \
	fi
endif

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

check-nosqlite: $(NOSQLITE_OBJECTS)
	$(CXX) $(CXXFLAGS) $(NOSQLITE_OBJECTS) -o $(TARGET)-nosqlite$(EXEEXT)
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
	cp -R include src tests makefile README.md README.zh-CN.md LICENSE CHANGELOG.md CONTRIBUTING.md SECURITY.md .gitattributes linux_traffic_guard.hpp $(DISTDIR)/
	tar -czf $(DISTDIR).tar.gz $(DISTDIR)
	rm -rf $(DISTDIR)

clean:
	-$(RM) $(TARGET) $(TARGET).exe $(TARGET)-nosqlite $(TARGET)-nosqlite.exe linux-traffic-guard-*.tar.gz $(NULL)
	-$(RMDIR) build build-nosqlite $(NULL)

help:
	@echo "Linux Traffic Guard makefile"
	@echo "  make            build ltg"
	@echo "  make deps       install only missing Ubuntu/Debian dependencies"
	@echo "  make bootstrap  deps + build + install + fail2ban protection bootstrap"
	@echo "  make update     git pull + deps + rebuild + install + bootstrap verification"
	@echo "  make run        build and open the interactive TUI"
	@echo "  make status     build and print the dashboard"
	@echo "  make doctor     build and check dependencies"
	@echo "  make check      build and run self-tests"
	@echo "  make release-check run release gates and source package"
	@echo "  make install    install to $(BINDIR)"
	@echo "  make uninstall  remove $(BINDIR)/$(TARGET)"
	@echo "  make dist       build a source release package"
	@echo "  apt packages    sudo apt install -y $(DEPS)"
	@echo "  make clean      remove build artifacts"
