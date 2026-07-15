BIN := nimux
SRC := src/nimux.nim
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SETCAP ?= 1

NIMFLAGS := -d:release -d:ssl -d:sslVersion=3 --opt:speed --gc:orc \
            --dynlibOverride:ssl --passl:-lcrypto --passl:-lssl \
            --nimcache:.nimcache -o:$(BIN)

.PHONY: linux test clean deps check-runtime-deps install uninstall

deps:
	@command -v nim >/dev/null 2>&1 || { \
		echo "installing nim via choosenim..."; \
		curl -sSf https://nim-lang.org/choosenim/init.sh | sh -s -- -y; \
		export PATH="$$HOME/.nimble/bin:$$PATH"; \
	}
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "installing mingw-w64..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get install -y mingw-w64; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm mingw-w64-gcc; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y mingw64-gcc; \
		else \
			echo "error: unsupported package manager — install mingw-w64 manually"; exit 1; \
		fi; \
	}
	@ldconfig -p | grep -q libkrb5.so.3 && ldconfig -p | grep -q libgssapi_krb5.so.2 || { \
		echo "installing kerberos runtime libraries..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get install -y krb5-user libgssapi-krb5-2 libssl-dev; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm krb5 openssl; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y krb5-libs openssl-devel; \
		else \
			echo "error: unsupported package manager — install krb5-user libgssapi-krb5-2 libssl-dev manually"; exit 1; \
		fi; \
	}
	@ldconfig -p | grep -q libssl || { \
		echo "installing openssl dev libraries..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get install -y libssl-dev; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm openssl; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y openssl-devel; \
		else \
			echo "error: unsupported package manager — install libssl-dev manually"; exit 1; \
		fi; \
	}
	@echo "deps ok"

check-runtime-deps:
	@command -v nim >/dev/null 2>&1 || { \
		echo "error: nim is required at runtime for bin/execute-assembly helper builds"; \
		exit 1; \
	}
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "error: mingw-w64 is required at runtime for Windows helper builds"; \
		exit 1; \
	}

linux:
	nim c $(NIMFLAGS) $(SRC)
	@if [ "$(SETCAP)" = "1" ]; then \
		sudo setcap cap_net_bind_service=ep $(BIN) 2>/dev/null && echo "built $(BIN) (cap_net_bind_service set)" || echo "built $(BIN) (run: sudo setcap cap_net_bind_service=ep $(BIN))"; \
	else \
		echo "built $(BIN)"; \
	fi

install: check-runtime-deps linux
	install -Dm755 $(BIN) "$(DESTDIR)$(BINDIR)/$(BIN)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"

test:
	nim c -d:ssl --nimcache:.nimcache/test-dpapi -r tests/test_dpapi_ng.nim
	@echo "tests ok"

clean:
	rm -f $(BIN)
	rm -rf .nimcache
