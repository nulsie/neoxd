PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: all build static install uninstall clean

all: build

build:
	@mkdir -p bin
	nim c -d:danger --opt:speed --out:bin/neoxd src/neoxd.nim

static:
	@mkdir -p bin
	nim c -d:danger --opt:speed \
		--gcc.exe:musl-gcc \
		--gcc.linkerexe:musl-gcc \
		--passL:"-static" \
		--out:bin/neoxd-x86_64-linux-musl src/neoxd.nim

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 bin/neoxd $(DESTDIR)$(BINDIR)/neoxd
	@if [ -f doc/neoxd.1 ]; then \
		install -d $(DESTDIR)$(MANDIR); \
		install -m 644 doc/neoxd.1 $(DESTDIR)$(MANDIR)/neoxd.1; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/neoxd
	rm -f $(DESTDIR)$(MANDIR)/neoxd.1

clean:
	rm -rf bin nimcache
