CC ?= cc
VERSION = 1.0.2
PREFIX ?= /opt
DESTDIR ?=
SBINDIR ?= $(PREFIX)/sbin
ETCDIR ?= $(PREFIX)/etc
INITDIR ?= $(ETCDIR)/init.d

CPPFLAGS += -Iinclude
CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith \
	-Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror
LDFLAGS ?=
LDLIBS += -lcrypto

SRC = src/main.c src/config.c src/usteer.c src/ft.c src/mtk.c
OBJ = $(SRC:src/%.c=build/%.o)
TEST_OBJ = $(SRC:src/%.c=build/test/%.o) build/test/test.o

.PHONY: all clean install test sanitize

all: keensteerd

keensteerd: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c include/keensteer.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

build/test/%.o: src/%.c include/keensteer.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKS_TEST -c -o $@ $<

build/test/test.o: tests/test.c include/keensteer.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKS_TEST -c -o $@ $<

build/test/test: $(TEST_OBJ)
	$(CC) $(LDFLAGS) -Wl,--wrap=ioctl -o $@ $(TEST_OBJ) $(LDLIBS)

test: build/test/test
	./build/test/test
	./tests/test-setup.sh

sanitize:
	@mkdir -p build
	$(CC) $(CPPFLAGS) -DKS_TEST -std=c11 -O1 -g \
		-Wall -Wextra -Wformat=2 -Wshadow -Wpointer-arith -Wcast-qual \
		-Wstrict-prototypes -Wmissing-prototypes -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		$(SRC) tests/test.c -Wl,--wrap=ioctl $(LDLIBS) -o build/test-sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./build/test-sanitize

install: keensteerd
	mkdir -p $(DESTDIR)$(SBINDIR) $(DESTDIR)$(ETCDIR) $(DESTDIR)$(INITDIR)
	cp keensteerd $(DESTDIR)$(SBINDIR)/keensteerd
	cp files/keensteer.conf $(DESTDIR)$(ETCDIR)/keensteer.conf.example
	cp files/S99keensteer $(DESTDIR)$(INITDIR)/S99keensteer
	cp files/keensteer-setup $(DESTDIR)$(SBINDIR)/keensteer-setup
	chmod 0755 $(DESTDIR)$(SBINDIR)/keensteerd $(DESTDIR)$(SBINDIR)/keensteer-setup \
		$(DESTDIR)$(INITDIR)/S99keensteer
	chmod 0644 $(DESTDIR)$(ETCDIR)/keensteer.conf.example

clean:
	rm -rf build keensteerd
