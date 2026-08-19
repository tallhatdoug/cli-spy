CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += -Ivendor
LDLIBS := -lm -lpthread

OBJ := cli-spy.o seal.o vendor/tweetnacl.o

cli-spy: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

vendor/tweetnacl.o: vendor/tweetnacl.c vendor/tweetnacl.h
	$(CC) -O2 -w $(CPPFLAGS) -c -o $@ $<

static: CC := musl-gcc
static: CFLAGS := -O2 -Wall -Wextra -static
static: clean cli-spy

matrix:
	mkdir -p dist
	for t in x86_64 aarch64 i386; do \
		zig cc -target $$t-linux-musl -O2 -static -Ivendor \
			-o dist/cli-spy-$$t cli-spy.c seal.c vendor/tweetnacl.c \
			-lm -lpthread; \
	done
	zig cc -target armv7l-linux-musleabihf -O2 -static -Ivendor \
		-o dist/cli-spy-armv7l cli-spy.c seal.c vendor/tweetnacl.c \
		-lm -lpthread

clean:
	rm -f cli-spy $(OBJ)

distclean: clean
	rm -rf dist

.PHONY: static matrix clean distclean

PUBKEY ?= $(shell tr -d '[:space:]' < cli-spy.pk 2>/dev/null)

operator:
	@test -n "$(PUBKEY)" || { echo "need cli-spy.pk (run tools/keygen.py)"; exit 1; }
	$(MAKE) clean
	$(MAKE) cli-spy \
		CFLAGS='-O2 -Wall -Wextra' \
		CPPFLAGS='-Ivendor -DOPERATOR_PUBKEY_HEX=\"$(PUBKEY)\"'

operator-static:
	@test -n "$(PUBKEY)" || { echo "need cli-spy.pk (run tools/keygen.py)"; exit 1; }
	$(MAKE) clean
	$(MAKE) cli-spy CC=musl-gcc \
		CFLAGS='-O2 -Wall -Wextra -static' \
		CPPFLAGS='-Ivendor -DOPERATOR_PUBKEY_HEX=\"$(PUBKEY)\"'

cli-spy.o: cli-spy.c seal.h
