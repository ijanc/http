#
# Copyright (c) 2026 Murilo Ijanc' <murilo@ijanc.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

RUSTC ?= $(shell rustup which rustc 2>/dev/null || which rustc)
RUSTFLAGS ?= -C opt-level=2
VERSION = 0.1.0

BUILD = build
SRC = http.rs
LIB = $(BUILD)/libhttp.rlib
TEST = $(BUILD)/http-test

CLIPPY ?= $(shell rustup which clippy-driver 2>/dev/null)
RUSTFMT ?= $(shell rustup which rustfmt 2>/dev/null)
RUSTDOC ?= $(shell rustup which rustdoc 2>/dev/null || which rustdoc)

DOC = $(BUILD)/doc/http/index.html

.PHONY: all clean test fmt-check clippy ci doc

all: $(LIB)

$(LIB): $(SRC)
	mkdir -p $(BUILD)
	HTTP_VERSION=$(VERSION) $(RUSTC) --edition 2024 \
		--crate-type rlib --crate-name http $(RUSTFLAGS) \
		-o $@ $<

$(TEST): $(SRC)
	mkdir -p $(BUILD)
	HTTP_VERSION=$(VERSION) $(RUSTC) --edition 2024 \
		--test --crate-name http -o $@ $<

test: $(TEST)
	$(TEST)

fmt-check:
	$(RUSTFMT) --edition 2024 --check $(SRC)

clippy:
	mkdir -p $(BUILD)
	HTTP_VERSION=$(VERSION) $(CLIPPY) --edition 2024 \
		--crate-type rlib --crate-name http \
		-W clippy::all -o $(BUILD)/http.clippy $(SRC)
	@rm -f $(BUILD)/http.clippy

ci: fmt-check clippy $(LIB) test

$(DOC): $(SRC)
	mkdir -p $(BUILD)
	$(RUSTDOC) --edition 2024 --crate-name http \
		-o $(BUILD)/doc $(SRC)

doc: $(DOC)

clean:
	rm -rf $(BUILD)
