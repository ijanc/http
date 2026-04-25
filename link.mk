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

# Build-time metadata for consumers that vendor http.rs.  Read by
# marmita(1) on `add`/`update` and copied to vendor/<stem>.mk so the
# consumer's Makefile can pick it up via -include $(wildcard vendor/*.mk).
#
# LINK_FLAGS: native libs added to the bin link step.
# BUILD_ENV:  env vars exported when compiling vendor/http.rs as rlib
#             (http.rs reads HTTP_VERSION via env! at compile time).
LINK_FLAGS += -ltls -lcrypto
BUILD_ENV  += HTTP_VERSION=$(VERSION)
