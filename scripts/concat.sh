#!/usr/bin/env sh
#
# scripts/concat.sh — Concatenate individual TU sources into the single-file
# distribution artifact src/pqc_asn1.c.
#
# Usage:
#   ./scripts/concat.sh               # writes src/pqc_asn1.c
#   ./scripts/concat.sh /path/out.c   # writes to the specified path
#
# Each src/*.c TU begins with a block comment header followed by a single
# #include "pqc_asn1_internal.h" line.  The concatenation script:
#   1. Emits the combined file-level preamble (copyright/description header,
#      feature-test macros, and common includes).
#   2. For each TU, strips the per-file block comment header and the
#      #include "pqc_asn1_internal.h" line, then appends the remainder.
#
# The order of TUs matters: tlv.c defines helpers used by all other units.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$ROOT/src"

OUTPUT="${1:-$SRC_DIR/pqc_asn1.c}"

# TU concatenation order (dependencies first)
TUS="tlv.c builder.c parser.c base64.c pem.c"

version() {
    cat "$ROOT/VERSION" | tr -d '[:space:]'
}

emit_preamble() {
    cat <<PREAMBLE
/*
 * pqc_asn1.c — DER/PEM/Base64 utilities for post-quantum key serialization.
 *
 * GENERATED FILE — do not edit directly.
 * Edit the individual source files in src/ and run scripts/concat.sh to
 * regenerate this file.
 *
 * Source files (in concatenation order):
 *   src/tlv.c      — version, safe arithmetic, secure zeroing, DER TLV helpers
 *   src/builder.c  — SPKI/PKCS#8 layout structs and DER builders
 *   src/parser.c   — SPKI/PKCS#8 DER parsers
 *   src/base64.c   — RFC 4648 Base64 encode/decode
 *   src/pem.c      — RFC 7468 PEM encode/decode
 *
 * Version: $(version)
 *
 * Standalone C library — no external dependencies beyond the C standard library.
 *
 * Algorithm-agnostic codec for ASN.1/DER/PEM/Base64 encoding.
 * All allocating functions use PQC_ASN1_MALLOC / PQC_ASN1_FREE macros
 * (default: malloc/free), configurable by the consumer before including
 * the header.
 *
 * This module is intentionally algorithm-agnostic: the same DER/PEM
 * primitives apply to ML-DSA, ML-KEM, SLH-DSA, and any future PQC
 * scheme that uses standard SPKI / PKCS#8 / PEM wrapping.
 */

/* Feature-test macros — must precede all system includes.
 * _GNU_SOURCE:             enables memmem() and explicit_bzero() on glibc.
 * __STDC_WANT_LIB_EXT1__: enables memset_s() on Apple/BSD via Annex K. */
#if defined(__linux__)
#define _GNU_SOURCE
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "pqc_asn1.h"
#include <string.h>
#if defined(_MSC_VER)
#include <windows.h>    /* SecureZeroMemory */
#endif

PREAMBLE
}

# Emit shared inline helpers from pqc_asn1_internal.h.
# These are defined as static inline in the internal header (not installed),
# so they must be inlined directly into the single-file distribution.
# Extracts from the sentinel #define through the last closing brace before #endif.
emit_internal_helpers() {
    internal_h="$SRC_DIR/pqc_asn1_internal.h"
    awk '
        /^#define PQC_SIZE_OVERFLOW/ { found_start = 1 }
        found_start && /^#endif/ { exit }
        found_start { print }
    ' "$internal_h"
    printf '\n'
}

# Strip block comment header + #include "pqc_asn1_internal.h" from a TU file.
# Keeps everything after the first blank line that follows the leading comment block
# and the include line.
strip_tu_header() {
    tu_file="$1"
    # Skip lines until past the opening comment block (ends with ' */') and
    # past the #include "pqc_asn1_internal.h" line that follows.
    awk '
        /^#include "pqc_asn1_internal\.h"/ { found_include = 1; next }
        found_include { print }
    ' "$tu_file"
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

emit_preamble > "$tmp"
emit_internal_helpers >> "$tmp"

for tu in $TUS; do
    tu_path="$SRC_DIR/$tu"
    if [ ! -f "$tu_path" ]; then
        echo "ERROR: $tu_path not found" >&2
        exit 1
    fi
    printf '\n/* ================================================================== */\n' >> "$tmp"
    printf '/* Concatenated from: src/%s */\n' "$tu" >> "$tmp"
    printf '/* ================================================================== */\n\n' >> "$tmp"
    strip_tu_header "$tu_path" >> "$tmp"
done

cp "$tmp" "$OUTPUT"
echo "Written: $OUTPUT ($(wc -l < "$OUTPUT") lines)"
