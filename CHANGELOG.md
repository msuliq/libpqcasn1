# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-07-15

### Fixed

#### RFC 5958 PKCS#8 OneAsymmetricKey version
- `pqc_asn1_pkcs8_build_write_ex` now emits version **v2 (INTEGER 1)** when the
  optional `publicKey [1]` field is present, and **v1 (INTEGER 0)** when it is
  absent, per RFC 5958 §2. Previously the version was hardcoded to v1 even with a
  `publicKey` present, producing non-conformant DER that strict decoders (e.g.
  OpenSSL `d2i_PKCS8`) reject. The version TLV is the same length in both cases, so
  the computed structure size is unchanged
- `pqc_asn1_pkcs8_parse` now accepts version v1 **or** v2 and enforces the RFC 5958
  §2 rule that v2 appears if and only if `publicKey` is present; mismatched
  combinations return `PQC_ASN1_ERR_VERSION`. Previously only v1 was accepted, so
  conformant v2 keys — including the library's own `publicKey`-bearing output —
  could not be parsed
- Updated the `PQC_ASN1_ERR_VERSION` message and the public-header parse contract,
  which previously stated the version must be INTEGER 0
- Synced the C API version constants (`PQC_ASN1_VERSION_*` / `PQC_ASN1_VERSION_STRING`
  in `include/pqc_asn1.h`) with the `VERSION` file; these had drifted — the header
  reported 0.1.3 while `VERSION` was 0.1.5

### Added

- `pqc_asn1_pkcs8_parse` now accepts the OPTIONAL RFC 5958 `attributes [0]` field
  (tag `0xA0`) between `privateKey` and `publicKey`. A well-formed field is skipped
  (not exposed) instead of being rejected as `PQC_ASN1_ERR_EXTRA_FIELDS`; a
  structurally malformed one returns `PQC_ASN1_ERR_DER_PARSE`. Out-of-order fields
  are still rejected
- Tests: PKCS#8 `publicKey` round-trip (asserts the v2 version byte), version /
  `publicKey` mismatch rejection in both directions, and `attributes [0]`
  acceptance with and without a `publicKey`

### Changed

- **Behavioral (wire format):** PKCS#8 DER emitted by earlier releases' `_ex`
  builder with a `publicKey` carried version v1 (non-conformant). The new parser
  rejects that v1 + `publicKey` combination as `PQC_ASN1_ERR_VERSION`. Re-export
  affected keys with this release to produce conformant v2 DER

---

## [0.1.5] - 2026-03-19

### Added

#### CI & build infrastructure improvements
- Reusable `build.yml` workflow: parameterized, multi-platform build workflow used by all CI jobs to eliminate duplication
- **Build caching**: ccache (Linux/macOS) and sccache (Windows) for 5-10x faster builds across platforms
- **Parallel test execution**: all ctest runs now use `--parallel 4` for faster feedback
- **Code coverage reporting**: new `PQC_ASN1_COVERAGE` CMake option enables gcovr HTML/JSON coverage reports; automated coverage job in CI with artifact uploads
- **Enhanced secret scanning**: Gitleaks job detects hardcoded secrets/credentials in git history
- **Expanded security scanning**: Semgrep now includes OWASP Top 10 and CWE Top 25 rule packs (in addition to security-audit and memory-safety)
- **Modern release pipeline**: auto-release on merge to main (no manual tag workflow)
  - Version detection from `VERSION` file
  - Automatic git tag creation on merge
  - Orphaned tag cleanup
  - Multi-stage pipeline: version detection → tag creation → build/sign → publish
- **Artifact signing**: Cosign keyless (OIDC-based) signatures on all release artifacts for supply chain security
- **SBOM generation**: Software Bill of Materials (SPDX JSON format) generated and attached to all releases for transparency
- **Changelog integration**: release notes auto-extracted from CHANGELOG.md; publishes with verification instructions

#### Documentation
- Updated README: added sections on coverage reporting, release pipeline, and verification procedures

### Changed

#### CI workflow refactoring
- `ci.yml`: simplified from 175 lines to ~155 lines by delegating to reusable `build.yml`
- `edge-cases.yml`: reduced from 134 lines to 65 lines using reusable workflow for compatible jobs
- `security.yml`: updated codeql-action from v3 to v4

---

## [0.1.4] - 2026-03-19

### Added

#### CI & build infrastructure
- `static-analysis` CI job: cppcheck and clang-tidy analysis on source translation
  units (not on generated single-file artifact)
- `pkg-config` CI job: validates `pqc_asn1.pc` generation and required fields
  (Name, Version, Description, Libs, Cflags)
- `security.yml` workflow with four security-focused jobs:
  - `semgrep`: static security scanning (p/security-audit, p/c, p/memory-safety)
    with SARIF upload to GitHub Security tab; runs on push/PR/weekly schedule
  - `code-security`: verifies no stdio.h usage, no unsafe string functions
    (strcpy/strcat/sprintf), secure-zero function presence, error-handling
    validation
  - `dependency-check`: validates stdlib-only includes (no pthread/sys/fcntl),
    confirms C11 standard requirement
  - `header-check`: validates header guards, API function count, internal header
    isolation, C++ compatibility
- `edge-cases.yml` workflow with five edge-case validation jobs:
  - `pedantic-compilation`: builds with `-Wall -Wextra -Werror -Wpedantic -Wshadow`
    via both Make and CMake
  - `single-file-build`: compiles test directly against `src/pqc_asn1.c`
    (distribution artifact) to catch sync drift between individual TUs and
    generated concat artifact
  - `minimal-config`: validates library-only builds (tests OFF)
  - `custom-allocator-build`: validates custom allocator macro overrides
    (`PQC_ASN1_MALLOC`, `PQC_ASN1_FREE`, `PQC_ASN1_REALLOC`)
  - `concat-reproducibility`: runs `make concat` and verifies no git diff
    (catches TU edits without regenerating single-file artifact)

---

## [0.1.3] - 2026-03-17

### Changed

#### Build & CI hardening
- CI `test` jobs now build with `-Werror` (Make and CMake) to catch new warnings
- Windows CI job builds with MSVC `/WX` (warnings as errors)
- Makefile test link step now passes `$(LDFLAGS)` so sanitizer flags propagate
  correctly

### Added

- `PQC_ASN1_SANITIZE` CMake option for building with AddressSanitizer and
  UndefinedBehaviorSanitizer (applies to both library and test targets)
- Dedicated `sanitize` CI job running ASan + UBSan on Linux and macOS (Make and
  CMake)
- `fuzz/fuzz_decode.c` — minimal libFuzzer entrypoint targeting `base64_decode`,
  `base64_decode_into`, `pem_decode_auto`, and `pem_decode_auto_into`
- `fuzz` CI job that builds and runs the fuzzer for 60 seconds under
  ASan + UBSan on Linux
- Documentation: README section on running sanitizers and fuzzers locally

### Fixed

- Documented `pqc_asn1_secure_zero` NULL-pointer contract in public header
  (`ptr` may be NULL; the call is a no-op regardless of `len`)
- Added safety comment in `pem.c` `find_at_line_start` explaining why
  `candidate[-1]` access is in-bounds

---

## [0.1.2] - 2026-03-17

### Changed

#### Parser strictness control (breaking)
- `pqc_asn1_spki_parse` and `pqc_asn1_pkcs8_parse` now accept a `uint32_t flags`
  parameter as the last argument
- Strict AlgorithmIdentifier validation is now controlled by the
  `PQC_PARSE_STRICT_ALG_ID` flag instead of passing NULL for the `alg_params`
  output pointer
- Without the flag, AlgorithmIdentifier parameters are silently accepted
  (captured if out-pointers are non-NULL, discarded otherwise)
- With `PQC_PARSE_STRICT_ALG_ID`, any trailing bytes in the AlgorithmIdentifier
  SEQUENCE are rejected as `PQC_ASN1_ERR_EXTRA_FIELDS` (RFC 9629 strict mode)

### Added

- `PQC_PARSE_STRICT_ALG_ID` parse flag constant (`0x01u`) for opting into strict
  AlgorithmIdentifier validation
- `PQC_ASN1_ERR_PEM_MALFORMED` error code (`-18`) for PEM boundary lines with
  trailing junk

---

## [0.1.1] - 2026-03-16

### Changed

#### Build
- Split monolithic `src/pqc_asn1.c` into focused translation units:
  `src/tlv.c`, `src/builder.c`, `src/parser.c`, `src/base64.c`, `src/pem.c`
- Added `src/pqc_asn1_internal.h` for shared internal helpers (static inline
  functions, internal structs); not installed
- `src/pqc_asn1.c` is now a **generated** single-file distribution artifact;
  regenerate it with `make concat` or `./scripts/concat.sh`
- Updated `CMakeLists.txt` and `Makefile` to build from individual translation
  units; added `concat` target and private `src/` include path

#### API renames (breaking)
Removed redundant `_der`, `_pk_`, and `_sk_` infixes; standardised to
`<structure>_<operation>[_ex]` naming:

| Old name | New name |
|----------|----------|
| `pqc_asn1_spki_der_size` | `pqc_asn1_spki_size` |
| `pqc_asn1_build_pk_spki_der_write` | `pqc_asn1_spki_build_write` |
| `pqc_asn1_build_pk_spki_der` | `pqc_asn1_spki_build` |
| `pqc_asn1_pkcs8_der_size` | `pqc_asn1_pkcs8_size` |
| `pqc_asn1_build_sk_pkcs8_der_write` | `pqc_asn1_pkcs8_build_write` |
| `pqc_asn1_build_sk_pkcs8_der` | `pqc_asn1_pkcs8_build` |
| `pqc_asn1_parse_pk_spki_der` | `pqc_asn1_spki_parse` |
| `pqc_asn1_parse_sk_pkcs8_der` | `pqc_asn1_pkcs8_parse` |

#### Parser behaviour
- `parse_algorithm_identifier()` now **captures** optional AlgorithmIdentifier
  parameters instead of rejecting them
- `pqc_asn1_spki_parse` and `pqc_asn1_pkcs8_parse` expose
  `alg_params`/`alg_params_len` output pointers; pass `NULL/NULL` to discard
  and maintain strict RFC 9629 mode
- `pqc_asn1_pkcs8_parse` exposes `pub_key`/`pub_key_len` for the optional
  RFC 5958 `publicKey [1]` field; pass `NULL/NULL` to discard

### Added

- `pqc_asn1_spki_size_ex` — compute SPKI size with optional AlgorithmIdentifier
  parameter blob (`params`/`params_len`)
- `pqc_asn1_spki_build_write_ex` — write SPKI DER with optional parameters
- `pqc_asn1_pkcs8_size_ex` — compute PKCS#8 size with optional parameters and
  optional RFC 5958 `publicKey [1]` field (`pub_len`)
- `pqc_asn1_pkcs8_build_write_ex` — write PKCS#8 DER with optional parameters
  and optional `publicKey [1] IMPLICIT` field
- `scripts/concat.sh` — shell script that concatenates translation units into
  the single-file distribution artifact

---

## [0.1.0] - 2025-01-01

### Added

- Initial release
- DER/PEM/Base64 codec for post-quantum key serialization (SPKI, PKCS#8)
- Zero external dependencies; C11
- Dual API (allocating + write-into-buffer) for all operations
- Configurable allocator (`PQC_ASN1_MALLOC` / `PQC_ASN1_FREE` / `PQC_ASN1_REALLOC`)
- Secure zeroing on all secret key error paths
- 18 distinct status codes with human-readable descriptions
- RFC 9629, RFC 5958, RFC 5280, RFC 7468, RFC 4648, ITU-T X.690 compliance
- CMake and Makefile build systems
- pkg-config support
- GitHub Actions CI for Linux (GCC, Clang), macOS (AppleClang), Windows (MSVC)
