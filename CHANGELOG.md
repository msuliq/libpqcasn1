# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
