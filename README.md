# libpqcasn1

Standalone C library for DER/PEM/Base64 encoding and decoding of post-quantum cryptographic keys in standard **SPKI** (SubjectPublicKeyInfo) and **PKCS#8** (OneAsymmetricKey) formats.

## Why this library?

Post-quantum cryptography (PQC) schemes like **ML-DSA**, **ML-KEM**, and **SLH-DSA** use the same ASN.1 structures as classical algorithms for key serialization. However, depending on OpenSSL or other large cryptographic libraries just for DER/PEM encoding introduces unnecessary coupling:

1. **Post-quantum independence** -- ML-DSA is designed to survive a future where classical crypto is broken. Coupling key serialization to OpenSSL at link time defeats the purpose.
2. **Portability** -- A self-contained codec with zero external dependencies is trivial to embed in Ruby, Python, Rust, Go, or any other language binding.
3. **Simplicity** -- PQC keys only use SEQUENCE, OID, BIT STRING, OCTET STRING, and INTEGER 0. The required ASN.1 subset fits comfortably in a single C file.
4. **Secure zeroing** -- Secret key intermediates are zeroed in the same compilation unit, making the wipe path easy to audit without depending on another library's internal buffer management.

libpqcasn1 provides exactly this: a minimal, auditable, dependency-free codec for the DER/PEM subset that PQC key serialization requires.

## Features

- **Algorithm-agnostic** -- works with any PQC scheme (ML-DSA, ML-KEM, SLH-DSA, and future algorithms) that uses standard SPKI/PKCS#8 wrapping
- **Zero external dependencies** -- only requires the C standard library (C11)
- **Single-file implementation** -- one header (`pqc_asn1.h`) + one source file (`pqc_asn1.c`)
- **Dual API pattern** -- every operation has both an allocating variant and a write-into-buffer variant
- **Configurable allocator** -- override `PQC_ASN1_MALLOC`/`PQC_ASN1_FREE` for custom memory management (e.g. Ruby's `ruby_xmalloc`/`ruby_xfree`)
- **Secure memory handling** -- secret key buffers are securely zeroed on error and deallocation using platform-optimized primitives
- **Strict validation** -- DER canonical form enforcement, RFC 7468 PEM boundary rules, RFC 4648 base64 padding strictness, RFC 9629 AlgorithmIdentifier rules
- **Overflow-safe arithmetic** -- all size computations use checked addition to prevent integer overflow
- **Comprehensive error codes** -- 18 distinct status codes for precise error diagnosis
- **Cross-platform** -- builds and tests on Linux (GCC, Clang), macOS (AppleClang), and Windows (MSVC)

## Quick start

### Build with Make

```sh
make        # build libpqc_asn1.a
make test   # build and run tests
make install PREFIX=/usr/local
```

### Build with CMake

```sh
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Install:

```sh
cmake --install build
```

### Embed directly in your project

Copy `include/pqc_asn1.h` and `src/pqc_asn1.c` into your project and compile them alongside your code. No build system integration needed.

## Usage examples

### Encode a public key to SPKI DER

```c
#include "pqc_asn1.h"

/* ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18 */
static const uint8_t ML_DSA_65_OID[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};

void encode_public_key(const uint8_t *pk, size_t pk_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;

    pqc_asn1_status_t rc = pqc_asn1_build_pk_spki_der(
        ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
        pk, pk_len,
        &der, &der_len);

    if (rc != PQC_ASN1_OK) {
        fprintf(stderr, "SPKI encode failed: %s\n",
                pqc_asn1_error_message(rc));
        return;
    }

    /* Use der/der_len ... */
    PQC_ASN1_FREE(der);
}
```

### Encode a private key to PKCS#8 DER

```c
void encode_private_key(const uint8_t *sk, size_t sk_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;

    pqc_asn1_status_t rc = pqc_asn1_build_sk_pkcs8_der(
        ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
        sk, sk_len,
        &der, &der_len);

    if (rc != PQC_ASN1_OK) {
        fprintf(stderr, "PKCS#8 encode failed: %s\n",
                pqc_asn1_error_message(rc));
        return;
    }

    /* Use der/der_len ... */

    /* Important: securely zero private key DER before freeing */
    pqc_asn1_secure_zero(der, der_len);
    PQC_ASN1_FREE(der);
}
```

### Wrap DER as PEM

```c
void der_to_pem(const uint8_t *der, size_t der_len) {
    char *pem = NULL;
    size_t pem_len = 0;

    pqc_asn1_status_t rc = pqc_asn1_pem_encode(
        der, der_len,
        "PUBLIC KEY", 10,  /* label + label length */
        &pem, &pem_len);

    if (rc == PQC_ASN1_OK) {
        /* pem is NUL-terminated, pem_len excludes the NUL */
        printf("%s", pem);
        PQC_ASN1_FREE(pem);
    }
}
```

### Decode PEM back to DER

```c
void pem_to_der(const char *pem, size_t pem_len) {
    uint8_t *der = NULL;
    size_t der_len = 0;
    char label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];

    pqc_asn1_status_t rc = pqc_asn1_pem_decode(
        pem, pem_len,
        "PUBLIC KEY", 10,       /* expected label + length */
        &der, &der_len,
        label, sizeof(label));  /* optional: discovered label */

    if (rc == PQC_ASN1_OK) {
        /* Parse the DER ... */
        PQC_ASN1_FREE(der);
    }
}
```

### Parse SPKI DER (zero-copy)

```c
void parse_public_key(const uint8_t *der, size_t der_len) {
    const uint8_t *oid, *pk;
    size_t oid_len, pk_len;

    pqc_asn1_status_t rc = pqc_asn1_parse_pk_spki_der(
        der, der_len,
        &oid, &oid_len,    /* points into der -- no allocation */
        &pk, &pk_len);     /* points into der -- no allocation */

    if (rc == PQC_ASN1_OK) {
        /* oid/oid_len is the full OID TLV */
        /* pk/pk_len is the raw public key bytes */
    }
}
```

### Write-into-buffer variant (no allocation)

```c
void encode_spki_no_alloc(const uint8_t *pk, size_t pk_len) {
    size_t needed;
    pqc_asn1_spki_der_size(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                            pk_len, &needed);

    uint8_t buf[4096];  /* or stack/caller-provided buffer */
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_build_pk_spki_der_write(
        buf, sizeof(buf),
        ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
        pk, pk_len,
        &written);

    /* buf[0..written-1] contains the SPKI DER */
}
```

### Custom allocator (e.g. for Ruby)

```c
#define PQC_ASN1_MALLOC ruby_xmalloc
#define PQC_ASN1_FREE   ruby_xfree
#include "pqc_asn1.h"

/* All allocating functions now use Ruby's memory manager */
```

## API overview

### Status codes

All functions return `pqc_asn1_status_t`. `PQC_ASN1_OK` (0) indicates success; all errors are negative values. Use `pqc_asn1_error_message()` for human-readable descriptions.

| Code | Value | Description |
|------|-------|-------------|
| `PQC_ASN1_OK` | 0 | Success |
| `PQC_ASN1_ERR_OUTER_SEQUENCE` | -1 | Invalid/missing outer SEQUENCE |
| `PQC_ASN1_ERR_VERSION` | -2 | Invalid/missing version INTEGER |
| `PQC_ASN1_ERR_ALGORITHM` | -3 | Invalid/missing AlgorithmIdentifier |
| `PQC_ASN1_ERR_KEY` | -4 | Invalid/missing key element |
| `PQC_ASN1_ERR_UNUSED_BITS` | -5 | BIT STRING has non-zero unused bits |
| `PQC_ASN1_ERR_TRAILING_DATA` | -6 | Unexpected data after SEQUENCE |
| `PQC_ASN1_ERR_PEM_NO_MARKERS` | -7 | No valid PEM markers found |
| `PQC_ASN1_ERR_PEM_LABEL` | -8 | PEM label mismatch |
| `PQC_ASN1_ERR_BASE64` | -9 | Invalid base64 data |
| `PQC_ASN1_ERR_INVALID_OID` | -10 | Invalid OID TLV |
| `PQC_ASN1_ERR_EXTRA_FIELDS` | -11 | Extra fields inside structure |
| `PQC_ASN1_ERR_OVERFLOW` | -12 | Size overflow |
| `PQC_ASN1_ERR_ALLOC` | -13 | Allocation failed |
| `PQC_ASN1_ERR_BUFFER_TOO_SMALL` | -14 | Caller buffer too small |
| `PQC_ASN1_ERR_LABEL_TOO_LONG` | -15 | PEM label exceeds limit |
| `PQC_ASN1_ERR_DER_PARSE` | -16 | Generic DER parse error |
| `PQC_ASN1_ERR_NULL_PARAM` | -17 | Required pointer is NULL |

### DER structure functions

| Function | Description |
|----------|-------------|
| `pqc_asn1_spki_der_size()` | Compute SPKI DER size |
| `pqc_asn1_build_pk_spki_der_write()` | Write SPKI DER into buffer |
| `pqc_asn1_build_pk_spki_der()` | Build SPKI DER (allocating) |
| `pqc_asn1_pkcs8_der_size()` | Compute PKCS#8 DER size |
| `pqc_asn1_build_sk_pkcs8_der_write()` | Write PKCS#8 DER into buffer |
| `pqc_asn1_build_sk_pkcs8_der()` | Build PKCS#8 DER (allocating) |
| `pqc_asn1_parse_pk_spki_der()` | Parse SPKI DER (zero-copy) |
| `pqc_asn1_parse_sk_pkcs8_der()` | Parse PKCS#8 DER (zero-copy) |

### Base64 functions

| Function | Description |
|----------|-------------|
| `pqc_asn1_base64_encode_size_raw()` | Compute raw base64 output size |
| `pqc_asn1_base64_encode_raw()` | Encode to raw base64 (no wrapping) |
| `pqc_asn1_base64_encode_raw_alloc()` | Encode to raw base64 (allocating) |
| `pqc_asn1_base64_encode_size()` | Compute wrapped base64 output size |
| `pqc_asn1_base64_encode_write()` | Encode with 64-char line wrapping |
| `pqc_asn1_base64_encode()` | Encode with line wrapping (allocating) |
| `pqc_asn1_base64_decode_maxsize()` | Compute max decoded output size |
| `pqc_asn1_base64_decode_into()` | Decode into caller buffer |
| `pqc_asn1_base64_decode()` | Decode (allocating) |

### PEM functions

| Function | Description |
|----------|-------------|
| `pqc_asn1_pem_encode_size()` | Compute PEM output size |
| `pqc_asn1_pem_encode_write()` | Encode DER to PEM into buffer |
| `pqc_asn1_pem_encode()` | Encode DER to PEM (allocating) |
| `pqc_asn1_pem_decode_maxsize()` | Compute max PEM decoded size |
| `pqc_asn1_pem_decode_into()` | Decode PEM with label check (into buffer) |
| `pqc_asn1_pem_decode()` | Decode PEM with label check (allocating) |
| `pqc_asn1_pem_decode_auto_into()` | Decode PEM, any label (into buffer) |
| `pqc_asn1_pem_decode_auto()` | Decode PEM, any label (allocating) |
| `pqc_asn1_validate_pem_label()` | Validate a PEM label string |

### Utility functions

| Function | Description |
|----------|-------------|
| `pqc_asn1_version()` | Runtime version string |
| `pqc_asn1_secure_zero()` | Securely zero memory |
| `pqc_asn1_error_message()` | Human-readable error string |
| `pqc_asn1_der_length_size()` | DER length field byte count |
| `pqc_asn1_der_write_tlv()` | Write a DER TLV (allocating) |
| `pqc_asn1_der_write_tlv_write()` | Write a DER TLV into buffer |
| `pqc_asn1_der_read_length()` | Read a DER length field |
| `pqc_asn1_der_read_tlv()` | Read a DER TLV |

## Architecture and design

### DER structures produced

**SPKI (SubjectPublicKeyInfo)** for public keys:

```
SEQUENCE {
  SEQUENCE { OID }           -- AlgorithmIdentifier (OID only, per RFC 9629)
  BIT STRING { 0x00, pk }   -- public key bytes, 0 unused bits
}
```

**PKCS#8 (OneAsymmetricKey)** for private keys:

```
SEQUENCE {
  INTEGER 0                  -- version (v1)
  SEQUENCE { OID }           -- AlgorithmIdentifier
  OCTET STRING { sk }       -- private key bytes
}
```

### Design principles

**Layout-then-serialize**: DER structures are built in two phases. First, a layout struct pre-computes every field's size using overflow-checked arithmetic. Then, serialization writes bytes in a single pass using the pre-computed sizes. This guarantees the `_size` and `_write` functions always agree.

**Local cursor pattern**: DER read functions use a local copy of the position pointer, only committing it back to the caller on success. This ensures partial parse failures never corrupt the caller's state.

**Dual API**: Every encoding operation offers both an allocating variant (returns a malloc'd buffer) and a write-into-buffer variant (caller provides the buffer). This lets callers choose between convenience and full memory control.

**Secure zeroing**: Private key buffers are securely zeroed on error paths and during buffer trimming, using platform-optimized primitives (`SecureZeroMemory`, `memset_s`, `explicit_bzero`, or a volatile-pointer fallback).

**No `stdio.h`**: The library avoids `stdio.h` entirely, making it safe to embed in contexts where file I/O is unavailable or undesirable. String operations like PEM marker construction use `memcpy` instead of `sprintf`.

### Constants strategy

Internal constants use `enum` where the value fits in `int` (e.g., `PQC_B64_INV = 255`, PEM string lengths). Values exceeding `INT_MAX` use `static const size_t` (e.g., `PQC_DER_MAX_LENGTH`). `#define` is reserved only for values that must work in preprocessor expressions or cannot be represented as either type (e.g., `PQC_SIZE_OVERFLOW = (size_t)-1`).

## Security considerations

- **Secret key material**: PKCS#8 write functions securely zero the output buffer on error. Callers should securely zero and free PKCS#8 DER/PEM buffers when done.
- **Base64 decode errors**: Partial decoded output is securely zeroed on failure to prevent key material leakage.
- **Buffer trimming**: When `base64_decode` trims an over-allocated buffer, the old buffer is securely zeroed before being freed.
- **Overflow protection**: All size computations use `safe_add()` with `PQC_SIZE_OVERFLOW` sentinel detection. No integer overflow can lead to undersized allocations.
- **Strict parsing**: DER parsing rejects non-canonical length encodings, indefinite-length forms, trailing data, and extra fields. Base64 decoding rejects non-zero padding bits per RFC 4648 section 3.5.

## Standards compliance

| Standard | Aspect |
|----------|--------|
| ITU-T X.690 | DER encoding rules (canonical form, definite length only) |
| RFC 5280 | SubjectPublicKeyInfo structure |
| RFC 5958 | OneAsymmetricKey / PKCS#8 structure |
| RFC 9629 | PQC AlgorithmIdentifier (OID only, no parameters) |
| RFC 7468 | PEM encoding (boundary lines at line start, label validation) |
| RFC 4648 | Base64 encoding (strict padding, standard alphabet) |

## Testing

The library includes a comprehensive test suite (58 tests) covering:

- DER length encoding/decoding (short, 2-byte, 3-byte forms, non-canonical rejection)
- DER TLV read/write roundtrips
- NULL parameter validation for all public functions
- Output parameter zeroing on error
- Base64 encode/decode (raw and wrapped, allocating and into-buffer)
- Base64 strictness (non-zero padding bits, excess padding, partial output zeroing)
- SPKI and PKCS#8 roundtrips (both allocating and write-into-buffer)
- OID validation (tag, length, consistency)
- AlgorithmIdentifier strictness (no trailing parameters)
- PEM encode/decode roundtrips
- PEM label validation (control chars, length limit, mismatch)
- PEM boundary line enforcement (line-start requirement, trailing junk on BEGIN and END)
- PEM decode variants (auto, into-buffer, null found_label)
- Secure zeroing
- Error message completeness

Run tests:

```sh
make test                        # Make
ctest --test-dir build           # CMake
```

## Platform support

| Platform | Compiler | CI |
|----------|----------|----|
| Linux | GCC, Clang | GitHub Actions |
| macOS | AppleClang | GitHub Actions |
| Windows | MSVC | GitHub Actions |

## Project structure

```
libpqcasn1/
  include/pqc_asn1.h        -- public header (all API declarations)
  src/pqc_asn1.c             -- implementation (single file)
  test/test_pqc_asn1.c       -- test suite (58 tests)
  CMakeLists.txt              -- CMake build system
  Makefile                    -- simple Make alternative
  pqc_asn1.pc.in              -- pkg-config template
  VERSION                     -- version string (0.1.0)
  LICENSE-MIT                 -- MIT license
  LICENSE-APACHE              -- Apache 2.0 license
```

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
