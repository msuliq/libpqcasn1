/*
 * pqc_asn1_internal.h — private header for libpqcasn1 translation units.
 *
 * Defines feature-test macros that must precede all standard-library includes,
 * then pulls in the public header and the common C standard headers used across
 * all TUs.  This header is NOT installed — it is only used during the library
 * build itself.
 *
 * Every src TU includes this header first.
 */

#ifndef PQC_ASN1_INTERNAL_H
#define PQC_ASN1_INTERNAL_H

/* Feature-test macros — must precede all system includes.
 * _GNU_SOURCE:             enables memmem() and explicit_bzero() on glibc.
 * __STDC_WANT_LIB_EXT1__: enables memset_s() on Apple/BSD via Annex K. */
#if defined(__linux__)
#  define _GNU_SOURCE
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#  define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "pqc_asn1.h"
#include <string.h>
#if defined(_MSC_VER)
#  include <windows.h>   /* SecureZeroMemory */
#endif

/* ------------------------------------------------------------------ */
/* Shared internal helpers — used across multiple translation units   */
/* ------------------------------------------------------------------ */

/* Sentinel value for size overflow detection.  Uses (size_t)-1 (i.e.
 * SIZE_MAX) which is never a valid allocation size.  Kept as a #define
 * because this value exceeds INT_MAX and cannot be represented as an
 * enum constant portably, and static const cannot be used in other
 * static initializers in C11. */
#define PQC_SIZE_OVERFLOW ((size_t)-1)

/* Overflow-checked addition.  Returns PQC_SIZE_OVERFLOW on wraparound.
 * Composable: safe_add(safe_add(a, b), c) propagates overflow because
 * any addition involving PQC_SIZE_OVERFLOW will itself overflow. */
static inline size_t safe_add(size_t a, size_t b)
{
    size_t result = a + b;
    if (result < a)
        return PQC_SIZE_OVERFLOW;
    return result;
}

/* Compute total TLV size for a given content length: 1 (tag) + length field + content.
 * Returns PQC_SIZE_OVERFLOW on overflow or if length is too large to encode. */
static inline size_t der_tlv_total_size(size_t inner_len)
{
    size_t len_size;
    if (pqc_asn1_der_length_size(inner_len, &len_size) != PQC_ASN1_OK)
        return PQC_SIZE_OVERFLOW;
    size_t total = safe_add(safe_add(1, len_size), inner_len);
    return total;  /* PQC_SIZE_OVERFLOW if safe_add overflowed */
}

/* Write DER length field into out.  Returns number of bytes written,
 * or 0 on overflow.  Caller must ensure out has at least 5 bytes. */
static inline size_t der_write_length(uint8_t *out, size_t len)
{
    size_t n;
    if (pqc_asn1_der_length_size(len, &n) != PQC_ASN1_OK)
        return 0;  /* too large to encode */
    if (n == 1) {
        out[0] = (uint8_t)len;
    } else {
        size_t num_bytes = n - 1;
        size_t i;
        out[0] = (uint8_t)(0x80 | num_bytes);
        for (i = 1; i <= num_bytes; i++)
            out[i] = (uint8_t)(len >> (8 * (num_bytes - i)));
    }
    return n;
}

/* Write DER length, returning status.  Advances *p by bytes written.
 * Used by _write functions to guard against der_write_length returning 0. */
static inline pqc_asn1_status_t der_write_length_safe(uint8_t **p, size_t len)
{
    size_t n = der_write_length(*p, len);
    if (n == 0) return PQC_ASN1_ERR_OVERFLOW;
    *p += n;
    return PQC_ASN1_OK;
}

#endif /* PQC_ASN1_INTERNAL_H */
