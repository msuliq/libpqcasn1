/*
 * tlv.c — version, safe arithmetic, secure zeroing, and DER TLV primitives.
 *
 * Covers: pqc_asn1_version, pqc_asn1_secure_zero, DER length encoding/decoding,
 * low-level TLV read/write helpers, and pqc_asn1_error_message.
 */
#include "pqc_asn1_internal.h"


/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

const char *pqc_asn1_version(void)
{
    return PQC_ASN1_VERSION_STRING;
}

/* ------------------------------------------------------------------ */
/* Secure zeroing                                                      */
/* ------------------------------------------------------------------ */

/* Securely zero a memory region, preventing the compiler from
 * optimizing away the write.  This is critical for clearing secret key
 * material from stack and heap buffers.
 *
 * Platform selection rationale:
 *   - MSVC:        SecureZeroMemory is an intrinsic — always emitted.
 *   - Apple/BSD:   memset_s (C11 Annex K) is guaranteed not optimized away.
 *   - glibc/BSD:   explicit_bzero is purpose-built for this use case.
 *   - Fallback:    volatile pointer write loop — the volatile qualifier
 *                  forces the compiler to emit every store. */
void pqc_asn1_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0) return;
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    memset_s(ptr, len, 0, len);
#elif defined(__GLIBC__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
      defined(__DragonFly__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

/* ------------------------------------------------------------------ */
/* DER length helpers                                                  */
/* ------------------------------------------------------------------ */

/* Maximum DER length we support encoding: 4 bytes (0xFFFFFFFF).
 * On 64-bit platforms, size_t can exceed this; we reject such values.
 * Uses static const rather than enum because the value exceeds INT_MAX
 * on 32-bit platforms and cannot be portably represented as an enum. */
static const size_t PQC_DER_MAX_LENGTH = 0xFFFFFFFFUL;

pqc_asn1_status_t pqc_asn1_der_length_size(size_t len, size_t *out)
{
    if (!out) return PQC_ASN1_ERR_NULL_PARAM;
    if (len < 128) { *out = 1; return PQC_ASN1_OK; }
    if (len <= 0xFF) { *out = 2; return PQC_ASN1_OK; }
    if (len <= 0xFFFF) { *out = 3; return PQC_ASN1_OK; }
    if (len <= 0xFFFFFF) { *out = 4; return PQC_ASN1_OK; }
    if (len <= PQC_DER_MAX_LENGTH) { *out = 5; return PQC_ASN1_OK; }
    *out = 0;
    return PQC_ASN1_ERR_OVERFLOW;
}

/* Note: der_tlv_total_size, der_write_length, der_write_length_safe, safe_add,
 * and PQC_SIZE_OVERFLOW are defined as static inline in pqc_asn1_internal.h
 * so they are available to all translation units. */

pqc_asn1_status_t pqc_asn1_der_write_tlv_write(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t *buf, size_t buf_len, size_t *out_written)
{
    if (!buf || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    if (!content && content_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t len_size;
    if (pqc_asn1_der_length_size(content_len, &len_size) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OVERFLOW;

    size_t total = safe_add(safe_add(1, len_size), content_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    if (buf_len < total) return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;
    *p++ = tag;
    p += der_write_length(p, content_len);
    if (content_len > 0)
        memcpy(p, content, content_len);

    *out_written = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_der_write_tlv(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!content && content_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t len_size;
    if (pqc_asn1_der_length_size(content_len, &len_size) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OVERFLOW;

    size_t total = safe_add(safe_add(1, len_size), content_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;

    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_der_write_tlv_write(
        tag, content, content_len, buf, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }

    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* DER reading helpers                                                 */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_der_read_length(
    const uint8_t *buf, size_t buf_len,
    size_t *pos, size_t *out_len)
{
    if (!buf || !pos || !out_len) return PQC_ASN1_ERR_NULL_PARAM;

    size_t p = *pos;  /* local cursor — only committed on success */

    if (p >= buf_len) return PQC_ASN1_ERR_DER_PARSE;
    uint8_t b0 = buf[p++];
    if (b0 < 128) {
        *out_len = b0;
        *pos = p;
        return PQC_ASN1_OK;
    }
    if (b0 == 0x80) return PQC_ASN1_ERR_DER_PARSE;  /* indefinite length — not DER */
    size_t num_bytes = b0 & 0x7f;
    if (num_bytes > 4 || num_bytes > buf_len - p) return PQC_ASN1_ERR_DER_PARSE;

    /* Reject non-canonical: leading zero byte means a shorter encoding exists. */
    if (num_bytes > 0 && buf[p] == 0x00) return PQC_ASN1_ERR_DER_PARSE;

    size_t len = 0;
    size_t j;
    for (j = 0; j < num_bytes; j++)
        len = (len << 8) | buf[p++];

    /* Reject non-canonical: value < 128 must use short form,
     * and value must require all num_bytes to encode. */
    if (len < 128) return PQC_ASN1_ERR_DER_PARSE;
    if (num_bytes > 1 && len < ((size_t)1 << (8 * (num_bytes - 1))))
        return PQC_ASN1_ERR_DER_PARSE;

    if (len > buf_len - p) return PQC_ASN1_ERR_DER_PARSE;  /* content exceeds buffer */
    *out_len = len;
    *pos = p;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_der_read_tlv(
    const uint8_t *buf, size_t buf_len, size_t *pos,
    uint8_t expected_tag,
    const uint8_t **content, size_t *content_len)
{
    if (!buf || !pos || !content || !content_len) return PQC_ASN1_ERR_NULL_PARAM;
    size_t p = *pos;  /* local cursor — only committed on success */
    if (p >= buf_len || buf[p] != expected_tag) return PQC_ASN1_ERR_DER_PARSE;
    p++;
    if (pqc_asn1_der_read_length(buf, buf_len, &p, content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_DER_PARSE;
    /* der_read_length already validates content fits within buf_len. */
    *content = buf + p;
    p += *content_len;
    *pos = p;  /* commit only on success */
    return PQC_ASN1_OK;
}


/* ------------------------------------------------------------------ */
/* Error description                                                   */
/* ------------------------------------------------------------------ */

const char *pqc_asn1_error_message(pqc_asn1_status_t code)
{
    switch (code) {
    case PQC_ASN1_OK:                   return "success";
    case PQC_ASN1_ERR_OUTER_SEQUENCE:   return "invalid or missing outer SEQUENCE";
    case PQC_ASN1_ERR_VERSION:          return "invalid or missing version (expected INTEGER 0)";
    case PQC_ASN1_ERR_ALGORITHM:        return "invalid or missing AlgorithmIdentifier";
    case PQC_ASN1_ERR_KEY:              return "invalid or missing key element";
    case PQC_ASN1_ERR_UNUSED_BITS:      return "BIT STRING has non-zero unused-bits byte";
    case PQC_ASN1_ERR_TRAILING_DATA:    return "unexpected trailing data after outer SEQUENCE";
    case PQC_ASN1_ERR_PEM_NO_MARKERS:   return "no valid PEM markers found";
    case PQC_ASN1_ERR_PEM_LABEL:        return "PEM label invalid or mismatched";
    case PQC_ASN1_ERR_BASE64:           return "invalid Base64 data";
    case PQC_ASN1_ERR_INVALID_OID:      return "oid_der is not a valid OID TLV";
    case PQC_ASN1_ERR_EXTRA_FIELDS:     return "unexpected extra fields inside structure";
    case PQC_ASN1_ERR_OVERFLOW:         return "size overflow in computation";
    case PQC_ASN1_ERR_ALLOC:            return "memory allocation failed";
    case PQC_ASN1_ERR_BUFFER_TOO_SMALL: return "caller-provided buffer is too small";
    case PQC_ASN1_ERR_LABEL_TOO_LONG:   return "PEM label exceeds maximum length";
    case PQC_ASN1_ERR_DER_PARSE:        return "DER parse error";
    case PQC_ASN1_ERR_NULL_PARAM:       return "required pointer parameter is NULL";
    case PQC_ASN1_ERR_PEM_MALFORMED:   return "PEM boundary line has trailing non-whitespace";
    }
    return "unknown error";
}
