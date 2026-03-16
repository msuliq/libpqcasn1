/*
 * pem.c — RFC 7468 PEM encode/decode.
 *
 * Covers: pqc_asn1_pem_decode_maxsize, pqc_asn1_validate_pem_label,
 * pqc_asn1_pem_encode_size, pqc_asn1_pem_encode_write, pqc_asn1_pem_encode,
 * pqc_asn1_pem_decode_into, pqc_asn1_pem_decode_auto_into,
 * pqc_asn1_pem_decode, pqc_asn1_pem_decode_auto.
 */
#include "pqc_asn1_internal.h"

/* PEM — internal helpers                                              */
/* ------------------------------------------------------------------ */

/* PEM boundary string constants per RFC 7468.  Stored as static arrays
 * so sizeof() yields the length at compile time.  Shared between the
 * encode and decode paths. */
static const char pem_begin_prefix[] = "-----BEGIN ";
static const char pem_end_prefix[]   = "-----END ";
static const char pem_dashes[]       = "-----";
static const char pem_suffix[]       = "-----\n";

enum {
    PEM_BEGIN_PREFIX_LEN = sizeof(pem_begin_prefix) - 1,
    PEM_END_PREFIX_LEN   = sizeof(pem_end_prefix) - 1,
    PEM_DASHES_LEN       = sizeof(pem_dashes) - 1,
    PEM_SUFFIX_LEN       = sizeof(pem_suffix) - 1
};

/* Length-bounded substring search.  Uses the platform's memmem() where
 * available (glibc, BSD) for performance; falls back to a simple O(n*m)
 * scan elsewhere.  The fallback is adequate because PEM inputs are
 * bounded and needles are short (< 100 bytes). */
static const char *bounded_find(const char *hay, size_t hay_len,
                                 const char *needle, size_t needle_len)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__) || defined(_GNU_SOURCE)
    return (const char *)memmem(hay, hay_len, needle, needle_len);
#else
    if (needle_len == 0) return hay;
    if (needle_len > hay_len) return NULL;
    size_t limit = hay_len - needle_len;
    size_t i;
    for (i = 0; i <= limit; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0)
            return hay + i;
    }
    return NULL;
#endif
}

/* Find needle in haystack, but only match if the candidate is at the very
 * start of the input (pem_start) or immediately preceded by a newline.
 * Returns pointer to match, or NULL. */
static const char *find_at_line_start(const char *hay, size_t hay_len,
                                       const char *needle, size_t needle_len,
                                       const char *pem_start)
{
    const char *search = hay;
    size_t search_len = hay_len;
    while (search_len > 0) {
        const char *candidate = bounded_find(search, search_len, needle, needle_len);
        if (!candidate) return NULL;
        if (candidate == pem_start || candidate[-1] == '\n' || candidate[-1] == '\r')
            return candidate;
        size_t skip = (size_t)(candidate - search) + 1;
        search += skip;
        search_len -= skip;
    }
    return NULL;
}

pqc_asn1_status_t pqc_asn1_pem_decode_maxsize(size_t pem_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    /* Subtract the minimum possible header + footer overhead before
     * applying the base64 3/4 ratio.  The shortest valid PEM has
     * "-----BEGIN X-----\n" (19) + "-----END X-----\n" (17) = 36 bytes
     * of framing.  When pem_len is smaller than the minimum framing, we
     * fall back to pem_len as a safe (if generous) upper bound — such
     * input can never be valid PEM, but the caller may still want a
     * buffer size before attempting decode. */
    enum { PEM_MIN_FRAMING = 36 };
    size_t body_upper = (pem_len > PEM_MIN_FRAMING) ? (pem_len - PEM_MIN_FRAMING) : pem_len;
    return pqc_asn1_base64_decode_maxsize(body_upper, out_size);
}

/* Validate a PEM label: non-empty, within length limit, printable ASCII only.
 * Used by both encode and decode paths. */
pqc_asn1_status_t pqc_asn1_validate_pem_label(const char *label, size_t label_len)
{
    if (!label || label_len == 0) return PQC_ASN1_ERR_PEM_LABEL;
    if (label_len > PQC_ASN1_MAX_PEM_LABEL_LEN) return PQC_ASN1_ERR_LABEL_TOO_LONG;
    /* RFC 7468: labels must contain only printable ASCII (0x20-0x7E). */
    size_t li;
    for (li = 0; li < label_len; li++) {
        unsigned char ch = (unsigned char)label[li];
        if (ch < 0x20 || ch > 0x7E)
            return PQC_ASN1_ERR_PEM_LABEL;
    }
    return PQC_ASN1_OK;
}

/* Find PEM markers and extract the base64 body region.
 * label_out must be a non-NULL buffer of at least label_out_max bytes.
 * On success, writes the NUL-terminated label into label_out.
 * Returns PQC_ASN1_OK on success, or a specific error code. */
static pqc_asn1_status_t pem_find_body(const char *pem, size_t pem_len,
                                         char *label_out, size_t label_out_max,
                                         const char **body_start_out,
                                         size_t *body_len_out)
{
    /* RFC 7468: the pre-encapsulation boundary must be at the start of a line. */
    const char *begin = find_at_line_start(pem, pem_len,
                                            pem_begin_prefix, PEM_BEGIN_PREFIX_LEN, pem);
    if (!begin) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    const char *label_start = begin + PEM_BEGIN_PREFIX_LEN;
    size_t remaining = pem_len - (size_t)(label_start - pem);
    const char *label_end = bounded_find(label_start, remaining, pem_dashes, PEM_DASHES_LEN);
    if (!label_end) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    size_t label_len = (size_t)(label_end - label_start);
    if (label_len == 0) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    if (label_len >= label_out_max)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;
    {
        pqc_asn1_status_t lrc = pqc_asn1_validate_pem_label(label_start, label_len);
        if (lrc != PQC_ASN1_OK) return lrc;
    }
    /* Write directly into the caller's buffer. */
    memcpy(label_out, label_start, label_len);
    label_out[label_len] = '\0';

    /* Verify nothing but whitespace follows the closing dashes on the BEGIN line.
     * RFC 7468: the line should end after "-----". */
    const char *after_dashes = label_end + PEM_DASHES_LEN;
    const char *body_start = after_dashes;
    while (body_start < pem + pem_len && *body_start != '\n' && *body_start != '\r') {
        if (*body_start != ' ' && *body_start != '\t')
            return PQC_ASN1_ERR_PEM_MALFORMED;
        body_start++;
    }
    while (body_start < pem + pem_len && (*body_start == '\n' || *body_start == '\r'))
        body_start++;

    /* Build END marker with memcpy — avoids <stdio.h> dependency.
     * Safe because label_len <= MAX_PEM_LABEL_LEN. */
    char end_marker[PEM_END_PREFIX_LEN + PQC_ASN1_MAX_PEM_LABEL_LEN + PEM_DASHES_LEN];
    char *ep = end_marker;
    memcpy(ep, pem_end_prefix, PEM_END_PREFIX_LEN); ep += PEM_END_PREFIX_LEN;
    memcpy(ep, label_out, label_len); ep += label_len;
    memcpy(ep, pem_dashes, PEM_DASHES_LEN); ep += PEM_DASHES_LEN;
    size_t em_len = (size_t)(ep - end_marker);

    /* RFC 7468: the post-encapsulation boundary must be at the start of a line. */
    remaining = pem_len - (size_t)(body_start - pem);
    const char *body_end = find_at_line_start(body_start, remaining,
                                               end_marker, em_len, pem);
    if (!body_end) return PQC_ASN1_ERR_PEM_NO_MARKERS;

    /* Verify nothing but whitespace follows the closing dashes on the END line. */
    const char *after_end = body_end + em_len;
    const char *pem_end_ptr = pem + pem_len;
    while (after_end < pem_end_ptr && *after_end != '\n' && *after_end != '\r') {
        if (*after_end != ' ' && *after_end != '\t')
            return PQC_ASN1_ERR_PEM_MALFORMED;
        after_end++;
    }

    *body_start_out = body_start;
    *body_len_out = (size_t)(body_end - body_start);
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* PEM codec                                                           */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_pem_encode_size(size_t der_len,
                                              const char *label, size_t label_len,
                                              size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    {
        pqc_asn1_status_t lrc = pqc_asn1_validate_pem_label(label, label_len);
        if (lrc != PQC_ASN1_OK) return lrc;
    }
    size_t header_len = safe_add(safe_add(PEM_BEGIN_PREFIX_LEN, label_len), PEM_SUFFIX_LEN);
    if (header_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    /* base64 body + trailing newline */
    size_t b64_body;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(der_len, &b64_body);
    if (rc != PQC_ASN1_OK) return rc;
    size_t b64_len = safe_add(b64_body, 1);
    if (b64_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    size_t footer_len = safe_add(safe_add(PEM_END_PREFIX_LEN, label_len), PEM_SUFFIX_LEN);
    if (footer_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    size_t total = safe_add(safe_add(header_len, b64_len), footer_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *out_size = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pem_encode_write(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !label || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!der && der_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_pem_encode_size(der_len, label, label_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    char *p = out;

    /* Header: -----BEGIN <label>-----\n */
    memcpy(p, pem_begin_prefix, PEM_BEGIN_PREFIX_LEN); p += PEM_BEGIN_PREFIX_LEN;
    memcpy(p, label, label_len); p += label_len;
    memcpy(p, pem_suffix, PEM_SUFFIX_LEN); p += PEM_SUFFIX_LEN;

    /* Base64 body */
    size_t b64_written;
    size_t b64_space = out_len - (size_t)(p - out);
    rc = pqc_asn1_base64_encode_write(der, der_len,
        p, b64_space, &b64_written);
    if (rc != PQC_ASN1_OK) return rc;
    p += b64_written;
    *p++ = '\n';

    /* Footer: -----END <label>-----\n */
    memcpy(p, pem_end_prefix, PEM_END_PREFIX_LEN); p += PEM_END_PREFIX_LEN;
    memcpy(p, label, label_len); p += label_len;
    memcpy(p, pem_suffix, PEM_SUFFIX_LEN); p += PEM_SUFFIX_LEN;

    *out_written = (size_t)(p - out);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pem_encode(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!label) return PQC_ASN1_ERR_NULL_PARAM;
    if (!der && der_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_pem_encode_size(der_len, label, label_len, &total);
    if (rc != PQC_ASN1_OK) return rc;

    char *buf = (char *)PQC_ASN1_MALLOC(total + 1);  /* +1 for NUL */
    if (!buf) return PQC_ASN1_ERR_ALLOC;

    size_t written;
    rc = pqc_asn1_pem_encode_write(der, der_len,
        label, label_len, buf, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    buf[written] = '\0';
    *out_buf = buf;
    *out_len = written;
    return PQC_ASN1_OK;
}

/* Internal: shared PEM decode prefix — find body, handle label copy and
 * expected-label comparison.  On success, *body_start_out and *body_len_out
 * point to the base64 body region ready for decoding. */
static pqc_asn1_status_t pem_decode_prefix(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    char *found_label, size_t found_label_max,
    const char **body_start_out, size_t *body_len_out)
{
    if (!pem) return PQC_ASN1_ERR_NULL_PARAM;
    if (found_label && found_label_max > 0) found_label[0] = '\0';

    /* Always extract into a local buffer so we have the label for
     * comparison even when the caller passes found_label == NULL. */
    char local_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
    local_label[0] = '\0';

    pqc_asn1_status_t rc = pem_find_body(pem, pem_len, local_label,
                                          sizeof(local_label),
                                          body_start_out, body_len_out);
    if (rc != PQC_ASN1_OK)
        return rc;

    size_t lbl_len = strlen(local_label);

    /* Copy to caller's buffer if provided. */
    if (found_label) {
        if (lbl_len >= found_label_max)
            return PQC_ASN1_ERR_BUFFER_TOO_SMALL;
        memcpy(found_label, local_label, lbl_len + 1);
    }

    if (expected_label) {
        if (lbl_len != expected_label_len ||
            memcmp(local_label, expected_label, expected_label_len) != 0)
            return PQC_ASN1_ERR_PEM_LABEL;
    }

    return PQC_ASN1_OK;
}

/* Internal: shared PEM decode logic (allocating variant). */
static pqc_asn1_status_t pem_decode_common(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    const char *body_start;
    size_t body_len;
    pqc_asn1_status_t rc = pem_decode_prefix(pem, pem_len,
                                              expected_label, expected_label_len,
                                              found_label, found_label_max,
                                              &body_start, &body_len);
    if (rc != PQC_ASN1_OK) return rc;

    return pqc_asn1_base64_decode(body_start, body_len, out_buf, out_len);
}

/* Internal: shared PEM decode-into-buffer logic. */
static pqc_asn1_status_t pem_decode_common_into(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    const char *body_start;
    size_t body_len;
    pqc_asn1_status_t rc = pem_decode_prefix(pem, pem_len,
                                              expected_label, expected_label_len,
                                              found_label, found_label_max,
                                              &body_start, &body_len);
    if (rc != PQC_ASN1_OK) return rc;

    return pqc_asn1_base64_decode_into(body_start, body_len,
                                        out, out_max, out_written);
}

pqc_asn1_status_t pqc_asn1_pem_decode_into(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    if (!expected_label) return PQC_ASN1_ERR_NULL_PARAM;
    return pem_decode_common_into(pem, pem_len,
                                   expected_label, expected_label_len,
                                   out, out_max, out_written,
                                   found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode_auto_into(
    const char *pem, size_t pem_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    return pem_decode_common_into(pem, pem_len, NULL, 0,
                                   out, out_max, out_written,
                                   found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    if (!expected_label) return PQC_ASN1_ERR_NULL_PARAM;
    return pem_decode_common(pem, pem_len,
                              expected_label, expected_label_len,
                              out_buf, out_len, found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode_auto(
    const char *pem, size_t pem_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    return pem_decode_common(pem, pem_len, NULL, 0,
                              out_buf, out_len, found_label, found_label_max);
}

/* ------------------------------------------------------------------ */
