/*
 * base64.c — RFC 4648 Base64 encode/decode.
 *
 * Covers: pqc_asn1_base64_encode_size_raw, pqc_asn1_base64_encode_raw,
 * pqc_asn1_base64_encode_raw_alloc, pqc_asn1_base64_encode_size,
 * pqc_asn1_base64_encode_write, pqc_asn1_base64_encode, 
 * pqc_asn1_base64_decode_maxsize, pqc_asn1_base64_decode_into,
 * pqc_asn1_base64_decode.
 */
#include "pqc_asn1_internal.h"

/* Base64 codec                                                        */
/* ------------------------------------------------------------------ */

/* Standard RFC 4648 alphabet.  Used by both raw (no line-wrap) and
 * PEM-style (64-char line-wrap) encoding paths. */
static const char b64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Compile-time 256-entry decode table — maps every byte value to either
 * its 6-bit decoded value (0–63) or PQC_B64_INV (255) for invalid bytes.
 * Built at compile time to avoid the cost of a runtime init function. */
enum { PQC_B64_INV = 255 };
static const uint8_t b64_decode_table[256] = {
    /* 0x00-0x0F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x10-0x1F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x20-0x2F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,         62,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,         63,
    /* 0x30-0x3F */         52,         53,         54,         55,
                            56,         57,         58,         59,
                            60,         61, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x40-0x4F */ PQC_B64_INV,          0,          1,          2,
                             3,          4,          5,          6,
                             7,          8,          9,         10,
                            11,         12,         13,         14,
    /* 0x50-0x5F */         15,         16,         17,         18,
                            19,         20,         21,         22,
                            23,         24,         25, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x60-0x6F */ PQC_B64_INV,         26,         27,         28,
                            29,         30,         31,         32,
                            33,         34,         35,         36,
                            37,         38,         39,         40,
    /* 0x70-0x7F */         41,         42,         43,         44,
                            45,         46,         47,         48,
                            49,         50,         51, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x80-0xFF: all invalid */
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
};

/* Internal: raw base64 encode.  Callers must validate size and buffer
 * before calling — this function does not perform size checks. */
static void base64_encode_core(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_written,
    int wrap_lines)
{
    size_t si = 0, di = 0, col = 0;

    while (si + 2 < data_len) {
        uint32_t n = ((uint32_t)data[si] << 16) |
                     ((uint32_t)data[si+1] << 8) |
                      (uint32_t)data[si+2];
        si += 3;
        out[di++] = b64_encode_table[(n >> 18) & 0x3f];
        out[di++] = b64_encode_table[(n >> 12) & 0x3f];
        out[di++] = b64_encode_table[(n >>  6) & 0x3f];
        out[di++] = b64_encode_table[ n        & 0x3f];
        col += 4;
        if (wrap_lines && col == 64 && si < data_len) {
            out[di++] = '\n';
            col = 0;
        }
    }
    if (si < data_len) {
        /* If the main loop filled a line exactly (col == 64), insert a
         * newline before the trailing-bytes group to avoid a >64-char line. */
        if (wrap_lines && col == 64) {
            out[di++] = '\n';
        }
        int has_second = (si + 1 < data_len);
        uint32_t n = (uint32_t)data[si] << 16;
        if (has_second) n |= (uint32_t)data[si+1] << 8;
        out[di++] = b64_encode_table[(n >> 18) & 0x3f];
        out[di++] = b64_encode_table[(n >> 12) & 0x3f];
        out[di++] = has_second ? b64_encode_table[(n >> 6) & 0x3f] : '=';
        out[di++] = '=';
    }

    *out_written = di;
}

pqc_asn1_status_t pqc_asn1_base64_encode_size_raw(size_t data_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (data_len > (SIZE_MAX / 4) * 3)
        return PQC_ASN1_ERR_OVERFLOW;
    *out_size = ((data_len + 2) / 3) * 4;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_raw(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed) return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    base64_encode_core(data, data_len, out, out_written, 0);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_raw_alloc(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &total);
    if (rc != PQC_ASN1_OK) return rc;
    char *out = (char *)PQC_ASN1_MALLOC(total + 1);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_base64_encode_raw(data, data_len, out, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }
    out[written] = '\0';
    *out_buf = out;
    *out_len = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_size(size_t data_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    size_t b64_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &b64_len);
    if (rc != PQC_ASN1_OK) return rc;
    size_t newlines = (b64_len > 0) ? ((b64_len - 1) / 64) : 0;
    size_t total = safe_add(b64_len, newlines);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *out_size = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_write(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(data_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    base64_encode_core(data, data_len, out, out_written, 1);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(data_len, &total);
    if (rc != PQC_ASN1_OK) return rc;
    char *out = (char *)PQC_ASN1_MALLOC(total + 1);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_base64_encode_write(data, data_len,
        out, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }
    out[written] = '\0';
    *out_buf = out;
    *out_len = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_decode_maxsize(size_t b64_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (b64_len == 0) return PQC_ASN1_OK;
    /* Guard against overflow: (b64_len / 4 + 1) * 3 */
    size_t groups = b64_len / 4;
    if (groups > (SIZE_MAX / 3) - 1)
        return PQC_ASN1_ERR_OVERFLOW;
    *out_size = (groups + 1) * 3;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_decode_into(
    const char *b64, size_t b64_len,
    uint8_t *out, size_t out_max, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!b64 && b64_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t si = 0, di = 0;
    uint8_t buf4[4];
    int buf4_count = 0;
    int pad = 0;
    int seen_pad = 0;
    pqc_asn1_status_t err = PQC_ASN1_ERR_BASE64;

    for (si = 0; si < b64_len; si++) {
        unsigned char c = (unsigned char)b64[si];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') {
            pad++;
            if (pad > 2) goto fail;
            seen_pad = 1;
            buf4[buf4_count++] = 0;
        }
        else if (seen_pad) { goto fail; }
        else if (b64_decode_table[c] == PQC_B64_INV) { goto fail; }
        else { buf4[buf4_count++] = b64_decode_table[c]; }

        if (buf4_count == 4) {
            uint32_t n = ((uint32_t)buf4[0] << 18) | ((uint32_t)buf4[1] << 12) |
                         ((uint32_t)buf4[2] << 6)  |  (uint32_t)buf4[3];
            /* RFC 4648 §3.5: non-significant bits in padding must be zero. */
            if (pad == 2 && (n & 0x0FFFF)) goto fail;
            if (pad == 1 && (n & 0x000FF)) goto fail;
            if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
            out[di++] = (uint8_t)(n >> 16);
            if (pad < 2) {
                if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
                out[di++] = (uint8_t)(n >> 8);
            }
            if (pad < 1) {
                if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
                out[di++] = (uint8_t)n;
            }
            buf4_count = 0;
            pad = 0;
        }
    }
    if (buf4_count != 0) goto fail;

    *out_written = di;
    return PQC_ASN1_OK;

fail:
    /* Zero any partially-decoded output to prevent key material leakage. */
    if (di > 0) pqc_asn1_secure_zero(out, di);
    return err;
}

pqc_asn1_status_t pqc_asn1_base64_decode(
    const char *b64, size_t b64_len,
    uint8_t **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!b64 && b64_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    /* Empty input decodes to empty output — avoid unnecessary allocation.
     * out_buf and out_len are already zeroed above. */
    if (b64_len == 0)
        return PQC_ASN1_OK;

    size_t max_out;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode_maxsize(b64_len, &max_out);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *out = (uint8_t *)PQC_ASN1_MALLOC(max_out);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t decoded;
    rc = pqc_asn1_base64_decode_into(b64, b64_len,
                                       out, max_out, &decoded);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }

    /* Trim to exact decoded size to avoid returning an over-allocated buffer.
     * Skip the trim when waste is trivial (<=32 bytes) — the extra
     * reallocation is not worth it for such small savings.
     * Securely zero the unused tail before realloc so that key material
     * does not persist in freed heap memory regardless of whether realloc
     * moves the buffer or shrinks it in place. */
    if (decoded > 0 && max_out - decoded > 32) {
        pqc_asn1_secure_zero(out + decoded, max_out - decoded);
        uint8_t *trimmed = (uint8_t *)PQC_ASN1_REALLOC(out, decoded);
        if (trimmed)
            out = trimmed;
        /* If realloc fails, keep the over-sized buffer — still correct. */
    }

    *out_buf = out;
    *out_len = decoded;
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
