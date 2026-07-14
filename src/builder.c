/*
 * builder.c — SubjectPublicKeyInfo and PKCS#8 DER structure builders.
 *
 * Covers: layout structs, pqc_asn1_spki_{size,build_write,build},
 * pqc_asn1_pkcs8_{size,build_write,build}, and the _ex variants that
 * accept optional AlgorithmIdentifier parameters and publicKey fields.
 */
#include "pqc_asn1_internal.h"

/* ------------------------------------------------------------------ */
/* Internal: SPKI layout (shared between _size and _write)             */
/* ------------------------------------------------------------------ */

/* Pre-computed DER sizes for SubjectPublicKeyInfo.  Computing the layout
 * once and passing it to both the _size and _write functions ensures the
 * size calculation and serialization always agree — a mismatch would
 * cause buffer overflows or truncated output.
 *
 *   SEQUENCE (total) {
 *     SEQUENCE (alg_total) { OID (alg_inner) }
 *     BIT STRING (bs_total) { 0x00 unused-bits, pk_bytes (bs_inner) }
 *   }
 */
typedef struct {
    size_t alg_inner;   /* AlgorithmIdentifier content (= OID TLV) */
    size_t alg_total;   /* AlgorithmIdentifier SEQUENCE TLV */
    size_t bs_inner;    /* BIT STRING content (1 + pk_len) */
    size_t bs_total;    /* BIT STRING TLV */
    size_t seq_inner;   /* outer SEQUENCE content */
    size_t total;       /* outer SEQUENCE TLV (final DER size) */
} spki_layout_t;

/* Validate that oid_der is a well-formed OID TLV by delegating to the
 * existing DER TLV reader.  This ensures consistent length parsing
 * (including long-form lengths) and avoids duplicating DER validation
 * logic.  The TLV must consume the entire buffer exactly. */
static pqc_asn1_status_t validate_oid_tlv(const uint8_t *oid_der, size_t oid_der_len)
{
    if (!oid_der || oid_der_len < 3) return PQC_ASN1_ERR_INVALID_OID;
    size_t pos = 0;
    const uint8_t *content;
    size_t content_len;
    if (pqc_asn1_der_read_tlv(oid_der, oid_der_len, &pos, 0x06,
                                &content, &content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_INVALID_OID;
    /* OID content must be non-empty and TLV must span the entire buffer. */
    if (content_len == 0 || pos != oid_der_len)
        return PQC_ASN1_ERR_INVALID_OID;
    return PQC_ASN1_OK;
}

/* Compute AlgorithmIdentifier SEQUENCE { OID [params] } total size.
 * params_len == 0 means no parameters (OID-only AlgorithmIdentifier).
 * Shared between SPKI and PKCS#8 layout computation. */
static pqc_asn1_status_t alg_id_compute_size(const uint8_t *oid_der, size_t oid_der_len,
                                               size_t params_len,
                                               size_t *alg_inner_out, size_t *alg_total_out)
{
    pqc_asn1_status_t rc = validate_oid_tlv(oid_der, oid_der_len);
    if (rc != PQC_ASN1_OK) return rc;

    *alg_inner_out = safe_add(oid_der_len, params_len);
    if (*alg_inner_out == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *alg_total_out = der_tlv_total_size(*alg_inner_out);
    if (*alg_total_out == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    return PQC_ASN1_OK;
}

static pqc_asn1_status_t spki_compute_layout_ex(spki_layout_t *l,
                                                  const uint8_t *oid_der, size_t oid_der_len,
                                                  size_t params_len, size_t pk_len)
{
    pqc_asn1_status_t rc = alg_id_compute_size(oid_der, oid_der_len,
                                                params_len,
                                                &l->alg_inner, &l->alg_total);
    if (rc != PQC_ASN1_OK) return rc;

    l->bs_inner = safe_add(1, pk_len);
    if (l->bs_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->bs_total = der_tlv_total_size(l->bs_inner);
    if (l->bs_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->seq_inner = safe_add(l->alg_total, l->bs_total);
    if (l->seq_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->total = der_tlv_total_size(l->seq_inner);
    if (l->total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    return PQC_ASN1_OK;
}

static pqc_asn1_status_t spki_compute_layout(spki_layout_t *l,
                                               const uint8_t *oid_der, size_t oid_der_len,
                                               size_t pk_len)
{
    return spki_compute_layout_ex(l, oid_der, oid_der_len, 0, pk_len);
}

/* ------------------------------------------------------------------ */
/* Internal: PKCS#8 layout (shared between _size and _write)           */
/* ------------------------------------------------------------------ */

/* Version field for PKCS#8 OneAsymmetricKey (RFC 5958 §2): v1 (INTEGER 0)
 * when the publicKey [1] field is absent, v2 (INTEGER 1) when it is present.
 * Stored as pre-encoded DER TLVs to avoid runtime encoding.  Both encode to
 * the same 3-byte length, so the layout size is independent of the choice. */
static const uint8_t PKCS8_VERSION_V1_TLV[] = {0x02, 0x01, 0x00};
static const uint8_t PKCS8_VERSION_V2_TLV[] = {0x02, 0x01, 0x01};

/* Pre-computed DER sizes for PKCS#8 OneAsymmetricKey.
 *
 *   SEQUENCE (total) {
 *     INTEGER version (v1=0, or v2=1 when publicKey present)
 *     SEQUENCE (alg_total) { OID [params] (alg_inner) }
 *     OCTET STRING (os_total) { sk_bytes (os_inner) }
 *     [1] IMPLICIT (pub_total) { pub_bytes }   -- optional publicKey field
 *   }
 */
typedef struct {
    size_t alg_inner;   /* AlgorithmIdentifier content (= OID TLV [+ params]) */
    size_t alg_total;   /* AlgorithmIdentifier SEQUENCE TLV */
    size_t os_inner;    /* OCTET STRING content (= sk_len) */
    size_t os_total;    /* OCTET STRING TLV */
    size_t pub_total;   /* publicKey [1] TLV size (0 if absent) */
    size_t seq_inner;   /* outer SEQUENCE content */
    size_t total;       /* outer SEQUENCE TLV (final DER size) */
} pkcs8_layout_t;

static pqc_asn1_status_t pkcs8_compute_layout_ex(pkcs8_layout_t *l,
                                                   const uint8_t *oid_der, size_t oid_der_len,
                                                   size_t params_len, size_t sk_len,
                                                   size_t pub_len)
{
    pqc_asn1_status_t rc = alg_id_compute_size(oid_der, oid_der_len,
                                                params_len,
                                                &l->alg_inner, &l->alg_total);
    if (rc != PQC_ASN1_OK) return rc;

    l->os_inner = sk_len;
    l->os_total = der_tlv_total_size(l->os_inner);
    if (l->os_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    if (pub_len > 0) {
        l->pub_total = der_tlv_total_size(pub_len);
        if (l->pub_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    } else {
        l->pub_total = 0;
    }

    /* v1 and v2 version TLVs are the same length, so either sizeof works. */
    l->seq_inner = safe_add(
        safe_add(safe_add(sizeof(PKCS8_VERSION_V1_TLV), l->alg_total), l->os_total),
        l->pub_total);
    if (l->seq_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->total = der_tlv_total_size(l->seq_inner);
    if (l->total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    return PQC_ASN1_OK;
}

static pqc_asn1_status_t pkcs8_compute_layout(pkcs8_layout_t *l,
                                                const uint8_t *oid_der, size_t oid_der_len,
                                                size_t sk_len)
{
    return pkcs8_compute_layout_ex(l, oid_der, oid_der_len, 0, sk_len, 0);
}

/* ------------------------------------------------------------------ */
/* DER structure builders                                              */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_spki_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t pk_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (!oid_der) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout_ex(&l, oid_der, oid_der_len, params_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    *out_size = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_spki_size(const uint8_t *oid_der, size_t oid_der_len,
                                       size_t pk_len, size_t *out_size)
{
    return pqc_asn1_spki_size_ex(oid_der, oid_der_len, NULL, 0, pk_len, out_size);
}

pqc_asn1_status_t pqc_asn1_spki_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written)
{
    if (!buf || !oid_der || !pk_bytes || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout_ex(&l, oid_der, oid_der_len, params_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    if (buf_len < l.total)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;

    /* Outer SEQUENCE */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.seq_inner);
    if (rc != PQC_ASN1_OK) return rc;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.alg_inner);
    if (rc != PQC_ASN1_OK) return rc;
    memcpy(p, oid_der, oid_der_len);
    p += oid_der_len;
    if (params_len > 0) {
        memcpy(p, params, params_len);
        p += params_len;
    }

    /* BIT STRING { 0x00 unused-bits, key bytes } */
    *p++ = 0x03;
    rc = der_write_length_safe(&p, l.bs_inner);
    if (rc != PQC_ASN1_OK) return rc;
    *p++ = 0x00;
    memcpy(p, pk_bytes, pk_len);

    *out_written = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_spki_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written)
{
    return pqc_asn1_spki_build_write_ex(
        buf, buf_len, oid_der, oid_der_len, NULL, 0, pk_bytes, pk_len, out_written);
}

pqc_asn1_status_t pqc_asn1_spki_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!oid_der || !pk_bytes) return PQC_ASN1_ERR_NULL_PARAM;

    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout(&l, oid_der, oid_der_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(l.total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_spki_build_write(
        buf, l.total, oid_der, oid_der_len, pk_bytes, pk_len, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t sk_len, size_t pub_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (!oid_der) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout_ex(&l, oid_der, oid_der_len,
                                                    params_len, sk_len, pub_len);
    if (rc != PQC_ASN1_OK) return rc;
    *out_size = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_size(const uint8_t *oid_der, size_t oid_der_len,
                                        size_t sk_len, size_t *out_size)
{
    return pqc_asn1_pkcs8_size_ex(oid_der, oid_der_len, NULL, 0, sk_len, 0, out_size);
}

/* Write PKCS#8 DER with optional AlgorithmIdentifier parameters and
 * OneAsymmetricKey publicKey [1] field into a caller-provided buffer.
 * Error paths securely zero the buffer because it may contain partial
 * secret key material — callers should not need to handle this. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *sk_bytes, size_t sk_len,
    const uint8_t *pub_bytes, size_t pub_len,
    size_t *out_written)
{
    if (!buf || !oid_der || !sk_bytes || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    if (pub_len > 0 && !pub_bytes) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout_ex(&l, oid_der, oid_der_len,
                                                    params_len, sk_len, pub_len);
    if (rc != PQC_ASN1_OK) return rc;
    if (buf_len < l.total)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;

    /* Outer SEQUENCE */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.seq_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }

    /* INTEGER version — v2 (1) when the OneAsymmetricKey publicKey [1] field
     * is present, else v1 (0), per RFC 5958 §2. */
    const uint8_t *version_tlv = (pub_len > 0) ? PKCS8_VERSION_V2_TLV
                                               : PKCS8_VERSION_V1_TLV;
    memcpy(p, version_tlv, sizeof(PKCS8_VERSION_V1_TLV));
    p += sizeof(PKCS8_VERSION_V1_TLV);

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.alg_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
    memcpy(p, oid_der, oid_der_len);
    p += oid_der_len;
    if (params_len > 0) {
        memcpy(p, params, params_len);
        p += params_len;
    }

    /* OCTET STRING { key bytes } */
    *p++ = 0x04;
    rc = der_write_length_safe(&p, l.os_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
    memcpy(p, sk_bytes, sk_len);
    p += sk_len;

    /* Optional publicKey [1] IMPLICIT (tag 0x81) */
    if (pub_len > 0) {
        *p++ = 0x81;
        rc = der_write_length_safe(&p, pub_len);
        if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
        memcpy(p, pub_bytes, pub_len);
    }

    *out_written = l.total;
    return PQC_ASN1_OK;
}

/* Write PKCS#8 DER into a caller-provided buffer (no params, no publicKey).
 * Error paths securely zero the buffer because it may contain partial
 * secret key material — callers should not need to handle this. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    size_t *out_written)
{
    return pqc_asn1_pkcs8_build_write_ex(
        buf, buf_len, oid_der, oid_der_len, NULL, 0, sk_bytes, sk_len, NULL, 0, out_written);
}

pqc_asn1_status_t pqc_asn1_pkcs8_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!oid_der || !sk_bytes) return PQC_ASN1_ERR_NULL_PARAM;

    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout(&l, oid_der, oid_der_len, sk_len);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(l.total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_pkcs8_build_write(
        buf, l.total, oid_der, oid_der_len, sk_bytes, sk_len, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}

