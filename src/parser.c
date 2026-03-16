/*
 * parser.c — SubjectPublicKeyInfo and PKCS#8 DER structure parsers.
 *
 * Covers: parse_algorithm_identifier (internal), pqc_asn1_spki_parse,
 * pqc_asn1_pkcs8_parse.
 */
#include "pqc_asn1_internal.h"

/* ------------------------------------------------------------------ */
/* Internal: shared AlgorithmIdentifier parser                         */
/* ------------------------------------------------------------------ */

/* Parse AlgorithmIdentifier SEQUENCE from within an outer SEQUENCE.
 * Reads the OID TLV and captures any trailing bytes as parameters.
 * On success, *oid_out points to the OID TLV and *params_out to the
 * optional parameters (NULL/0 if absent).  Advances *pos past the
 * AlgorithmIdentifier SEQUENCE.
 * Pass NULL for params_out/params_len_out to discard parameters.
 * When (flags & PQC_PARSE_STRICT_ALG_ID), any trailing bytes in the
 * AlgorithmIdentifier are rejected as PQC_ASN1_ERR_EXTRA_FIELDS. */
static pqc_asn1_status_t parse_algorithm_identifier(
    const uint8_t *seq, size_t seq_len, size_t *pos,
    const uint8_t **oid_out, size_t *oid_len_out,
    const uint8_t **params_out, size_t *params_len_out,
    uint32_t flags)
{
    const uint8_t *alg_content;
    size_t alg_len;
    if (pqc_asn1_der_read_tlv(seq, seq_len, pos, 0x30,
                                &alg_content, &alg_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_ALGORITHM;

    size_t alg_pos = 0;
    const uint8_t *oid_content;
    size_t oid_content_len;
    if (pqc_asn1_der_read_tlv(alg_content, alg_len, &alg_pos, 0x06,
                                &oid_content, &oid_content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_ALGORITHM;

    /* alg_pos now equals the full OID TLV size (tag + length + content). */
    size_t oid_tlv_len = alg_pos;
    *oid_out = alg_content;
    *oid_len_out = oid_tlv_len;

    /* Capture optional AlgorithmIdentifier parameters (bytes after OID).
     * PQC_PARSE_STRICT_ALG_ID: reject any trailing bytes (RFC 9629 strict).
     * Without that flag: capture if out-pointers are non-NULL, otherwise discard. */
    if (alg_pos < alg_len) {
        if (flags & PQC_PARSE_STRICT_ALG_ID) {
            return PQC_ASN1_ERR_EXTRA_FIELDS;
        }
        if (params_out && params_len_out) {
            *params_out = alg_content + alg_pos;
            *params_len_out = alg_len - alg_pos;
        }
    } else {
        if (params_out) *params_out = NULL;
        if (params_len_out) *params_len_out = 0;
    }

    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* DER structure parsers                                               */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_spki_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **pk_bytes, size_t *pk_len,
    uint32_t flags)
{
    if (!der || !oid_der || !oid_der_len || !pk_bytes || !pk_len)
        return PQC_ASN1_ERR_NULL_PARAM;

    size_t pos = 0;
    const uint8_t *seq_content;
    size_t seq_len;

    /* Outer SEQUENCE */
    if (pqc_asn1_der_read_tlv(der, der_len, &pos, 0x30,
                                &seq_content, &seq_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OUTER_SEQUENCE;
    if (pos != der_len)
        return PQC_ASN1_ERR_TRAILING_DATA;

    size_t inner_pos = 0;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    pqc_asn1_status_t alg_rc = parse_algorithm_identifier(
        seq_content, seq_len, &inner_pos, oid_der, oid_der_len,
        alg_params, alg_params_len, flags);
    if (alg_rc != PQC_ASN1_OK) return alg_rc;

    /* BIT STRING */
    const uint8_t *bs_content;
    size_t bs_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x03,
                                &bs_content, &bs_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_KEY;

    if (bs_len < 1 || bs_content[0] != 0x00)
        return PQC_ASN1_ERR_UNUSED_BITS;

    /* Reject extra fields inside outer SEQUENCE */
    if (inner_pos != seq_len)
        return PQC_ASN1_ERR_EXTRA_FIELDS;

    *pk_bytes = bs_content + 1;
    *pk_len = bs_len - 1;

    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **sk_bytes, size_t *sk_len,
    const uint8_t **pub_key, size_t *pub_key_len,
    uint32_t flags)
{
    if (!der || !oid_der || !oid_der_len || !sk_bytes || !sk_len)
        return PQC_ASN1_ERR_NULL_PARAM;

    size_t pos = 0;
    const uint8_t *seq_content;
    size_t seq_len;

    /* Outer SEQUENCE */
    if (pqc_asn1_der_read_tlv(der, der_len, &pos, 0x30,
                                &seq_content, &seq_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OUTER_SEQUENCE;
    if (pos != der_len)
        return PQC_ASN1_ERR_TRAILING_DATA;

    size_t inner_pos = 0;

    /* INTEGER (version — must be 0) */
    const uint8_t *int_content;
    size_t int_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x02,
                                &int_content, &int_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_VERSION;
    if (int_len != 1 || int_content[0] != 0x00)
        return PQC_ASN1_ERR_VERSION;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    pqc_asn1_status_t alg_rc = parse_algorithm_identifier(
        seq_content, seq_len, &inner_pos, oid_der, oid_der_len,
        alg_params, alg_params_len, flags);
    if (alg_rc != PQC_ASN1_OK) return alg_rc;

    /* OCTET STRING (secret key) */
    const uint8_t *os_content;
    size_t os_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x04,
                                &os_content, &os_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_KEY;

    *sk_bytes = os_content;
    *sk_len = os_len;

    /* Optional publicKey [1] IMPLICIT BIT STRING (RFC 9629 / RFC 5958 §3).
     * Tag 0x81 = CONTEXT-SPECIFIC[1] PRIMITIVE.  Only accepted if no other
     * unrecognised fields follow; silently skip if caller passes NULL. */
    if (pub_key) *pub_key = NULL;
    if (pub_key_len) *pub_key_len = 0;

    if (inner_pos < seq_len) {
        /* Accept [1] IMPLICIT BIT STRING — store if caller wants it. */
        if (seq_content[inner_pos] == 0x81) {
            const uint8_t *pk_content;
            size_t pk_len_val;
            if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x81,
                                       &pk_content, &pk_len_val) != PQC_ASN1_OK)
                return PQC_ASN1_ERR_KEY;
            if (pub_key) *pub_key = pk_content;
            if (pub_key_len) *pub_key_len = pk_len_val;
        }
    }

    /* Reject any remaining unrecognised fields. */
    if (inner_pos != seq_len)
        return PQC_ASN1_ERR_EXTRA_FIELDS;

    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
