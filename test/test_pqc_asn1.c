/*
 * test_pqc_asn1.c — Test suite for the standalone pqc_asn1 library.
 *
 * Uses a minimal test harness that continues after failures and
 * reports a pass/fail summary at the end.
 * Returns 0 on all-pass, 1 if any test failed.
 */

#include "pqc_asn1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Minimal test harness                                                */
/* ------------------------------------------------------------------ */

static int test_count  = 0;
static int pass_count  = 0;
static int fail_count  = 0;
static int current_failed = 0;

/* CHECK: assert condition, mark failure but continue the test. */
#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("    FAIL at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        current_failed = 1; \
    } \
} while (0)

/* CHECK_BAIL: assert condition, mark failure and return from test.
 * Use after allocations or setup where continuing would crash. */
#define CHECK_BAIL(cond) do { \
    if (!(cond)) { \
        printf("    FAIL at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        current_failed = 1; \
        return; \
    } \
} while (0)

#define CHECK_RC(expr) CHECK((expr) == PQC_ASN1_OK)
#define CHECK_RC_BAIL(expr) CHECK_BAIL((expr) == PQC_ASN1_OK)

#define RUN_TEST(fn) do { \
    current_failed = 0; \
    test_count++; \
    fn(); \
    if (current_failed) { \
        fail_count++; \
    } else { \
        pass_count++; \
        printf("  PASS: %s\n", #fn); \
    } \
} while (0)

/* ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18 (DER-encoded OID TLV) */
static const uint8_t ML_DSA_65_OID[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

static void test_version(void)
{
    const char *v = pqc_asn1_version();
    CHECK(v != NULL);
    CHECK(strcmp(v, PQC_ASN1_VERSION_STRING) == 0);
    CHECK(PQC_ASN1_VERSION_MAJOR == 0);
    CHECK(PQC_ASN1_VERSION_MINOR == 1);
    CHECK(PQC_ASN1_VERSION_PATCH == 6);
}

/* ------------------------------------------------------------------ */
/* DER length encoding/decoding                                        */
/* ------------------------------------------------------------------ */

static void test_der_length_short(void)
{
    /* Use der_length_size to verify the size, then test read_length. */
    size_t lsz;
    CHECK_RC(pqc_asn1_der_length_size(42, &lsz));
    CHECK(lsz == 1);

    /* Write a minimal TLV to test read_length indirectly via read_tlv. */
    size_t pos = 0, len = 0;
    const uint8_t data[] = {0x04, 42};  /* tag=OCTET STRING, len=42 (short form) */
    /* read_length starts after tag, so pos=1 */
    pos = 1;
    CHECK_RC(pqc_asn1_der_read_length(data, sizeof(data) + 42, &pos, &len));
    CHECK(len == 42);
    CHECK(pos == 2);
}

static void test_der_length_two_byte(void)
{
    size_t lsz;
    CHECK_RC(pqc_asn1_der_length_size(200, &lsz));
    CHECK(lsz == 2);

    const uint8_t data[] = {0x81, 200};  /* long form: 1 byte follows */
    size_t pos = 0, len = 0;
    CHECK_RC(pqc_asn1_der_read_length(data, sizeof(data) + 200, &pos, &len));
    CHECK(len == 200);
}

static void test_der_length_three_byte(void)
{
    size_t lsz;
    CHECK_RC(pqc_asn1_der_length_size(0x1234, &lsz));
    CHECK(lsz == 3);

    const uint8_t data[] = {0x82, 0x12, 0x34};  /* long form: 2 bytes follow */
    size_t pos = 0, len = 0;
    CHECK_RC(pqc_asn1_der_read_length(data, sizeof(data) + 0x1234, &pos, &len));
    CHECK(len == 0x1234);
}

static void test_der_length_size(void)
{
    size_t out;
    CHECK_RC(pqc_asn1_der_length_size(0, &out));     CHECK(out == 1);
    CHECK_RC(pqc_asn1_der_length_size(127, &out));   CHECK(out == 1);
    CHECK_RC(pqc_asn1_der_length_size(128, &out));   CHECK(out == 2);
    CHECK_RC(pqc_asn1_der_length_size(255, &out));   CHECK(out == 2);
    CHECK_RC(pqc_asn1_der_length_size(256, &out));   CHECK(out == 3);
    CHECK_RC(pqc_asn1_der_length_size(0xFFFF, &out)); CHECK(out == 3);
    CHECK_RC(pqc_asn1_der_length_size(0x10000, &out)); CHECK(out == 4);
    /* On 64-bit, values > 0xFFFFFFFF should return ERR_OVERFLOW. */
    if (sizeof(size_t) > 4) {
        CHECK(pqc_asn1_der_length_size((size_t)0xFFFFFFFFUL + 1, &out) == PQC_ASN1_ERR_OVERFLOW);
    }
    /* NULL out param */
    CHECK(pqc_asn1_der_length_size(0, NULL) == PQC_ASN1_ERR_NULL_PARAM);
}

/* ------------------------------------------------------------------ */
/* Non-canonical DER length rejection                                  */
/* ------------------------------------------------------------------ */

static void test_der_reject_non_canonical_lengths(void)
{
    size_t pos, len;

    /* Long form for value < 128: 0x81 0x01 encodes length 1, but
     * short form (single byte 0x01) is the canonical encoding. */
    const uint8_t long_form_small[] = {0x81, 0x01};
    pos = 0; len = 0;
    CHECK(pqc_asn1_der_read_length(long_form_small, sizeof(long_form_small) + 1,
                                     &pos, &len) == PQC_ASN1_ERR_DER_PARSE);

    /* Leading zero in multi-byte length: 0x82 0x00 0xFF encodes 255
     * but 0x81 0xFF is the minimal encoding. */
    const uint8_t leading_zero[] = {0x82, 0x00, 0xFF};
    pos = 0; len = 0;
    CHECK(pqc_asn1_der_read_length(leading_zero, sizeof(leading_zero) + 255,
                                     &pos, &len) == PQC_ASN1_ERR_DER_PARSE);

    /* Over-wide encoding: 0x82 0x00 0x80 encodes 128 but 0x81 0x80
     * is the minimal two-byte encoding. */
    const uint8_t over_wide[] = {0x82, 0x00, 0x80};
    pos = 0; len = 0;
    CHECK(pqc_asn1_der_read_length(over_wide, sizeof(over_wide) + 128,
                                     &pos, &len) == PQC_ASN1_ERR_DER_PARSE);

    /* Indefinite length (0x80) is not DER. */
    const uint8_t indefinite[] = {0x80};
    pos = 0; len = 0;
    CHECK(pqc_asn1_der_read_length(indefinite, sizeof(indefinite),
                                     &pos, &len) == PQC_ASN1_ERR_DER_PARSE);

    /* Verify *pos is not mutated on error. */
    const uint8_t bad_long[] = {0x82, 0x00, 0x80};
    pos = 0; len = 0;
    size_t saved_pos = pos;
    CHECK(pqc_asn1_der_read_length(bad_long, sizeof(bad_long) + 128,
                                     &pos, &len) == PQC_ASN1_ERR_DER_PARSE);
    CHECK(pos == saved_pos);

    /* Verify canonical encodings still work. */
    const uint8_t canon_short[] = {127};  /* short form */
    pos = 0; len = 0;
    CHECK_RC(pqc_asn1_der_read_length(canon_short, sizeof(canon_short) + 127,
                                        &pos, &len));
    CHECK(len == 127);

    const uint8_t canon_long[] = {0x81, 128};  /* minimal long form */
    pos = 0; len = 0;
    CHECK_RC(pqc_asn1_der_read_length(canon_long, sizeof(canon_long) + 128,
                                        &pos, &len));
    CHECK(len == 128);
}

/* ------------------------------------------------------------------ */
/* DER TLV read/write                                                  */
/* ------------------------------------------------------------------ */

static void test_der_write_tlv(void)
{
    const uint8_t content[] = {0x01, 0x02, 0x03};
    uint8_t *tlv = NULL;
    size_t total;
    CHECK_RC_BAIL(pqc_asn1_der_write_tlv(0x04, content, 3, &tlv, &total));
    CHECK(total == 5);
    CHECK(tlv[0] == 0x04); /* OCTET STRING tag */
    CHECK(tlv[1] == 0x03); /* length */
    CHECK(memcmp(tlv + 2, content, 3) == 0);
    PQC_ASN1_FREE(tlv);
}

static void test_der_write_tlv_write(void)
{
    const uint8_t content[] = {0x01, 0x02, 0x03};
    uint8_t buf[16];
    size_t written;

    /* Normal write */
    CHECK_RC(pqc_asn1_der_write_tlv_write(0x04, content, 3,
                                           buf, sizeof(buf), &written));
    CHECK(written == 5);
    CHECK(buf[0] == 0x04);
    CHECK(buf[1] == 0x03);
    CHECK(memcmp(buf + 2, content, 3) == 0);

    /* Buffer too small */
    CHECK(pqc_asn1_der_write_tlv_write(0x04, content, 3,
                                        buf, 4, &written) == PQC_ASN1_ERR_BUFFER_TOO_SMALL);

    /* NULL content with zero length is OK */
    CHECK_RC(pqc_asn1_der_write_tlv_write(0x05, NULL, 0,
                                           buf, sizeof(buf), &written));
    CHECK(written == 2);
    CHECK(buf[0] == 0x05);
    CHECK(buf[1] == 0x00);

    /* NULL params */
    CHECK(pqc_asn1_der_write_tlv_write(0x04, content, 3,
                                        NULL, 16, &written) == PQC_ASN1_ERR_NULL_PARAM);
    CHECK(pqc_asn1_der_write_tlv_write(0x04, content, 3,
                                        buf, sizeof(buf), NULL) == PQC_ASN1_ERR_NULL_PARAM);
}

static void test_der_read_tlv(void)
{
    const uint8_t data[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
    size_t pos = 0;
    const uint8_t *content;
    size_t content_len;
    CHECK_RC(pqc_asn1_der_read_tlv(data, sizeof(data), &pos, 0x04,
                                     &content, &content_len));
    CHECK(content_len == 3);
    CHECK(content[0] == 0xAA);
    CHECK(pos == 5);
}

static void test_der_read_tlv_wrong_tag(void)
{
    const uint8_t data[] = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
    size_t pos = 0;
    const uint8_t *content;
    size_t content_len;
    CHECK(pqc_asn1_der_read_tlv(data, sizeof(data), &pos, 0x30,
                                  &content, &content_len) == PQC_ASN1_ERR_DER_PARSE);
}

/* ------------------------------------------------------------------ */
/* NULL parameter validation                                           */
/* ------------------------------------------------------------------ */

static void test_null_params(void)
{
    /* der_write_tlv: null out_buf */
    CHECK(pqc_asn1_der_write_tlv(0x04, (const uint8_t *)"x", 1,
                                   NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* der_write_tlv: null content with non-zero len */
    uint8_t *p = NULL;
    size_t n = 0;
    CHECK(pqc_asn1_der_write_tlv(0x04, NULL, 5, &p, &n) == PQC_ASN1_ERR_NULL_PARAM);
    CHECK(p == NULL);
    CHECK(n == 0);

    /* der_read_length: null params */
    CHECK(pqc_asn1_der_read_length(NULL, 10, NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* der_read_tlv: null params */
    CHECK(pqc_asn1_der_read_tlv(NULL, 10, NULL, 0x30,
                                  NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* build_pk_spki_der: null out_buf */
    uint8_t pk[4] = {0};
    CHECK(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                       pk, sizeof(pk),
                                       NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* build_pk_spki_der: null pk_bytes */
    uint8_t *der = NULL;
    size_t total = 0;
    CHECK(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                       NULL, 4,
                                       &der, &total) == PQC_ASN1_ERR_NULL_PARAM);
    CHECK(der == NULL);
    CHECK(total == 0);

    /* build_sk_pkcs8_der: null out_buf */
    CHECK(pqc_asn1_pkcs8_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                        pk, sizeof(pk),
                                        NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* parse_pk_spki_der: null params */
    CHECK(pqc_asn1_spki_parse(NULL, 0, NULL, NULL,
                                       NULL, NULL, NULL, NULL,
                                       0) == PQC_ASN1_ERR_NULL_PARAM);

    /* parse_sk_pkcs8_der: null params */
    CHECK(pqc_asn1_pkcs8_parse(NULL, 0, NULL, NULL,
                                        NULL, NULL, NULL, NULL,
                                        NULL, NULL,
                                        0) == PQC_ASN1_ERR_NULL_PARAM);

    /* base64_encode_write: null out */
    CHECK(pqc_asn1_base64_encode_write((const uint8_t *)"x", 1,
                                             NULL, 0, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* base64_encode_raw: null out */
    CHECK(pqc_asn1_base64_encode_raw((const uint8_t *)"x", 1,
                                       NULL, 0, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* base64_encode (alloc): null out_buf */
    CHECK(pqc_asn1_base64_encode((const uint8_t *)"x", 1,
                                       NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* base64_decode (alloc): null out_buf */
    CHECK(pqc_asn1_base64_decode("AAEC", 4,
                                   NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* base64_decode_into: null out */
    CHECK(pqc_asn1_base64_decode_into("AAEC", 4,
                                        NULL, 0, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* pem_encode_write: null label */
    char buf[256];
    size_t written;
    CHECK(pqc_asn1_pem_encode_write((const uint8_t *)"x", 1,
                                      NULL, 0,
                                      buf, sizeof(buf),
                                      &written) == PQC_ASN1_ERR_NULL_PARAM);

    /* pem_encode (alloc): null out_buf */
    CHECK(pqc_asn1_pem_encode((const uint8_t *)"x", 1,
                                "TEST", 4,
                                NULL, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* pem_decode: null expected_label */
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    char label[64];
    CHECK(pqc_asn1_pem_decode("test", 4, NULL, 0,
                                &dec, &dec_len,
                                label, sizeof(label)) == PQC_ASN1_ERR_NULL_PARAM);
    CHECK(dec == NULL);
    CHECK(dec_len == 0);

    /* pem_decode_auto: null out_buf */
    CHECK(pqc_asn1_pem_decode_auto("test", 4,
                                     NULL, NULL,
                                     label, sizeof(label)) == PQC_ASN1_ERR_NULL_PARAM);
}

/* ------------------------------------------------------------------ */
/* Out-params zeroed on error                                          */
/* ------------------------------------------------------------------ */

static void test_out_params_zeroed_on_error(void)
{
    /* der_write_tlv: on error, out_buf and out_total should be NULL/0 */
    uint8_t *buf = (uint8_t *)0xDEAD;
    size_t total = 999;
    pqc_asn1_status_t rc = pqc_asn1_der_write_tlv(0x04, NULL, 5, &buf, &total);
    CHECK(rc != PQC_ASN1_OK);
    CHECK(buf == NULL);
    CHECK(total == 0);

    /* build_pk_spki_der: bad OID should zero out-params */
    uint8_t bad_oid[] = {0x30, 0x03, 0x01, 0x01, 0x00};
    buf = (uint8_t *)0xDEAD;
    total = 999;
    rc = pqc_asn1_spki_build(bad_oid, sizeof(bad_oid),
                                      (const uint8_t *)"pk", 2,
                                      &buf, &total);
    CHECK(rc == PQC_ASN1_ERR_INVALID_OID);
    CHECK(buf == NULL);
    CHECK(total == 0);

    /* build_sk_pkcs8_der: bad OID should zero out-params */
    buf = (uint8_t *)0xDEAD;
    total = 999;
    rc = pqc_asn1_pkcs8_build(bad_oid, sizeof(bad_oid),
                                       (const uint8_t *)"sk", 2,
                                       &buf, &total);
    CHECK(rc == PQC_ASN1_ERR_INVALID_OID);
    CHECK(buf == NULL);
    CHECK(total == 0);

    /* base64_decode: invalid data should zero out-params */
    buf = (uint8_t *)0xDEAD;
    total = 999;
    rc = pqc_asn1_base64_decode("!!!", 3, &buf, &total);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
    CHECK(buf == NULL);
    CHECK(total == 0);

    /* pem_decode: no markers should zero out-params */
    buf = (uint8_t *)0xDEAD;
    total = 999;
    char label[64];
    rc = pqc_asn1_pem_decode("not pem", 7, "PUBLIC KEY", 10,
                               &buf, &total, label, sizeof(label));
    CHECK(rc == PQC_ASN1_ERR_PEM_NO_MARKERS);
    CHECK(buf == NULL);
    CHECK(total == 0);

    /* base64_encode (alloc): zero-length data should still work */
    char *b64_buf = NULL;
    total = 0;
    rc = pqc_asn1_base64_encode(NULL, 0, &b64_buf, &total);
    CHECK(rc == PQC_ASN1_OK);
    /* Empty input produces empty base64 */
    CHECK(total == 0);
    PQC_ASN1_FREE(b64_buf);
}

/* ------------------------------------------------------------------ */
/* Base64                                                              */
/* ------------------------------------------------------------------ */

static void test_base64_encode_decode(void)
{
    const uint8_t data[] = "Hello, PQC world!";
    size_t data_len = sizeof(data) - 1;

    size_t enc_size;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_size(data_len, &enc_size));
    char *enc_buf = (char *)malloc(enc_size);
    CHECK_BAIL(enc_buf != NULL);
    size_t enc_len;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_write(data, data_len,
                                                     enc_buf, enc_size, &enc_len));
    CHECK(enc_len > 0);

    size_t dec_max;
    CHECK_RC_BAIL(pqc_asn1_base64_decode_maxsize(enc_len, &dec_max));
    uint8_t *dec_buf = (uint8_t *)malloc(dec_max);
    CHECK_BAIL(dec_buf != NULL);
    size_t dec_len;
    CHECK_RC(pqc_asn1_base64_decode_into(enc_buf, enc_len,
                                           dec_buf, dec_max, &dec_len));
    CHECK(dec_len == data_len);
    CHECK(memcmp(dec_buf, data, data_len) == 0);

    free(enc_buf);
    free(dec_buf);
}

static void test_base64_allocating(void)
{
    const uint8_t data[] = {0x30, 0x82, 0x01, 0x22};
    char *encoded = NULL;
    size_t out_len;
    CHECK_RC_BAIL(pqc_asn1_base64_encode(data, sizeof(data), &encoded, &out_len));
    CHECK(out_len > 0);

    uint8_t *decoded = NULL;
    size_t dec_len;
    CHECK_RC_BAIL(pqc_asn1_base64_decode(encoded, out_len, &decoded, &dec_len));
    CHECK(dec_len == sizeof(data));
    CHECK(memcmp(decoded, data, sizeof(data)) == 0);

    PQC_ASN1_FREE(encoded);
    PQC_ASN1_FREE(decoded);
}

static void test_base64_invalid(void)
{
    const char bad[] = "Not!Valid@Base64";
    uint8_t *result = NULL;
    size_t out_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode(bad, sizeof(bad) - 1, &result, &out_len);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
    CHECK(result == NULL);
}

static void test_base64_decode_bounds_check(void)
{
    const uint8_t data[] = "Hello, PQC world!";
    size_t data_len = sizeof(data) - 1;

    size_t enc_size;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_size(data_len, &enc_size));
    char *enc_buf = (char *)malloc(enc_size);
    CHECK_BAIL(enc_buf != NULL);
    size_t enc_len;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_write(data, data_len,
                                                     enc_buf, enc_size, &enc_len));

    uint8_t tiny[2];
    size_t dec_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode_into(enc_buf, enc_len,
                                                          tiny, sizeof(tiny),
                                                          &dec_len);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);

    free(enc_buf);
}

static void test_base64_encode_buffer_too_small(void)
{
    const uint8_t data[] = "Hello";
    char tiny[2];
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_write(data, sizeof(data) - 1,
                                                               tiny, sizeof(tiny),
                                                               &written);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

static void test_base64_alloc_distinguishes_errors(void)
{
    /* Invalid base64 returns ERR_BASE64, not a generic NULL. */
    const char bad[] = "!!!";
    uint8_t *result = NULL;
    size_t out_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode(bad, sizeof(bad) - 1, &result, &out_len);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
}

/* ------------------------------------------------------------------ */
/* Raw base64 (no line wrapping)                                       */
/* ------------------------------------------------------------------ */

static void test_base64_raw_encode(void)
{
    const uint8_t data[] = "Hello, PQC world!";
    size_t data_len = sizeof(data) - 1;

    /* Compute raw size (no newlines) */
    size_t raw_size;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_size_raw(data_len, &raw_size));
    CHECK(raw_size > 0);

    /* Wrapped size should be >= raw size (newlines add bytes) */
    size_t wrapped_size;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_size(data_len, &wrapped_size));
    CHECK(wrapped_size >= raw_size);

    char *raw_buf = (char *)malloc(raw_size);
    CHECK_BAIL(raw_buf != NULL);
    size_t raw_written;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_raw(data, data_len,
                                               raw_buf, raw_size, &raw_written));

    /* Raw output should contain no newlines */
    size_t i;
    for (i = 0; i < raw_written; i++) {
        CHECK(raw_buf[i] != '\n');
        CHECK(raw_buf[i] != '\r');
    }

    /* Should decode back correctly */
    size_t dec_max;
    CHECK_RC_BAIL(pqc_asn1_base64_decode_maxsize(raw_written, &dec_max));
    uint8_t *dec_buf = (uint8_t *)malloc(dec_max);
    CHECK_BAIL(dec_buf != NULL);
    size_t dec_len;
    CHECK_RC(pqc_asn1_base64_decode_into(raw_buf, raw_written,
                                           dec_buf, dec_max, &dec_len));
    CHECK(dec_len == data_len);
    CHECK(memcmp(dec_buf, data, data_len) == 0);

    free(raw_buf);
    free(dec_buf);
}

static void test_base64_raw_encode_long(void)
{
    /* Test with data long enough that PEM wrapping would add newlines */
    uint8_t data[100];
    memset(data, 0x42, sizeof(data));

    size_t raw_size;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_size_raw(sizeof(data), &raw_size));
    CHECK(raw_size > 0);
    CHECK(raw_size == ((sizeof(data) + 2) / 3) * 4);  /* pure b64, no newlines */

    char *raw_buf = (char *)malloc(raw_size);
    CHECK_BAIL(raw_buf != NULL);
    size_t raw_written;
    CHECK_RC_BAIL(pqc_asn1_base64_encode_raw(data, sizeof(data),
                                               raw_buf, raw_size, &raw_written));
    CHECK(raw_written == raw_size);

    /* Verify no newlines in output */
    size_t i;
    for (i = 0; i < raw_written; i++) {
        CHECK(raw_buf[i] != '\n');
    }

    /* Compare with PEM-wrapped version: it should have newlines */
    size_t pem_size;
    CHECK_RC(pqc_asn1_base64_encode_size(sizeof(data), &pem_size));
    CHECK(pem_size > raw_size);  /* PEM version is larger due to newlines */

    free(raw_buf);
}

static void test_base64_raw_buffer_too_small(void)
{
    const uint8_t data[] = "Hello";
    char tiny[2];
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_raw(data, sizeof(data) - 1,
                                                         tiny, sizeof(tiny),
                                                         &written);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

static void test_base64_raw_alloc(void)
{
    const uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    char *out = NULL;
    size_t out_len;

    CHECK_RC_BAIL(pqc_asn1_base64_encode_raw_alloc(data, sizeof(data), &out, &out_len));
    CHECK(out != NULL);
    CHECK(out_len > 0);
    /* Raw encoding should have no newlines */
    size_t i;
    for (i = 0; i < out_len; i++)
        CHECK(out[i] != '\n');
    CHECK(out[out_len] == '\0');

    /* Verify round-trip */
    uint8_t *decoded = NULL;
    size_t decoded_len;
    CHECK_RC_BAIL(pqc_asn1_base64_decode(out, out_len, &decoded, &decoded_len));
    CHECK(decoded_len == sizeof(data));
    CHECK(memcmp(decoded, data, sizeof(data)) == 0);

    PQC_ASN1_FREE(decoded);
    PQC_ASN1_FREE(out);
}

static void test_pem_decode_maxsize(void)
{
    /* pem_decode_maxsize should return a tighter upper bound that
     * subtracts minimum header/footer overhead (36 bytes). */
    size_t max_out;
    CHECK_RC(pqc_asn1_pem_decode_maxsize(100, &max_out));
    /* 100 - 36 = 64 bytes of body; (64/4+1)*3 = 51 */
    CHECK(max_out >= 48);  /* at least 3/4 of the body portion */
    CHECK(max_out > 0);

    /* Zero input */
    CHECK_RC(pqc_asn1_pem_decode_maxsize(0, &max_out));
    CHECK(max_out == 0);

    /* NULL param */
    CHECK(pqc_asn1_pem_decode_maxsize(100, NULL) == PQC_ASN1_ERR_NULL_PARAM);

    /* Verify it's usable with pem_decode_into */
    const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";
    CHECK_RC(pqc_asn1_pem_decode_maxsize(strlen(pem), &max_out));
    uint8_t *buf = (uint8_t *)malloc(max_out);
    CHECK_BAIL(buf != NULL);
    size_t written;
    char label[64];
    CHECK_RC(pqc_asn1_pem_decode_into(pem, strlen(pem), "PUBLIC KEY", 10,
                                        buf, max_out, &written,
                                        label, sizeof(label)));
    CHECK(written == 3);
    free(buf);
}

static void test_pem_decode_label_buffer_too_small(void)
{
    const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";
    uint8_t out[64];
    size_t written;
    /* Label buffer too small: "PUBLIC KEY" is 10 chars + NUL = 11 bytes needed */
    char tiny_label[4];
    pqc_asn1_status_t rc = pqc_asn1_pem_decode_into(pem, strlen(pem), "PUBLIC KEY", 10,
                                                       out, sizeof(out), &written,
                                                       tiny_label, sizeof(tiny_label));
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

/* ------------------------------------------------------------------ */
/* SPKI build + parse round-trip                                       */
/* ------------------------------------------------------------------ */

static void test_spki_roundtrip(void)
{
    uint8_t pk[32];
    memset(pk, 0xAB, sizeof(pk));

    size_t der_size;
    CHECK_RC_BAIL(pqc_asn1_spki_size(ML_DSA_65_OID, sizeof(ML_DSA_65_OID), sizeof(pk), &der_size));
    CHECK_BAIL(der_size > 0);

    uint8_t *der = (uint8_t *)malloc(der_size);
    CHECK_BAIL(der != NULL);
    size_t written;
    CHECK_RC_BAIL(pqc_asn1_spki_build_write(der, der_size,
                                                     ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                     pk, sizeof(pk), &written));
    CHECK(written == der_size);

    const uint8_t *out_oid, *out_pk;
    size_t out_oid_len, out_pk_len;
    CHECK_RC(pqc_asn1_spki_parse(der, written,
                                          &out_oid, &out_oid_len,
                                          NULL, NULL,
                                          &out_pk, &out_pk_len,
                                          0));
    CHECK(out_oid_len == sizeof(ML_DSA_65_OID));
    CHECK(memcmp(out_oid, ML_DSA_65_OID, sizeof(ML_DSA_65_OID)) == 0);
    CHECK(out_pk_len == sizeof(pk));
    CHECK(memcmp(out_pk, pk, sizeof(pk)) == 0);

    free(der);
}

static void test_spki_allocating(void)
{
    uint8_t pk[32];
    memset(pk, 0xCD, sizeof(pk));

    uint8_t *der = NULL;
    size_t total;
    CHECK_RC_BAIL(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                               pk, sizeof(pk), &der, &total));
    CHECK(total > 0);

    const uint8_t *out_oid, *out_pk;
    size_t out_oid_len, out_pk_len;
    CHECK_RC(pqc_asn1_spki_parse(der, total, &out_oid, &out_oid_len,
                                          NULL, NULL, &out_pk, &out_pk_len,
                                          0));
    CHECK(out_pk_len == sizeof(pk));
    CHECK(memcmp(out_pk, pk, sizeof(pk)) == 0);

    PQC_ASN1_FREE(der);
}

static void test_spki_invalid_oid(void)
{
    uint8_t bad_oid[] = {0x30, 0x03, 0x01, 0x01, 0x00};
    size_t bad_size;
    CHECK(pqc_asn1_spki_size(bad_oid, sizeof(bad_oid), 32, &bad_size) == PQC_ASN1_ERR_INVALID_OID);

    /* Allocating variant returns specific error. */
    uint8_t pk[32];
    uint8_t *der = NULL;
    size_t total;
    CHECK(pqc_asn1_spki_build(bad_oid, sizeof(bad_oid),
                                       pk, sizeof(pk), &der, &total) == PQC_ASN1_ERR_INVALID_OID);
}

static void test_spki_write_buffer_too_small(void)
{
    uint8_t pk[32];
    memset(pk, 0xAB, sizeof(pk));
    uint8_t tiny[4];
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_spki_build_write(
        tiny, sizeof(tiny),
        ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
        pk, sizeof(pk), &written);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

/* ------------------------------------------------------------------ */
/* PKCS#8 build + parse round-trip                                     */
/* ------------------------------------------------------------------ */

static void test_pkcs8_roundtrip(void)
{
    uint8_t sk[64];
    memset(sk, 0x99, sizeof(sk));

    size_t der_size;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_size(ML_DSA_65_OID, sizeof(ML_DSA_65_OID), sizeof(sk), &der_size));
    CHECK_BAIL(der_size > 0);

    uint8_t *der = (uint8_t *)malloc(der_size);
    CHECK_BAIL(der != NULL);
    size_t written;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build_write(der, der_size,
                                                      ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                      sk, sizeof(sk), &written));
    CHECK(written == der_size);

    const uint8_t *out_oid, *out_sk;
    size_t out_oid_len, out_sk_len;
    CHECK_RC(pqc_asn1_pkcs8_parse(der, written,
                                           &out_oid, &out_oid_len,
                                           NULL, NULL,
                                           &out_sk, &out_sk_len,
                                           NULL, NULL,
                                           0));
    CHECK(out_oid_len == sizeof(ML_DSA_65_OID));
    CHECK(memcmp(out_oid, ML_DSA_65_OID, sizeof(ML_DSA_65_OID)) == 0);
    CHECK(out_sk_len == sizeof(sk));
    CHECK(memcmp(out_sk, sk, sizeof(sk)) == 0);

    pqc_asn1_secure_zero(der, der_size);
    free(der);
}

static void test_pkcs8_allocating(void)
{
    uint8_t sk[64];
    memset(sk, 0x77, sizeof(sk));

    uint8_t *der = NULL;
    size_t total;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                sk, sizeof(sk), &der, &total));

    const uint8_t *out_oid, *out_sk;
    size_t out_oid_len, out_sk_len;
    CHECK_RC(pqc_asn1_pkcs8_parse(der, total, &out_oid, &out_oid_len,
                                           NULL, NULL, &out_sk, &out_sk_len,
                                           NULL, NULL,
                                           0));
    CHECK(out_sk_len == sizeof(sk));

    pqc_asn1_secure_zero(der, total);
    PQC_ASN1_FREE(der);
}

/* RFC 5958 §2: when the OneAsymmetricKey publicKey [1] field is present the
 * version must be v2 (INTEGER 1).  This round-trips build_write_ex(pub) through
 * the parser, which also enforces the version-vs-publicKey rule. */
static void test_pkcs8_publickey_roundtrip(void)
{
    uint8_t sk[64];
    uint8_t pk[32];
    memset(sk, 0x55, sizeof(sk));
    memset(pk, 0xAB, sizeof(pk));

    size_t der_size;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_size_ex(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                  NULL, 0, sizeof(sk), sizeof(pk), &der_size));
    CHECK_BAIL(der_size > 0);

    uint8_t *der = (uint8_t *)malloc(der_size);
    CHECK_BAIL(der != NULL);
    size_t written;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build_write_ex(der, der_size,
                                                         ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                         NULL, 0,
                                                         sk, sizeof(sk),
                                                         pk, sizeof(pk),
                                                         &written));
    CHECK(written == der_size);

    /* The version TLV (02 01 vv) is the first element inside the outer
     * SEQUENCE, so the first 02 01 00/01 in the stream is the version; with
     * publicKey present it must be v2 (01). */
    size_t i;
    int found_version = 0;
    for (i = 0; i + 2 < written; i++) {
        if (der[i] == 0x02 && der[i+1] == 0x01 &&
            (der[i+2] == 0x00 || der[i+2] == 0x01)) {
            CHECK(der[i+2] == 0x01);  /* v2 because publicKey is present */
            found_version = 1;
            break;
        }
    }
    CHECK(found_version);

    const uint8_t *out_oid, *out_sk, *out_pub;
    size_t out_oid_len, out_sk_len, out_pub_len;
    CHECK_RC(pqc_asn1_pkcs8_parse(der, written,
                                           &out_oid, &out_oid_len,
                                           NULL, NULL,
                                           &out_sk, &out_sk_len,
                                           &out_pub, &out_pub_len,
                                           0));
    CHECK(out_oid_len == sizeof(ML_DSA_65_OID));
    CHECK(memcmp(out_oid, ML_DSA_65_OID, sizeof(ML_DSA_65_OID)) == 0);
    CHECK(out_sk_len == sizeof(sk));
    CHECK(memcmp(out_sk, sk, sizeof(sk)) == 0);
    CHECK(out_pub_len == sizeof(pk));
    CHECK(out_pub != NULL && memcmp(out_pub, pk, sizeof(pk)) == 0);

    pqc_asn1_secure_zero(der, der_size);
    free(der);
}

/* RFC 5958 §2 consistency: v2 (version 1) without a publicKey, and v1
 * (version 0) with a publicKey, are both rejected as PQC_ASN1_ERR_VERSION. */
static void test_pkcs8_version_publickey_mismatch(void)
{
    uint8_t sk[32];
    uint8_t pk[16];
    memset(sk, 0x22, sizeof(sk));
    memset(pk, 0xCD, sizeof(pk));

    const uint8_t *o, *s, *pb;
    size_t ol, sl, pl;

    /* Case 1: v1 (version 0) carrying a publicKey — build with pub, then
     * force the version byte back to 0.  Parser must reject. */
    size_t sz1;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_size_ex(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                  NULL, 0, sizeof(sk), sizeof(pk), &sz1));
    uint8_t *d1 = (uint8_t *)malloc(sz1);
    CHECK_BAIL(d1 != NULL);
    size_t w1;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build_write_ex(d1, sz1,
                                                         ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                         NULL, 0, sk, sizeof(sk),
                                                         pk, sizeof(pk), &w1));
    size_t i;
    for (i = 0; i + 2 < w1; i++) {
        if (d1[i] == 0x02 && d1[i+1] == 0x01 && d1[i+2] == 0x01) { d1[i+2] = 0x00; break; }
    }
    CHECK(pqc_asn1_pkcs8_parse(d1, w1, &o, &ol, NULL, NULL, &s, &sl,
                                        &pb, &pl, 0) == PQC_ASN1_ERR_VERSION);
    pqc_asn1_secure_zero(d1, sz1);
    free(d1);

    /* Case 2: v2 (version 1) without a publicKey — build without pub, then
     * force the version byte to 1.  Parser must reject. */
    uint8_t *d2 = NULL;
    size_t t2;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                sk, sizeof(sk), &d2, &t2));
    for (i = 0; i + 2 < t2; i++) {
        if (d2[i] == 0x02 && d2[i+1] == 0x01 && d2[i+2] == 0x00) { d2[i+2] = 0x01; break; }
    }
    CHECK(pqc_asn1_pkcs8_parse(d2, t2, &o, &ol, NULL, NULL, &s, &sl,
                                        &pb, &pl, 0) == PQC_ASN1_ERR_VERSION);
    pqc_asn1_secure_zero(d2, t2);
    PQC_ASN1_FREE(d2);
}

/* RFC 5958 §2: the OPTIONAL attributes [0] field (tag 0xA0) may appear after
 * privateKey.  The library does not model attributes, but the parser must
 * accept and skip it rather than reject the whole structure. */
static void test_pkcs8_attributes_accepted(void)
{
    uint8_t sk[8];
    uint8_t attrs_inner[] = { 0x05, 0x00 };  /* opaque placeholder content */
    memset(sk, 0x33, sizeof(sk));

    /* Hand-build a v1 OneAsymmetricKey with attributes [0] and no publicKey:
     *   SEQUENCE { INTEGER 0, SEQUENCE{OID}, OCTET STRING{sk}, [0]{attrs} } */
    uint8_t body[128];
    size_t p = 0;
    body[p++] = 0x02; body[p++] = 0x01; body[p++] = 0x00;             /* version 0 */
    body[p++] = 0x30; body[p++] = (uint8_t)sizeof(ML_DSA_65_OID);     /* alg SEQUENCE */
    memcpy(body + p, ML_DSA_65_OID, sizeof(ML_DSA_65_OID)); p += sizeof(ML_DSA_65_OID);
    body[p++] = 0x04; body[p++] = (uint8_t)sizeof(sk);                /* privateKey */
    memcpy(body + p, sk, sizeof(sk)); p += sizeof(sk);
    body[p++] = 0xA0; body[p++] = (uint8_t)sizeof(attrs_inner);       /* attributes [0] */
    memcpy(body + p, attrs_inner, sizeof(attrs_inner)); p += sizeof(attrs_inner);

    uint8_t der[130];
    size_t d = 0;
    der[d++] = 0x30; der[d++] = (uint8_t)p;   /* p < 128 → short-form length */
    memcpy(der + d, body, p); d += p;

    const uint8_t *out_oid, *out_sk, *out_pub;
    size_t out_oid_len, out_sk_len, out_pub_len;
    CHECK_RC(pqc_asn1_pkcs8_parse(der, d, &out_oid, &out_oid_len,
                                           NULL, NULL, &out_sk, &out_sk_len,
                                           &out_pub, &out_pub_len, 0));
    CHECK(out_sk_len == sizeof(sk));
    CHECK(memcmp(out_sk, sk, sizeof(sk)) == 0);
    CHECK(out_pub == NULL);          /* no publicKey present */
    CHECK(out_pub_len == 0);
}

/* attributes [0] followed by publicKey [1] (RFC 5958 field order) on a v2 key
 * must parse, skipping attributes and returning the publicKey. */
static void test_pkcs8_attributes_and_publickey(void)
{
    uint8_t sk[8];
    uint8_t pk[6];
    uint8_t attrs_inner[] = { 0x05, 0x00 };
    memset(sk, 0x44, sizeof(sk));
    memset(pk, 0x55, sizeof(pk));

    uint8_t body[128];
    size_t p = 0;
    body[p++] = 0x02; body[p++] = 0x01; body[p++] = 0x01;             /* version 1 (v2) */
    body[p++] = 0x30; body[p++] = (uint8_t)sizeof(ML_DSA_65_OID);
    memcpy(body + p, ML_DSA_65_OID, sizeof(ML_DSA_65_OID)); p += sizeof(ML_DSA_65_OID);
    body[p++] = 0x04; body[p++] = (uint8_t)sizeof(sk);
    memcpy(body + p, sk, sizeof(sk)); p += sizeof(sk);
    body[p++] = 0xA0; body[p++] = (uint8_t)sizeof(attrs_inner);       /* attributes [0] */
    memcpy(body + p, attrs_inner, sizeof(attrs_inner)); p += sizeof(attrs_inner);
    body[p++] = 0x81; body[p++] = (uint8_t)sizeof(pk);               /* publicKey [1] */
    memcpy(body + p, pk, sizeof(pk)); p += sizeof(pk);

    uint8_t der[130];
    size_t d = 0;
    der[d++] = 0x30; der[d++] = (uint8_t)p;
    memcpy(der + d, body, p); d += p;

    const uint8_t *out_oid, *out_sk, *out_pub;
    size_t out_oid_len, out_sk_len, out_pub_len;
    CHECK_RC(pqc_asn1_pkcs8_parse(der, d, &out_oid, &out_oid_len,
                                           NULL, NULL, &out_sk, &out_sk_len,
                                           &out_pub, &out_pub_len, 0));
    CHECK(out_sk_len == sizeof(sk));
    CHECK(memcmp(out_sk, sk, sizeof(sk)) == 0);
    CHECK(out_pub_len == sizeof(pk));
    CHECK(out_pub != NULL && memcmp(out_pub, pk, sizeof(pk)) == 0);
}

static void test_pkcs8_write_buffer_too_small(void)
{
    uint8_t sk[64];
    memset(sk, 0x99, sizeof(sk));
    uint8_t tiny[4];
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_pkcs8_build_write(
        tiny, sizeof(tiny),
        ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
        sk, sizeof(sk), &written);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

/* ------------------------------------------------------------------ */
/* PEM encode + decode round-trip                                      */
/* ------------------------------------------------------------------ */

static void test_pem_roundtrip(void)
{
    uint8_t pk[32];
    memset(pk, 0xEE, sizeof(pk));

    /* Build SPKI DER first */
    uint8_t *der = NULL;
    size_t der_total;
    CHECK_RC_BAIL(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                               pk, sizeof(pk), &der, &der_total));

    /* Encode to PEM using non-allocating API */
    const char *label = "PUBLIC KEY";
    size_t label_len = strlen(label);
    size_t pem_size;
    CHECK_RC_BAIL(pqc_asn1_pem_encode_size(der_total, label, label_len, &pem_size));
    char *pem_buf = (char *)malloc(pem_size + 1);
    CHECK_BAIL(pem_buf != NULL);
    size_t pem_written;
    CHECK_RC_BAIL(pqc_asn1_pem_encode_write(der, der_total, label, label_len,
                                              pem_buf, pem_size, &pem_written));
    pem_buf[pem_written] = '\0';

    CHECK(strncmp(pem_buf, "-----BEGIN PUBLIC KEY-----", 26) == 0);

    /* Decode back */
    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    CHECK_RC(pqc_asn1_pem_decode(pem_buf, pem_written,
                                   "PUBLIC KEY", 10,
                                   &decoded, &decoded_len,
                                   found_label, sizeof(found_label)));
    CHECK(decoded_len == der_total);
    CHECK(memcmp(decoded, der, der_total) == 0);
    CHECK(strcmp(found_label, "PUBLIC KEY") == 0);

    PQC_ASN1_FREE(decoded);
    free(pem_buf);
    PQC_ASN1_FREE(der);
}

static void test_pem_encode_allocating(void)
{
    uint8_t pk[32];
    memset(pk, 0xEE, sizeof(pk));

    uint8_t *der = NULL;
    size_t der_total;
    CHECK_RC_BAIL(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                               pk, sizeof(pk), &der, &der_total));

    /* Use the allocating PEM encode wrapper */
    char *pem_buf = NULL;
    size_t pem_len;
    CHECK_RC_BAIL(pqc_asn1_pem_encode(der, der_total, "PUBLIC KEY", 10,
                                        &pem_buf, &pem_len));
    CHECK(pem_len > 0);
    CHECK(strncmp(pem_buf, "-----BEGIN PUBLIC KEY-----", 26) == 0);

    /* Decode back to verify round-trip */
    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    CHECK_RC(pqc_asn1_pem_decode(pem_buf, pem_len,
                                   "PUBLIC KEY", 10,
                                   &decoded, &decoded_len,
                                   found_label, sizeof(found_label)));
    CHECK(decoded_len == der_total);
    CHECK(memcmp(decoded, der, der_total) == 0);

    PQC_ASN1_FREE(decoded);
    PQC_ASN1_FREE(pem_buf);
    PQC_ASN1_FREE(der);
}

static void test_pem_decode_auto(void)
{
    const char pem[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "AAEC\n"
        "-----END PRIVATE KEY-----\n";

    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    CHECK_RC_BAIL(pqc_asn1_pem_decode_auto(pem, strlen(pem),
                                             &decoded, &decoded_len,
                                             found_label, sizeof(found_label)));
    CHECK(strcmp(found_label, "PRIVATE KEY") == 0);
    CHECK(decoded_len == 3);
    CHECK(decoded[0] == 0x00 && decoded[1] == 0x01 && decoded[2] == 0x02);

    PQC_ASN1_FREE(decoded);
}

static void test_pem_label_mismatch(void)
{
    const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";

    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    pqc_asn1_status_t rc = pqc_asn1_pem_decode(pem, strlen(pem), "PRIVATE KEY", 11,
                                                  &decoded, &decoded_len,
                                                  found_label, sizeof(found_label));
    CHECK(rc == PQC_ASN1_ERR_PEM_LABEL);
    CHECK(decoded == NULL);
    CHECK(decoded_len == 0);
}

static void test_pem_no_markers(void)
{
    const char pem[] = "not a PEM at all";
    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    pqc_asn1_status_t rc = pqc_asn1_pem_decode(pem, strlen(pem), "PUBLIC KEY", 10,
                                                  &decoded, &decoded_len,
                                                  found_label, sizeof(found_label));
    CHECK(rc == PQC_ASN1_ERR_PEM_NO_MARKERS);
    CHECK(decoded == NULL);
    CHECK(decoded_len == 0);
}

static void test_pem_encode_buffer_too_small(void)
{
    const uint8_t der[] = {0x30, 0x03, 0x01, 0x01, 0x00};
    char tiny[4];
    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_pem_encode_write(der, sizeof(der),
                                                        "PUBLIC KEY", 10,
                                                        tiny, sizeof(tiny),
                                                        &written);
    CHECK(rc == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

static void test_pem_label_too_long(void)
{
    char long_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 16];
    memset(long_label, 'A', sizeof(long_label) - 1);
    long_label[sizeof(long_label) - 1] = '\0';

    size_t sz;
    CHECK(pqc_asn1_pem_encode_size(10, long_label, sizeof(long_label) - 1, &sz) == PQC_ASN1_ERR_LABEL_TOO_LONG);

    /* Allocating wrapper returns specific error. */
    char *buf = NULL;
    size_t len;
    const uint8_t der[] = {0x30, 0x00};
    CHECK(pqc_asn1_pem_encode(der, sizeof(der), long_label, sizeof(long_label) - 1,
                                &buf, &len) == PQC_ASN1_ERR_LABEL_TOO_LONG);
}

/* ------------------------------------------------------------------ */
/* Secure zeroing                                                      */
/* ------------------------------------------------------------------ */

static void test_secure_zero(void)
{
    uint8_t buf[16];
    memset(buf, 0xFF, sizeof(buf));
    pqc_asn1_secure_zero(buf, sizeof(buf));
    size_t i;
    for (i = 0; i < sizeof(buf); i++)
        CHECK(buf[i] == 0);

    /* NULL should not crash */
    pqc_asn1_secure_zero(NULL, 0);
    pqc_asn1_secure_zero(NULL, 10);
}

/* ------------------------------------------------------------------ */
/* Error messages                                                      */
/* ------------------------------------------------------------------ */

static void test_error_messages(void)
{
    CHECK(strcmp(pqc_asn1_error_message(PQC_ASN1_OK), "success") == 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_OUTER_SEQUENCE)) > 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_BUFFER_TOO_SMALL)) > 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_LABEL_TOO_LONG)) > 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_DER_PARSE)) > 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_BASE64)) > 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_NULL_PARAM)) > 0);
    CHECK(strcmp(pqc_asn1_error_message(PQC_ASN1_ERR_NULL_PARAM),
                 "required pointer parameter is NULL") == 0);
    CHECK(strlen(pqc_asn1_error_message(PQC_ASN1_ERR_PEM_MALFORMED)) > 0);
    CHECK(strcmp(pqc_asn1_error_message((pqc_asn1_status_t)-999), "unknown error") == 0);
}

/* ------------------------------------------------------------------ */
/* Parse error cases                                                   */
/* ------------------------------------------------------------------ */

static void test_parse_spki_trailing_data(void)
{
    uint8_t pk[32];
    memset(pk, 0xAB, sizeof(pk));
    uint8_t *der = NULL;
    size_t total;
    CHECK_RC_BAIL(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                               pk, sizeof(pk), &der, &total));

    uint8_t *bad = (uint8_t *)malloc(total + 1);
    CHECK_BAIL(bad != NULL);
    memcpy(bad, der, total);
    bad[total] = 0xFF;

    const uint8_t *out_oid, *out_pk;
    size_t out_oid_len, out_pk_len;
    CHECK(pqc_asn1_spki_parse(bad, total + 1, &out_oid, &out_oid_len,
                                       NULL, NULL,
                                       &out_pk, &out_pk_len,
                                       0) == PQC_ASN1_ERR_TRAILING_DATA);

    free(bad);
    PQC_ASN1_FREE(der);
}

static void test_parse_pkcs8_bad_version(void)
{
    uint8_t sk[32];
    memset(sk, 0x11, sizeof(sk));
    uint8_t *der = NULL;
    size_t total;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                sk, sizeof(sk), &der, &total));

    /* Find version INTEGER 0 (bytes 02 01 00) and change 00 to 01 */
    size_t i;
    for (i = 0; i + 2 < total; i++) {
        if (der[i] == 0x02 && der[i+1] == 0x01 && der[i+2] == 0x00) {
            der[i+2] = 0x01;
            break;
        }
    }

    const uint8_t *out_oid, *out_sk;
    size_t out_oid_len, out_sk_len;
    CHECK(pqc_asn1_pkcs8_parse(der, total, &out_oid, &out_oid_len,
                                        NULL, NULL,
                                        &out_sk, &out_sk_len,
                                        NULL, NULL,
                                        0) == PQC_ASN1_ERR_VERSION);

    PQC_ASN1_FREE(der);
}

/* ------------------------------------------------------------------ */
/* PEM BEGIN marker must be at line start                               */
/* ------------------------------------------------------------------ */

static void test_pem_begin_must_be_at_line_start(void)
{
    /* BEGIN marker mid-line should be rejected. */
    const char bad_pem[] =
        "garbage-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";
    uint8_t *decoded = NULL;
    size_t decoded_len;
    char found_label[128];
    pqc_asn1_status_t rc = pqc_asn1_pem_decode(bad_pem, strlen(bad_pem),
                                                  "PUBLIC KEY", 10,
                                                  &decoded, &decoded_len,
                                                  found_label, sizeof(found_label));
    CHECK(rc == PQC_ASN1_ERR_PEM_NO_MARKERS);
    CHECK(decoded == NULL);

    /* BEGIN marker after newline should work. */
    const char good_pem[] =
        "some header text\n"
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";
    rc = pqc_asn1_pem_decode(good_pem, strlen(good_pem),
                               "PUBLIC KEY", 10,
                               &decoded, &decoded_len,
                               found_label, sizeof(found_label));
    CHECK(rc == PQC_ASN1_OK);
    CHECK(decoded_len == 3);
    PQC_ASN1_FREE(decoded);
}

/* ------------------------------------------------------------------ */
/* Base64 non-zero padding bits                                        */
/* ------------------------------------------------------------------ */

static void test_base64_reject_nonzero_padding_bits(void)
{
    /* "AB==" — 'B' (value 1) has non-zero bits below byte boundary.
     * Only bits 16-23 are significant; bit 12 from 'B' is non-significant
     * and must be zero per RFC 4648 §3.5. */
    uint8_t *result = NULL;
    size_t out_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode(
        "AB==", 4, &result, &out_len);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
    CHECK(result == NULL);

    /* "AAB=" — 'B' (value 1) has non-zero bits below the 2-byte boundary.
     * Only bits 8-23 are significant; bits 0-7 from 'B' are non-significant. */
    rc = pqc_asn1_base64_decode(
        "AAB=", 4, &result, &out_len);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
    CHECK(result == NULL);

    /* "AA==" — valid: 'A' (value 0) has all zero non-significant bits. */
    rc = pqc_asn1_base64_decode(
        "AA==", 4, &result, &out_len);
    CHECK(rc == PQC_ASN1_OK);
    CHECK(out_len == 1);
    CHECK(result[0] == 0x00);
    PQC_ASN1_FREE(result);

    /* "AAA=" — valid: 'A' (value 0) has all zero non-significant bits. */
    rc = pqc_asn1_base64_decode(
        "AAA=", 4, &result, &out_len);
    CHECK(rc == PQC_ASN1_OK);
    CHECK(out_len == 2);
    PQC_ASN1_FREE(result);
}

/* ------------------------------------------------------------------ */
/* OID validation: zero-length content rejected                        */
/* ------------------------------------------------------------------ */

static void test_oid_zero_length_rejected(void)
{
    /* {0x06, 0x00} is a zero-length OID — invalid per X.690. */
    uint8_t zero_oid[] = {0x06, 0x00};
    size_t sz;
    CHECK(pqc_asn1_spki_size(zero_oid, sizeof(zero_oid), 32, &sz) == PQC_ASN1_ERR_INVALID_OID);
    CHECK(pqc_asn1_pkcs8_size(zero_oid, sizeof(zero_oid), 32, &sz) == PQC_ASN1_ERR_INVALID_OID);

    uint8_t pk[4] = {0};
    uint8_t *der = NULL;
    size_t total;
    CHECK(pqc_asn1_spki_build(zero_oid, sizeof(zero_oid),
                                       pk, sizeof(pk), &der, &total) == PQC_ASN1_ERR_INVALID_OID);
    CHECK(der == NULL);
}

/* ------------------------------------------------------------------ */
/* AlgorithmIdentifier strictness                                      */
/* ------------------------------------------------------------------ */

static void test_spki_alg_id_trailing_data(void)
{
    /* Build a valid SPKI, then patch the AlgorithmIdentifier SEQUENCE
     * to include an extra NULL (05 00) after the OID — simulating an
     * AlgorithmIdentifier with parameters, which RFC 9629 forbids for PQC. */
    uint8_t pk[32];
    memset(pk, 0xAB, sizeof(pk));

    uint8_t *good_der = NULL;
    size_t good_total;
    CHECK_RC_BAIL(pqc_asn1_spki_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                               pk, sizeof(pk), &good_der, &good_total));

    /* Construct a modified DER: insert NULL (05 00) after OID inside
     * AlgorithmIdentifier, adjusting lengths accordingly.
     *
     * Structure: SEQUENCE { SEQUENCE { OID [NULL] } BIT STRING { ... } }
     * We need to increase the AlgorithmIdentifier SEQUENCE length by 2
     * and the outer SEQUENCE length by 2. */
    size_t bad_total = good_total + 2;
    uint8_t *bad = (uint8_t *)malloc(bad_total);
    CHECK_BAIL(bad != NULL);

    /* Find the AlgorithmIdentifier SEQUENCE (second 0x30 after outer). */
    /* Outer: 30 <len> 30 <alg_len> 06 09 ... */
    /* Copy tag + length of outer SEQUENCE */
    size_t p = 0;
    bad[p++] = 0x30;  /* outer SEQUENCE tag */
    /* Outer length: good_total - 2 + 2 = good_total. Use short form. */
    size_t outer_inner = good_total - 2 + 2;  /* original inner + 2 */
    bad[p++] = (uint8_t)outer_inner;
    /* AlgorithmIdentifier SEQUENCE */
    bad[p++] = 0x30;
    bad[p++] = (uint8_t)(sizeof(ML_DSA_65_OID) + 2);  /* OID + NULL */
    /* OID */
    memcpy(bad + p, ML_DSA_65_OID, sizeof(ML_DSA_65_OID));
    p += sizeof(ML_DSA_65_OID);
    /* Extra NULL parameter */
    bad[p++] = 0x05;
    bad[p++] = 0x00;
    /* Copy BIT STRING from original (everything after AlgorithmIdentifier) */
    /* In original: outer tag(1) + outer len(1) + alg tag(1) + alg len(1) + OID(11) = 15 */
    size_t orig_bs_offset = 2 + 2 + sizeof(ML_DSA_65_OID);
    memcpy(bad + p, good_der + orig_bs_offset, good_total - orig_bs_offset);

    const uint8_t *out_oid, *out_pk;
    size_t out_oid_len, out_pk_len;
    CHECK(pqc_asn1_spki_parse(bad, bad_total, &out_oid, &out_oid_len,
                                       NULL, NULL,
                                       &out_pk, &out_pk_len,
                                       PQC_PARSE_STRICT_ALG_ID) == PQC_ASN1_ERR_EXTRA_FIELDS);

    free(bad);
    PQC_ASN1_FREE(good_der);
}

static void test_pkcs8_alg_id_trailing_data(void)
{
    /* Same idea for PKCS#8: inject NULL after OID in AlgorithmIdentifier. */
    uint8_t sk[32];
    memset(sk, 0x99, sizeof(sk));

    uint8_t *good_der = NULL;
    size_t good_total;
    CHECK_RC_BAIL(pqc_asn1_pkcs8_build(ML_DSA_65_OID, sizeof(ML_DSA_65_OID),
                                                sk, sizeof(sk), &good_der, &good_total));

    size_t bad_total = good_total + 2;
    uint8_t *bad = (uint8_t *)malloc(bad_total);
    CHECK_BAIL(bad != NULL);

    /* Structure: SEQUENCE { INTEGER 0, SEQUENCE { OID [NULL] }, OCTET STRING { ... } } */
    size_t p = 0;
    bad[p++] = 0x30;  /* outer SEQUENCE tag */
    size_t outer_inner = good_total - 2 + 2;
    bad[p++] = (uint8_t)outer_inner;
    /* INTEGER 0 (version) */
    bad[p++] = 0x02; bad[p++] = 0x01; bad[p++] = 0x00;
    /* AlgorithmIdentifier SEQUENCE with extra NULL */
    bad[p++] = 0x30;
    bad[p++] = (uint8_t)(sizeof(ML_DSA_65_OID) + 2);
    memcpy(bad + p, ML_DSA_65_OID, sizeof(ML_DSA_65_OID));
    p += sizeof(ML_DSA_65_OID);
    bad[p++] = 0x05; bad[p++] = 0x00;
    /* Copy OCTET STRING from original */
    /* Original: outer(1) + len(1) + ver(3) + alg_seq(1) + alg_len(1) + OID(11) = 18 */
    size_t orig_os_offset = 2 + 3 + 2 + sizeof(ML_DSA_65_OID);
    memcpy(bad + p, good_der + orig_os_offset, good_total - orig_os_offset);

    const uint8_t *out_oid, *out_sk;
    size_t out_oid_len, out_sk_len;
    CHECK(pqc_asn1_pkcs8_parse(bad, bad_total, &out_oid, &out_oid_len,
                                        NULL, NULL,
                                        &out_sk, &out_sk_len,
                                        NULL, NULL,
                                        PQC_PARSE_STRICT_ALG_ID) == PQC_ASN1_ERR_EXTRA_FIELDS);

    free(bad);
    PQC_ASN1_FREE(good_der);
}

static void test_der_read_tlv_preserves_pos_on_error(void)
{
    /* Tag matches but length is invalid — *pos must not advance. */
    uint8_t buf[] = {0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05};
    size_t pos = 0;
    size_t saved_pos = pos;
    const uint8_t *content;
    size_t content_len;
    CHECK(pqc_asn1_der_read_tlv(buf, sizeof(buf), &pos, 0x30,
                                  &content, &content_len) == PQC_ASN1_ERR_DER_PARSE);
    CHECK(pos == saved_pos);

    /* Wrong tag — *pos must not advance. */
    pos = 0;
    saved_pos = pos;
    CHECK(pqc_asn1_der_read_tlv(buf, sizeof(buf), &pos, 0x04,
                                  &content, &content_len) == PQC_ASN1_ERR_DER_PARSE);
    CHECK(pos == saved_pos);
}

static void test_pem_end_must_be_at_line_start(void)
{
    /* END marker embedded mid-line should be rejected. */
    const char *mid_line_end =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAAA\n"
        "X-----END PUBLIC KEY-----\n";
    uint8_t *out = NULL;
    size_t out_len;
    char label[64];
    CHECK(pqc_asn1_pem_decode(mid_line_end, strlen(mid_line_end),
                                "PUBLIC KEY", 10, &out, &out_len,
                                label, sizeof(label)) == PQC_ASN1_ERR_PEM_NO_MARKERS);
    if (out) PQC_ASN1_FREE(out);

    /* END marker at line start (after \n) should succeed. */
    const char *good =
        "-----BEGIN PUBLIC KEY-----\n"
        "QQ==\n"
        "-----END PUBLIC KEY-----\n";
    out = NULL;
    CHECK(pqc_asn1_pem_decode(good, strlen(good),
                                "PUBLIC KEY", 10, &out, &out_len,
                                label, sizeof(label)) == PQC_ASN1_OK);
    if (out) PQC_ASN1_FREE(out);
}

static void test_base64_reject_excess_padding(void)
{
    /* "====" is 4 padding chars — only 0, 1, or 2 are valid. */
    const char input[] = "====";
    uint8_t out[4];
    size_t written;
    CHECK(pqc_asn1_base64_decode_into(input, 4, out, sizeof(out),
                                        &written) == PQC_ASN1_ERR_BASE64);

    /* "A===" has 3 padding chars — also invalid. */
    const char input2[] = "A===";
    CHECK(pqc_asn1_base64_decode_into(input2, 4, out, sizeof(out),
                                        &written) == PQC_ASN1_ERR_BASE64);
}

static void test_pem_label_rejects_control_chars(void)
{
    /* Label with embedded NUL — should be rejected. */
    const char pem_nul[] =
        "-----BEGIN PUBLIC\0KEY-----\n"
        "QQ==\n"
        "-----END PUBLIC\0KEY-----\n";
    uint8_t *out = NULL;
    size_t out_len;
    char label[64];
    /* Use sizeof to include the NUL in the label region. */
    CHECK(pqc_asn1_pem_decode_auto(pem_nul, sizeof(pem_nul) - 1,
                                     &out, &out_len,
                                     label, sizeof(label)) == PQC_ASN1_ERR_PEM_LABEL);
    if (out) PQC_ASN1_FREE(out);

    /* Label with a tab (0x09) — also non-printable. */
    const char *pem_tab =
        "-----BEGIN PUBLIC\tKEY-----\n"
        "QQ==\n"
        "-----END PUBLIC\tKEY-----\n";
    out = NULL;
    CHECK(pqc_asn1_pem_decode_auto(pem_tab, strlen(pem_tab),
                                     &out, &out_len,
                                     label, sizeof(label)) == PQC_ASN1_ERR_PEM_LABEL);
    if (out) PQC_ASN1_FREE(out);
}

static void test_pem_begin_rejects_trailing_junk(void)
{
    /* Junk after closing dashes on BEGIN line. */
    const char *bad =
        "-----BEGIN PUBLIC KEY-----JUNK\n"
        "QQ==\n"
        "-----END PUBLIC KEY-----\n";
    uint8_t *out = NULL;
    size_t out_len;
    char label[64];
    CHECK(pqc_asn1_pem_decode(bad, strlen(bad), "PUBLIC KEY", 10,
                                &out, &out_len, label, sizeof(label))
            == PQC_ASN1_ERR_PEM_MALFORMED);
    if (out) PQC_ASN1_FREE(out);

    /* Trailing whitespace after dashes is OK. */
    const char *ok =
        "-----BEGIN PUBLIC KEY-----   \n"
        "QQ==\n"
        "-----END PUBLIC KEY-----\n";
    out = NULL;
    CHECK(pqc_asn1_pem_decode(ok, strlen(ok), "PUBLIC KEY", 10,
                                &out, &out_len, label, sizeof(label))
            == PQC_ASN1_OK);
    if (out) PQC_ASN1_FREE(out);
}

static void test_pem_end_rejects_trailing_junk(void)
{
    /* Junk after closing dashes on END line. */
    const char *bad =
        "-----BEGIN PUBLIC KEY-----\n"
        "QQ==\n"
        "-----END PUBLIC KEY-----JUNK\n";
    uint8_t *out = NULL;
    size_t out_len;
    char label[64];
    CHECK(pqc_asn1_pem_decode(bad, strlen(bad), "PUBLIC KEY", 10,
                                &out, &out_len, label, sizeof(label))
            == PQC_ASN1_ERR_PEM_MALFORMED);
    if (out) PQC_ASN1_FREE(out);

    /* Trailing whitespace after END dashes is OK. */
    const char *ok =
        "-----BEGIN PUBLIC KEY-----\n"
        "QQ==\n"
        "-----END PUBLIC KEY-----   \n";
    out = NULL;
    CHECK(pqc_asn1_pem_decode(ok, strlen(ok), "PUBLIC KEY", 10,
                                &out, &out_len, label, sizeof(label))
            == PQC_ASN1_OK);
    if (out) PQC_ASN1_FREE(out);

    /* END line at EOF without trailing newline is OK. */
    const char *eof =
        "-----BEGIN PUBLIC KEY-----\n"
        "QQ==\n"
        "-----END PUBLIC KEY-----";
    out = NULL;
    CHECK(pqc_asn1_pem_decode(eof, strlen(eof), "PUBLIC KEY", 10,
                                &out, &out_len, label, sizeof(label))
            == PQC_ASN1_OK);
    if (out) PQC_ASN1_FREE(out);
}

static void test_base64_decode_zeros_output_on_error(void)
{
    /* Decode valid prefix then hit an invalid char — partial output must be zeroed. */
    uint8_t out[16];
    memset(out, 0xAA, sizeof(out));
    size_t written;
    /* "QUFB" decodes to "AAA" (3 bytes), then "!!!" is invalid. */
    const char input[] = "QUFB!!!";
    pqc_asn1_status_t rc = pqc_asn1_base64_decode_into(input, 7,
                                                          out, sizeof(out), &written);
    CHECK(rc == PQC_ASN1_ERR_BASE64);
    /* The first 3 bytes of output should have been zeroed. */
    CHECK(out[0] == 0);
    CHECK(out[1] == 0);
    CHECK(out[2] == 0);
}

/* ------------------------------------------------------------------ */
/* Direct pqc_asn1_validate_pem_label tests                            */
/* ------------------------------------------------------------------ */

static void test_validate_pem_label_direct(void)
{
    /* NULL label */
    CHECK(pqc_asn1_validate_pem_label(NULL, 5) == PQC_ASN1_ERR_PEM_LABEL);

    /* Empty label (label_len == 0) */
    CHECK(pqc_asn1_validate_pem_label("X", 0) == PQC_ASN1_ERR_PEM_LABEL);

    /* Valid labels */
    CHECK(pqc_asn1_validate_pem_label("PUBLIC KEY", 10) == PQC_ASN1_OK);
    CHECK(pqc_asn1_validate_pem_label("PRIVATE KEY", 11) == PQC_ASN1_OK);
    CHECK(pqc_asn1_validate_pem_label("X", 1) == PQC_ASN1_OK);

    /* Non-printable at start, middle, end */
    CHECK(pqc_asn1_validate_pem_label("\x01KEY", 4) == PQC_ASN1_ERR_PEM_LABEL);
    CHECK(pqc_asn1_validate_pem_label("PU\x7FKEY", 6) == PQC_ASN1_ERR_PEM_LABEL);
    CHECK(pqc_asn1_validate_pem_label("KEY\x00", 4) == PQC_ASN1_ERR_PEM_LABEL);

    /* Exact max length — should succeed */
    char max_label[PQC_ASN1_MAX_PEM_LABEL_LEN];
    memset(max_label, 'A', sizeof(max_label));
    CHECK(pqc_asn1_validate_pem_label(max_label, PQC_ASN1_MAX_PEM_LABEL_LEN) == PQC_ASN1_OK);

    /* One over max — should fail */
    char over_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
    memset(over_label, 'A', sizeof(over_label));
    CHECK(pqc_asn1_validate_pem_label(over_label, sizeof(over_label)) == PQC_ASN1_ERR_LABEL_TOO_LONG);
}

/* ------------------------------------------------------------------ */
/* PEM decode into buffer                                              */
/* ------------------------------------------------------------------ */

static void test_pem_decode_into(void)
{
    const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";

    /* Decode with label check */
    uint8_t out[64];
    size_t written;
    char label[64];
    CHECK_RC(pqc_asn1_pem_decode_into(pem, strlen(pem), "PUBLIC KEY", 10,
                                        out, sizeof(out), &written,
                                        label, sizeof(label)));
    CHECK(written == 3);
    CHECK(out[0] == 0x00 && out[1] == 0x01 && out[2] == 0x02);
    CHECK(strcmp(label, "PUBLIC KEY") == 0);

    /* Label mismatch */
    written = 99;
    CHECK(pqc_asn1_pem_decode_into(pem, strlen(pem), "PRIVATE KEY", 11,
                                     out, sizeof(out), &written,
                                     label, sizeof(label)) == PQC_ASN1_ERR_PEM_LABEL);
    CHECK(written == 0);

    /* Buffer too small */
    uint8_t tiny[1];
    CHECK(pqc_asn1_pem_decode_into(pem, strlen(pem), "PUBLIC KEY", 10,
                                     tiny, sizeof(tiny), &written,
                                     label, sizeof(label)) == PQC_ASN1_ERR_BUFFER_TOO_SMALL);
}

static void test_pem_decode_auto_into(void)
{
    const char pem[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "AAEC\n"
        "-----END PRIVATE KEY-----\n";

    uint8_t out[64];
    size_t written;
    char label[64];
    CHECK_RC(pqc_asn1_pem_decode_auto_into(pem, strlen(pem),
                                             out, sizeof(out), &written,
                                             label, sizeof(label)));
    CHECK(written == 3);
    CHECK(strcmp(label, "PRIVATE KEY") == 0);
    CHECK(out[0] == 0x00 && out[1] == 0x01 && out[2] == 0x02);
}

/* ------------------------------------------------------------------ */
/* PEM decode with NULL found_label (optional)                         */
/* ------------------------------------------------------------------ */

static void test_pem_decode_null_found_label(void)
{
    const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "AAEC\n"
        "-----END PUBLIC KEY-----\n";

    /* Allocating: found_label = NULL should work. */
    uint8_t *decoded = NULL;
    size_t decoded_len;
    CHECK_RC_BAIL(pqc_asn1_pem_decode(pem, strlen(pem), "PUBLIC KEY", 10,
                                        &decoded, &decoded_len,
                                        NULL, 0));
    CHECK(decoded_len == 3);
    CHECK(decoded[0] == 0x00 && decoded[1] == 0x01 && decoded[2] == 0x02);
    PQC_ASN1_FREE(decoded);

    /* Auto allocating: found_label = NULL should work. */
    decoded = NULL;
    CHECK_RC_BAIL(pqc_asn1_pem_decode_auto(pem, strlen(pem),
                                             &decoded, &decoded_len,
                                             NULL, 0));
    CHECK(decoded_len == 3);
    PQC_ASN1_FREE(decoded);

    /* Into-buffer: found_label = NULL should work. */
    uint8_t out[64];
    size_t written;
    CHECK_RC(pqc_asn1_pem_decode_into(pem, strlen(pem), "PUBLIC KEY", 10,
                                        out, sizeof(out), &written,
                                        NULL, 0));
    CHECK(written == 3);

    /* Auto into-buffer: found_label = NULL should work. */
    CHECK_RC(pqc_asn1_pem_decode_auto_into(pem, strlen(pem),
                                             out, sizeof(out), &written,
                                             NULL, 0));
    CHECK(written == 3);

    /* Label mismatch still detected with found_label = NULL. */
    decoded = NULL;
    CHECK(pqc_asn1_pem_decode(pem, strlen(pem), "PRIVATE KEY", 11,
                                &decoded, &decoded_len,
                                NULL, 0) == PQC_ASN1_ERR_PEM_LABEL);
    CHECK(decoded == NULL);
}

/* ------------------------------------------------------------------ */
/* Base64 line wrapping at boundary                                    */
/* ------------------------------------------------------------------ */

static void test_base64_encode_line_wrap_boundary(void)
{
    /* 48 bytes of input produce exactly 64 base64 chars (one full line).
     * 49 bytes produce 64 + newline + 4 chars.  Before the fix, the
     * trailing 4-char group was appended without a newline, creating
     * a 68-char line. */
    uint8_t data49[49];
    memset(data49, 0xAA, sizeof(data49));

    char *b64 = NULL;
    size_t b64_len;
    CHECK_RC_BAIL(pqc_asn1_base64_encode(data49, sizeof(data49),
                                           &b64, &b64_len));

    /* Verify no line exceeds 64 chars. */
    size_t col = 0;
    size_t i;
    for (i = 0; i < b64_len; i++) {
        if (b64[i] == '\n') {
            CHECK(col <= 64);
            col = 0;
        } else {
            col++;
        }
    }
    /* Last line (may not end with \n) */
    CHECK(col <= 64);

    /* Round-trip: decode should recover original data. */
    uint8_t *decoded = NULL;
    size_t decoded_len;
    CHECK_RC(pqc_asn1_base64_decode(b64, b64_len, &decoded, &decoded_len));
    CHECK(decoded_len == sizeof(data49));
    if (decoded) {
        CHECK(memcmp(decoded, data49, sizeof(data49)) == 0);
        PQC_ASN1_FREE(decoded);
    }
    PQC_ASN1_FREE(b64);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== libpqcasn1 test suite ===\n\n");

    printf("Version:\n");
    RUN_TEST(test_version);

    printf("\nDER length:\n");
    RUN_TEST(test_der_length_short);
    RUN_TEST(test_der_length_two_byte);
    RUN_TEST(test_der_length_three_byte);
    RUN_TEST(test_der_length_size);
    RUN_TEST(test_der_reject_non_canonical_lengths);

    printf("\nDER TLV:\n");
    RUN_TEST(test_der_write_tlv);
    RUN_TEST(test_der_write_tlv_write);
    RUN_TEST(test_der_read_tlv);
    RUN_TEST(test_der_read_tlv_wrong_tag);
    RUN_TEST(test_der_read_tlv_preserves_pos_on_error);

    printf("\nNULL param validation:\n");
    RUN_TEST(test_null_params);
    RUN_TEST(test_out_params_zeroed_on_error);

    printf("\nBase64:\n");
    RUN_TEST(test_base64_encode_decode);
    RUN_TEST(test_base64_allocating);
    RUN_TEST(test_base64_invalid);
    RUN_TEST(test_base64_decode_bounds_check);
    RUN_TEST(test_base64_encode_buffer_too_small);
    RUN_TEST(test_base64_alloc_distinguishes_errors);

    printf("\nBase64 raw:\n");
    RUN_TEST(test_base64_raw_encode);
    RUN_TEST(test_base64_raw_encode_long);
    RUN_TEST(test_base64_raw_buffer_too_small);
    RUN_TEST(test_base64_raw_alloc);

    printf("\nSPKI:\n");
    RUN_TEST(test_spki_roundtrip);
    RUN_TEST(test_spki_allocating);
    RUN_TEST(test_spki_invalid_oid);
    RUN_TEST(test_spki_write_buffer_too_small);

    printf("\nPKCS#8:\n");
    RUN_TEST(test_pkcs8_roundtrip);
    RUN_TEST(test_pkcs8_allocating);
    RUN_TEST(test_pkcs8_publickey_roundtrip);
    RUN_TEST(test_pkcs8_version_publickey_mismatch);
    RUN_TEST(test_pkcs8_attributes_accepted);
    RUN_TEST(test_pkcs8_attributes_and_publickey);
    RUN_TEST(test_pkcs8_write_buffer_too_small);
    RUN_TEST(test_parse_pkcs8_bad_version);

    printf("\nPEM:\n");
    RUN_TEST(test_pem_roundtrip);
    RUN_TEST(test_pem_encode_allocating);
    RUN_TEST(test_pem_decode_auto);
    RUN_TEST(test_pem_label_mismatch);
    RUN_TEST(test_pem_no_markers);
    RUN_TEST(test_pem_encode_buffer_too_small);
    RUN_TEST(test_pem_label_too_long);

    printf("\nPEM line-start enforcement:\n");
    RUN_TEST(test_pem_begin_must_be_at_line_start);
    RUN_TEST(test_pem_end_must_be_at_line_start);

    printf("\nPEM label validation:\n");
    RUN_TEST(test_pem_label_rejects_control_chars);
    RUN_TEST(test_pem_begin_rejects_trailing_junk);
    RUN_TEST(test_pem_end_rejects_trailing_junk);

    printf("\nBase64 line wrapping:\n");
    RUN_TEST(test_base64_encode_line_wrap_boundary);

    printf("\nBase64 padding strictness:\n");
    RUN_TEST(test_base64_reject_nonzero_padding_bits);
    RUN_TEST(test_base64_reject_excess_padding);
    RUN_TEST(test_base64_decode_zeros_output_on_error);

    printf("\nPEM label validation (direct):\n");
    RUN_TEST(test_validate_pem_label_direct);

    printf("\nPEM decode into buffer:\n");
    RUN_TEST(test_pem_decode_into);
    RUN_TEST(test_pem_decode_auto_into);
    RUN_TEST(test_pem_decode_label_buffer_too_small);
    RUN_TEST(test_pem_decode_maxsize);
    RUN_TEST(test_pem_decode_null_found_label);

    printf("\nOID validation:\n");
    RUN_TEST(test_oid_zero_length_rejected);

    printf("\nAlgorithmIdentifier strictness:\n");
    RUN_TEST(test_spki_alg_id_trailing_data);
    RUN_TEST(test_pkcs8_alg_id_trailing_data);

    printf("\nMisc:\n");
    RUN_TEST(test_secure_zero);
    RUN_TEST(test_error_messages);
    RUN_TEST(test_parse_spki_trailing_data);

    printf("\n=== %d/%d tests passed", pass_count, test_count);
    if (fail_count > 0)
        printf(", %d FAILED", fail_count);
    printf(" ===\n");

    return (fail_count > 0) ? 1 : 0;
}
