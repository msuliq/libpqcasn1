/*
 * fuzz_decode.c — minimal libFuzzer entrypoint for base64 and PEM decode.
 *
 * Build:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
 *         -Iinclude -Isrc fuzz/fuzz_decode.c src/tlv.c src/builder.c       \
 *         src/parser.c src/base64.c src/pem.c -o fuzz/fuzz_decode
 *
 * Run:
 *   ./fuzz/fuzz_decode [-max_len=4096] [corpus_dir]
 */
#include "pqc_asn1.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* --- Base64 decode (into caller buffer) --- */
    {
        uint8_t buf[4096];
        size_t written = 0;
        pqc_asn1_base64_decode_into(
            (const char *)data, size,
            buf, sizeof(buf), &written);
    }

    /* --- Base64 decode (allocating) --- */
    {
        uint8_t *out = NULL;
        size_t out_len = 0;
        if (pqc_asn1_base64_decode(
                (const char *)data, size,
                &out, &out_len) == PQC_ASN1_OK) {
            PQC_ASN1_FREE(out);
        }
    }

    /* --- PEM decode auto (into caller buffer) --- */
    {
        uint8_t buf[4096];
        size_t written = 0;
        char label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
        pqc_asn1_pem_decode_auto_into(
            (const char *)data, size,
            buf, sizeof(buf), &written,
            label, sizeof(label));
    }

    /* --- PEM decode auto (allocating) --- */
    {
        uint8_t *out = NULL;
        size_t out_len = 0;
        char label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
        if (pqc_asn1_pem_decode_auto(
                (const char *)data, size,
                &out, &out_len,
                label, sizeof(label)) == PQC_ASN1_OK) {
            PQC_ASN1_FREE(out);
        }
    }

    return 0;
}
