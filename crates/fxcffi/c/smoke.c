/*
 * smoke.c - the suite's C-side proof for fxcffi.h: this file compiles
 * against the HEADER alone, links against the built static library, and
 * exercises the boundary in both directions (roundtrips plus committed
 * error codes). A header that lies about layout or names fails here.
 *
 * Wired into tests/suite.sh as "C smoke".
 */
#include "fxcffi.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "FAIL %s\n", msg);                            \
            fails++;                                                      \
        }                                                                 \
    } while (0)

int main(void) {
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    const char* plain = "c smoke plaintext";
    FxBytes enc = {NULL, 0};
    FxBytes dec = {NULL, 0};

    /* container roundtrip */
    CHECK(fx1_encrypt(7, key, sizeof(key), (const uint8_t*)plain,
                      strlen(plain), &enc) == FX_OK,
          "fx1_encrypt");
    CHECK(enc.len > 18, "container carries a header");
    CHECK(fx1_decrypt(7, key, sizeof(key), enc.ptr, enc.len, &dec) == FX_OK,
          "fx1_decrypt");
    CHECK(dec.len == strlen(plain) &&
              memcmp(dec.ptr, plain, dec.len) == 0,
          "container roundtrip bytes");
    fx_free(dec.ptr, dec.len);

    /* the committed wrong-key code */
    uint8_t wrong[32];
    memset(wrong, 0x43, sizeof(wrong));
    FxBytes out = {NULL, 0};
    CHECK(fx1_decrypt(7, wrong, sizeof(wrong), enc.ptr, enc.len, &out) ==
              FX_ERR_CHUNK,
          "wrong key answers FX_ERR_CHUNK");
    CHECK(strcmp(fx_error_name(FX_ERR_CHUNK), "FX_ERR_CHUNK") == 0,
          "fx_error_name");
    CHECK(fx1_decrypt(7, NULL, 32, enc.ptr, enc.len, &out) == FX_ERR_ARG,
          "NULL input answers FX_ERR_ARG");
    fx_free(enc.ptr, enc.len);

    /* empty plaintext: NULL/0 output must be freeable */
    FxBytes empty = {NULL, 0};
    CHECK(fx1_encrypt(7, key, sizeof(key), NULL, 0, &empty) == FX_OK,
          "encrypt empty");
    FxBytes empty_back = {NULL, 0};
    CHECK(fx1_decrypt(7, key, sizeof(key), empty.ptr, empty.len,
                      &empty_back) == FX_OK,
          "decrypt empty");
    CHECK(empty_back.len == 0, "empty stays empty");
    fx_free(empty_back.ptr, empty_back.len);
    fx_free(empty.ptr, empty.len);

    /* wrap / unwrap with domain separation */
    const uint8_t aad[] = "fx1:ark:v1";
    const uint8_t other_aad[] = "fx1:rootkey:v1";
    FxBytes wrapped = {NULL, 0};
    FxBytes opened = {NULL, 0};
    CHECK(fx_wrap(key, sizeof(key), (const uint8_t*)"record", 6, aad,
                  sizeof(aad) - 1, &wrapped) == FX_OK,
          "fx_wrap");
    CHECK(fx_unwrap(key, sizeof(key), wrapped.ptr, wrapped.len, aad,
                    sizeof(aad) - 1, &opened) == FX_OK,
          "fx_unwrap");
    CHECK(opened.len == 6 && memcmp(opened.ptr, "record", 6) == 0,
          "unwrap bytes");
    FxBytes refused = {NULL, 0};
    CHECK(fx_unwrap(key, sizeof(key), wrapped.ptr, wrapped.len, other_aad,
                    sizeof(other_aad) - 1, &refused) == FX_ERR_UNWRAP,
          "foreign AAD answers FX_ERR_UNWRAP");
    CHECK(strcmp(fx_error_name(FX_ERR_UNWRAP),
                 "FX_ERR_UNWRAP") == 0,
          "name of FX_ERR_UNWRAP");
    fx_free(wrapped.ptr, wrapped.len);
    fx_free(opened.ptr, opened.len);

    /* envelopes: key pair -> seal -> open, plus the seal-side codes */
    FxKeyPair kp = {0, {NULL, 0}, {NULL, 0}};
    CHECK(fx_generate_key_pair(-1, &kp) == FX_OK, "fx_generate_key_pair");
    CHECK(kp.suite == 1, "default suite is X25519");
    FxBytes share_aad = {NULL, 0};
    CHECK(fx_share_envelope_aad(77, "user-9", &share_aad) == FX_OK,
          "fx_share_envelope_aad");
    CHECK(share_aad.len == 8 + 6 + 1, "aad shape u64be || grantee || v1");
    FxBytes env = {NULL, 0};
    FxBytes rec = {NULL, 0};
    CHECK(fx_ecies_seal(kp.public_blob.ptr, kp.public_blob.len,
                        (const uint8_t*)"folder", 6, share_aad.ptr,
                        share_aad.len, &env) == FX_OK,
          "fx_ecies_seal");
    CHECK(fx_ecies_open(kp.pkcs8.ptr, kp.pkcs8.len, env.ptr, env.len,
                        share_aad.ptr, share_aad.len, &rec) == FX_OK,
          "fx_ecies_open");
    CHECK(rec.len == 6 && memcmp(rec.ptr, "folder", 6) == 0,
          "envelope bytes");
    const uint8_t one_byte[1] = {1};
    FxBytes refused_seal = {NULL, 0};
    CHECK(fx_ecies_seal(one_byte, 1, (const uint8_t*)"x", 1, share_aad.ptr,
                        share_aad.len, &refused_seal) ==
              FX_ERR_RECIPIENT_SHORT,
          "one-byte recipient answers FX_ERR_RECIPIENT_SHORT");
    fx_free(share_aad.ptr, share_aad.len);
    fx_free(env.ptr, env.len);
    fx_free(rec.ptr, rec.len);
    fx_keypair_free(&kp);

    if (fails) {
        fprintf(stderr, "%d C smoke check(s) failed\n", fails);
        return 1;
    }
    printf("C smoke: header + staticlib roundtrip through the C ABI\n");
    return 0;
}
