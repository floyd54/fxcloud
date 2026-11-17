/*
 * fxcffi.h - C ABI over the fxcloud client crypto core (ENCRYPTION.md 5,
 * phase 5 slice 3). Kotlin reaches these functions through JNI, Swift
 * through a bridging header; every golden vector runs through them as a
 * third reader (crates/fxcffi/tests/ffi_vectors.rs), and c/smoke.c proves
 * this header itself compiles and links against the built static library.
 *
 * Ownership contract (applies to every function below):
 *   - Input pointers may be NULL only together with a length of 0; input
 *     buffers are read, never freed, never retained past the call.
 *   - Output buffers are allocated by the library and MUST be released
 *     with fx_free() / fx_session_free() / fx_rewrapped_free() /
 *     fx_keypair_free() - never with the C library's free(): they come
 *     from Rust's allocator.
 *   - Return codes are stable: append codes, never renumber. 0 is success,
 *     negative values are failures. fx_error_name() maps a code to its
 *     static name for logs.
 *   - Panics never cross the boundary; they surface as FX_ERR_PANIC.
 *
 * All byte order is native (the format itself uses big-endian fields,
 * encoded by the library). Strings are NUL-terminated UTF-8.
 */
#ifndef Fxcffi_h
#define Fxcffi_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- stable error codes --------------------------------------------- */

#define FX_OK 0
#define FX_ERR_ARG -1          /* NULL/length/UTF-8 problem in the call itself */
#define FX_ERR_PANIC -2        /* a panic was caught at the boundary */

/* fxcrypto::FormatError, one per variant */
#define FX_ERR_FORMAT_TOO_SHORT -10 /* "file is too short to be an FXE1 container" */
#define FX_ERR_FORMAT_MAGIC -11     /* "not an FXE1 container (bad magic)" */
#define FX_ERR_FORMAT_VERSION -12   /* "unsupported fxcloud container version N" */
#define FX_ERR_FORMAT_SUITE -13     /* "unsupported cipher suite N" */
#define FX_ERR_FORMAT_CHUNK -14     /* "implausible chunk size in container header: N" */

/* fxcrypto::Error, one per variant */
#define FX_ERR_MALFORMED_TAIL -15   /* "malformed FXE1 container (truncated final chunk)" */
#define FX_ERR_KEY_LENGTH -20       /* "expected a 256-bit file key" */
#define FX_ERR_AEAD -21             /* the AEAD primitive refused */
#define FX_ERR_CHUNK -22            /* "decryption failed for chunk N - ..." */
#define FX_ERR_KDF -30              /* "argon2id key derivation failed ..." */
#define FX_ERR_HKDF -31             /* "hkdf expansion rejected the output length" */
#define FX_ERR_TOO_SHORT -32        /* "wrapped value is too short to be a key record" */
#define FX_ERR_UNWRAP -33           /* "could not unwrap this key - wrong passphrase, ..." */
#define FX_ERR_PUBLIC_BLOB -34      /* "public key is too short" */
#define FX_ERR_UNKNOWN_SUITE -35    /* "unknown key suite N" */
#define FX_ERR_RECIPIENT_SHORT -36  /* "recipient public key is too short" */
#define FX_ERR_PKCS8 -37            /* private key parses as neither curve */

/* ---- types ----------------------------------------------------------- */

/* A library-allocated byte buffer (outputs) or a borrowed one (fields of
 * FxAccountKeys, which the caller fills and the library only reads). */
typedef struct FxBytes {
    uint8_t* ptr; /* NULL iff len == 0 */
    size_t len;
} FxBytes;

/* A stored account row (ENCRYPTION.md 5.4), filled by the caller.
 * kdf_m/kdf_t/kdf_p of 0 mean "floor", exactly like the JS `|| FLOOR`. */
typedef struct FxAccountKeys {
    FxBytes kdf_salt;
    FxBytes wrapped_ark;
    FxBytes wrapped_root_key;
    FxBytes private_key_wrapped;
    FxBytes public_key;
    FxBytes wrapped_ark_recovery;
    uint32_t kdf_m;
    uint32_t kdf_t;
    uint32_t kdf_p;
} FxAccountKeys;

/* The opened session (DECISION 7): material, not key objects - importing
 * a CryptoKey is a browser concern, bytes are the contract. */
typedef struct FxSession {
    FxBytes ark;
    FxBytes root_key;
    FxBytes private_key_pkcs8;
    FxBytes public_blob;
    uint8_t suite; /* SUITE_X25519 (1) or SUITE_P256 (2) */
} FxSession;

/* Result of a passphrase change (5.7): O(1), only the ARK wrap moves. */
typedef struct FxRewrapped {
    FxBytes wrapped_ark;
    FxBytes kdf_salt;
    uint32_t kdf_m;
    uint32_t kdf_t;
    uint32_t kdf_p;
} FxRewrapped;

/* A fresh key pair (5.5): published form is suite || raw point. */
typedef struct FxKeyPair {
    uint8_t suite; /* SUITE_X25519 (1) or SUITE_P256 (2) */
    FxBytes public_blob;
    FxBytes pkcs8;
} FxKeyPair;

/* ---- memory and errors ---------------------------------------------- */

/* Release any FxBytes this library returned (NULL/0 is a no-op). The len
 * must be the one that came with the buffer. */
void fx_free(uint8_t* ptr, size_t len);

/* Static name of a code, e.g. "FX_ERR_UNWRAP"; never NULL. */
const char* fx_error_name(int32_t code);

/* ---- container (5.3) -------------------------------------------------- */

/* Encrypt plain into an FXE1 container (fresh nonce base per call). */
int32_t fx1_encrypt(uint64_t file_id,
                    const uint8_t* key, size_t key_len,
                    const uint8_t* plain, size_t plain_len,
                    FxBytes* out);

/* Decrypt an FXE1 container; wrong key/tampering/move = FX_ERR_CHUNK. */
int32_t fx1_decrypt(uint64_t file_id,
                    const uint8_t* key, size_t key_len,
                    const uint8_t* container, size_t container_len,
                    FxBytes* out);

/* ---- KDF and key records (5.1 / 5.4) --------------------------------- */

/* Argon2id(passphrase, salt) -> 32-byte KEK with stored params (0 = floor). */
int32_t fx_derive_kek(const char* passphrase,
                      const uint8_t* salt, size_t salt_len,
                      uint32_t kdf_m, uint32_t kdf_t, uint32_t kdf_p,
                      FxBytes* out);

/* HKDF-SHA-256 subkey derivation. */
int32_t fx_hkdf(const uint8_t* ikm, size_t ikm_len,
                const uint8_t* salt, size_t salt_len,
                const uint8_t* info, size_t info_len,
                uint32_t out_len, FxBytes* out);

/* AES-256-GCM wrap: nonce12 || ct || tag under a domain-separated AAD. */
int32_t fx_wrap(const uint8_t* key, size_t key_len,
                const uint8_t* value, size_t value_len,
                const uint8_t* aad, size_t aad_len,
                FxBytes* out);

/* Reverse of fx_wrap; every failure is FX_ERR_UNWRAP except a blob that
 * is not even long enough (FX_ERR_TOO_SHORT). */
int32_t fx_unwrap(const uint8_t* key, size_t key_len,
                  const uint8_t* blob, size_t blob_len,
                  const uint8_t* aad, size_t aad_len,
                  FxBytes* out);

/* AAD for a parent-wrapped child key: u64be(child_id) || version. */
int32_t fx_child_key_aad(uint64_t child_id, FxBytes* out);

int32_t fx_wrap_child_key(const uint8_t* parent, size_t parent_len,
                          uint64_t child_id,
                          const uint8_t* child, size_t child_len,
                          FxBytes* out);

int32_t fx_unwrap_child_key(const uint8_t* parent, size_t parent_len,
                            uint64_t child_id,
                            const uint8_t* wrapped, size_t wrapped_len,
                            FxBytes* out);

/* Display fingerprint (DECISION 6):32 lowercase hex chars. */
int32_t fx_fingerprint(const uint8_t* public_blob, size_t public_blob_len,
                       FxBytes* out);

/* ---- account access (5.7) -------------------------------------------- */

/* Open a session from a known ARK. */
int32_t fx_session_from_ark(const FxAccountKeys* keys,
                            const uint8_t* ark, size_t ark_len,
                            FxSession* out);

/* Open a stored account with the storage passphrase. */
int32_t fx_unlock_account(const FxAccountKeys* keys,
                          const char* passphrase,
                          FxSession* out);

/* Open a stored account with the recovery key (full session,5.7). */
int32_t fx_open_with_recovery(const FxAccountKeys* keys,
                              const uint8_t* recovery, size_t recovery_len,
                              FxSession* out);

/* Re-wrap the ARK under a new passphrase: fresh salt, floor params. */
int32_t fx_rewrap_account(const uint8_t* ark, size_t ark_len,
                          const char* new_passphrase,
                          FxRewrapped* out);

/* Release a session / rewrap result (NULL is a no-op; zeroes the struct
 * so a double free is harmless). */
void fx_session_free(FxSession* session);
void fx_rewrapped_free(FxRewrapped* rewrapped);

/* ---- share envelopes (5.5) ------------------------------------------- */

/* AAD binding one envelope to its share:
 * u64be(source_id) || utf8(grantee) || version. */
int32_t fx_share_envelope_aad(uint64_t source_id, const char* grantee,
                              FxBytes* out);

/* Fresh key pair: preferred_suite of2 requests P-256, anything else gets
 * X25519 (the JS generateKeyPair else-branch semantics). */
int32_t fx_generate_key_pair(int32_t preferred_suite, FxKeyPair* out);

/* Seal a key record: eph.publicBlob || nonce12 || ct||tag. */
int32_t fx_ecies_seal(const uint8_t* recipient_public, size_t recipient_public_len,
                      const uint8_t* plain, size_t plain_len,
                      const uint8_t* aad, size_t aad_len,
                      FxBytes* out);

/* Open a sealed envelope; wrong recipient, tampering and a foreign AAD
 * all answer with FX_ERR_UNWRAP (5.5: one message on purpose). */
int32_t fx_ecies_open(const uint8_t* pkcs8, size_t pkcs8_len,
                      const uint8_t* envelope, size_t envelope_len,
                      const uint8_t* aad, size_t aad_len,
                      FxBytes* out);

void fx_keypair_free(FxKeyPair* keypair);

#ifdef __cplusplus
}
#endif

#endif /* Fxcffi_h */
