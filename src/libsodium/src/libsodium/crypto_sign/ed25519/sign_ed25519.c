
#include <string.h>

#include "crypto_hash_sha512.h"
#include "crypto_generichash_blake2b.h"
#include "crypto_sign_ed25519.h"
#include "crypto_verify_32.h"
#include "ref10/sign_ed25519_ref10.h"
#include "crypto_scalarmult_curve25519.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

size_t
crypto_sign_ed25519ph_statebytes(void)
{
    return sizeof(crypto_sign_ed25519ph_state);
}

size_t
crypto_sign_ed25519_bytes(void)
{
    return crypto_sign_ed25519_BYTES;
}

size_t
crypto_sign_ed25519_seedbytes(void)
{
    return crypto_sign_ed25519_SEEDBYTES;
}

size_t
crypto_sign_ed25519_publickeybytes(void)
{
    return crypto_sign_ed25519_PUBLICKEYBYTES;
}

size_t
crypto_sign_ed25519_secretkeybytes(void)
{
    return crypto_sign_ed25519_SECRETKEYBYTES;
}

size_t
crypto_sign_ed25519_messagebytes_max(void)
{
    return crypto_sign_ed25519_MESSAGEBYTES_MAX;
}

int
crypto_sign_ed25519_sk_to_seed(unsigned char *seed, const unsigned char *sk)
{
    memmove(seed, sk, crypto_sign_ed25519_SEEDBYTES);

    return 0;
}

int
crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
    memmove(pk, sk + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    return 0;
}

int
crypto_sign_ed25519ph_init(crypto_sign_ed25519ph_state *state)
{
    crypto_hash_sha512_init(&state->hs);
    return 0;
}

int
crypto_sign_ed25519ph_update(crypto_sign_ed25519ph_state *state,
                             const unsigned char *m, unsigned long long mlen)
{
    return crypto_hash_sha512_update(&state->hs, m, mlen);
}

int
crypto_sign_ed25519ph_final_create(crypto_sign_ed25519ph_state *state,
                                   unsigned char               *sig,
                                   unsigned long long          *siglen_p,
                                   const unsigned char         *sk)
{
    unsigned char ph[crypto_hash_sha512_BYTES];

    crypto_hash_sha512_final(&state->hs, ph);

    return _crypto_sign_ed25519_detached(sig, siglen_p, ph, sizeof ph, sk, 1);
}

int
crypto_sign_ed25519ph_final_verify(crypto_sign_ed25519ph_state *state,
                                   unsigned char               *sig,
                                   const unsigned char         *pk)
{
    unsigned char ph[crypto_hash_sha512_BYTES];

    crypto_hash_sha512_final(&state->hs, ph);

    return _crypto_sign_ed25519_verify_detached(sig, ph, sizeof ph, pk, 1);
}

int
crypto_sign_ed25519_blake2b_seed_keypair(unsigned char *pk, unsigned char *sk,
                                 const unsigned char *seed)
{
    ge25519_p3 A;

#ifdef ED25519_NONDETERMINISTIC
    memmove(sk, seed, 32);
#else
    crypto_generichash_blake2b(sk, 64, seed, 32, NULL, 0);
#endif
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    ge25519_scalarmult_base(&A, sk);
    ge25519_p3_tobytes(pk, &A);

    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);

    return 0;
}

void
_crypto_sign_ed25519_blake2b_ref10_hinit(crypto_generichash_blake2b_state *hs, int prehashed)
{
    static const unsigned char DOM2PREFIX[32 + 2] = {
        'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
        'n', 'o', ' ',
        'E', 'd', '2', '5', '5', '1', '9', ' ',
        'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
    };

    crypto_generichash_blake2b_init(hs, NULL, 0, 64);
    if (prehashed) {
        crypto_generichash_blake2b(hs, 64, DOM2PREFIX, sizeof DOM2PREFIX, NULL, 0);
    }
}

static inline void
_crypto_sign_ed25519_clamp(unsigned char k[32])
{
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

#ifdef ED25519_NONDETERMINISTIC
/* r = hash(B || empty_labelset || Z || pad1 || k || pad2 || empty_labelset || K || extra || M) (mod q) */
static void
_crypto_sign_ed25519_blake2b_synthetic_r_hv(crypto_generichash_blake2b_state *hs,
                                    unsigned char Z[32],
                                    const unsigned char sk[64])
{
    static const unsigned char B[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };
    static const unsigned char zeros[128] = { 0x00 };
    static const unsigned char empty_labelset[3] = { 0x02, 0x00, 0x00 };

    crypto_generichash_blake2b_update(hs, B, 32);
    crypto_generichash_blake2b_update(hs, empty_labelset, 3);
    randombytes_buf(Z, 32);
    crypto_generichash_blake2b_update(hs, Z, 32);
    crypto_generichash_blake2b_update(hs, zeros, 128 - (32 + 3 + 32) % 128);
    crypto_generichash_blake2b_update(hs, sk, 32);
    crypto_generichash_blake2b_update(hs, zeros, 128 - 32 % 128);
    crypto_generichash_blake2b_update(hs, empty_labelset, 3);
    crypto_generichash_blake2b_update(hs, sk + 32, 32);
    /* empty extra */
}
#endif

int
crypto_sign_ed25519_blake2b_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[32];
    int           ret;

    randombytes_buf(seed, sizeof seed);
    ret = crypto_sign_ed25519_blake2b_seed_keypair(pk, sk, seed);
    sodium_memzero(seed, sizeof seed);

    return ret;
}

int
_crypto_sign_ed25519_blake2b_detached(unsigned char *sig, unsigned long long *siglen_p,
                              const unsigned char *m, unsigned long long mlen,
                              const unsigned char *sk, int prehashed)
{
    crypto_generichash_blake2b_state hs;
    unsigned char            az[64];
    unsigned char            nonce[64];
    unsigned char            hram[64];
    ge25519_p3               R;

    _crypto_sign_ed25519_blake2b_ref10_hinit(&hs, prehashed);

#ifdef ED25519_NONDETERMINISTIC
    memcpy(az, sk, 32);
    _crypto_sign_ed25519_blake2b_synthetic_r_hv(&hs, nonce, az);
#else
    crypto_generichash_blake2b(az, 64, sk, 32, NULL, 0);
    crypto_generichash_blake2b_update(&hs, az + 32, 32);
#endif

    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, nonce, sizeof nonce);

    memmove(sig + 32, sk + 32, 32);

    sc25519_reduce(nonce);
    ge25519_scalarmult_base(&R, nonce);
    ge25519_p3_tobytes(sig, &R);

    _crypto_sign_ed25519_blake2b_ref10_hinit(&hs, prehashed);
    crypto_generichash_blake2b_update(&hs, sig, 64);
    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, hram, sizeof hram);

    sc25519_reduce(hram);
    _crypto_sign_ed25519_clamp(az);
    sc25519_muladd(sig + 32, hram, az, nonce);

    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    if (siglen_p != NULL) {
        *siglen_p = 64U;
    }
    return 0;
}

int
crypto_sign_ed25519_blake2b_detached(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char *sk)
{
    return _crypto_sign_ed25519_blake2b_detached(sig, siglen_p, m, mlen, sk, 0);
}

int
crypto_sign_ed25519_blake2b(unsigned char *sm, unsigned long long *smlen_p,
                    const unsigned char *m, unsigned long long mlen,
                    const unsigned char *sk)
{
    unsigned long long siglen;

    memmove(sm + crypto_sign_ed25519_BYTES, m, mlen);
    /* LCOV_EXCL_START */
    if (crypto_sign_ed25519_blake2b_detached(
            sm, &siglen, sm + crypto_sign_ed25519_BYTES, mlen, sk) != 0 ||
        siglen != crypto_sign_ed25519_BYTES) {
        if (smlen_p != NULL) {
            *smlen_p = 0;
        }
        memset(sm, 0, mlen + crypto_sign_ed25519_BYTES);
        return -1;
    }
    /* LCOV_EXCL_STOP */

    if (smlen_p != NULL) {
        *smlen_p = mlen + siglen;
    }
    return 0;
}


int
_crypto_sign_ed25519_blake2b_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    crypto_generichash_blake2b_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    ge25519_p3               A;
    ge25519_p2               R;

#ifndef ED25519_COMPAT
    if (sc25519_is_canonical(sig + 32) == 0 ||
        ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (ge25519_is_canonical(pk) == 0) {
        return -1;
    }
#else
    if (sig[63] & 224) {
        return -1;
    }
#endif
    if (ge25519_has_small_order(pk) != 0 ||
        ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }
    _crypto_sign_ed25519_blake2b_ref10_hinit(&hs, prehashed);
    crypto_generichash_blake2b_update(&hs, sig, 32);
    crypto_generichash_blake2b_update(&hs, pk, 32);
    crypto_generichash_blake2b_update(&hs, m, mlen);
    crypto_generichash_blake2b_final(&hs, h, sizeof h);
    sc25519_reduce(h);

    ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge25519_tobytes(rcheck, &R);

    return crypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           sodium_memcmp(sig, rcheck, 32);
}

int
crypto_sign_ed25519_blake2b_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long   mlen,
                                    const unsigned char *pk)
{
    return _crypto_sign_ed25519_blake2b_verify_detached(sig, m, mlen, pk, 0);
}

int
crypto_sign_ed25519_blake2b_open(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *sm, unsigned long long smlen,
                         const unsigned char *pk)
{
    unsigned long long mlen;

    if (smlen < 64 || smlen - 64 > crypto_sign_ed25519_MESSAGEBYTES_MAX) {
        goto badsig;
    }
    mlen = smlen - 64;
    if (crypto_sign_ed25519_blake2b_verify_detached(sm, sm + 64, mlen, pk) != 0) {
        memset(m, 0, mlen);
        goto badsig;
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    memmove(m, sm + 64, mlen);

    return 0;

badsig:
    if (mlen_p != NULL) {
        *mlen_p = 0;
    }
    return -1;
}