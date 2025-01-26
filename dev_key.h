#ifndef KEY_H
#define KEY_H


#include <cuda_runtime.h>
#include <stdio.h>
#include "modinv64.h"
#include "secp256k1.h"

__host__ inline static void print_key(const rustsecp256k1_v0_10_0_pubkey *pubkey) {
    unsigned char serialized_pubkey[33];
    size_t output_len = 33;
    int res = rustsecp256k1_v0_10_0_ec_pubkey_serialize(serialized_pubkey, &output_len, pubkey, SECP256K1_EC_COMPRESSED);
    if (!res) {
        printf("Failed to serialize public key\n");
        return;
    }
    printf("Serialized public key: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", serialized_pubkey[i]);
    }
    printf("\n");
}

__device__ __host__ inline static void print_fe(const rustsecp256k1_v0_10_0_fe *fe) {
    printf("fe{%lx %lx %lx %lx %lx}\n", fe->n[0], fe->n[1], fe->n[2], fe->n[3], fe->n[4]);
}

__device__ __host__ inline static void print_ge(const rustsecp256k1_v0_10_0_ge *ge) {
    printf("ge: {\n x: ");
    print_fe(&ge->x);
    printf(" y: ");
    print_fe(&ge->y);
    printf("}\n");
}

__device__ static inline void dev_fe_impl_add(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a) {
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
}

__device__ static inline void dev_u128_mul(unsigned __int128 *r, uint64_t a, uint64_t b) {
   *r = (unsigned __int128)a * b;
}

__device__ static inline void dev_u128_accum_mul(unsigned __int128 *r, uint64_t a, uint64_t b) {
   *r += (unsigned __int128)a * b;
}

__device__ static inline uint64_t dev_u128_to_u64(const unsigned __int128 *a) {
   return (uint64_t)(*a);
}

__device__ static inline void dev_u128_rshift(unsigned __int128 *r, unsigned int n) {
   *r >>= n;
}

__device__ static inline void dev_u128_accum_u64(unsigned __int128 *r, uint64_t a) {
   *r += a;
}

__device__ inline static void dev_fe_mul_inner(uint64_t *r, const uint64_t *a, const uint64_t *b) {
    unsigned __int128 c, d;
    uint64_t t3, t4, tx, u0;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    dev_u128_mul(&d, a0, b[3]);
    dev_u128_accum_mul(&d, a1, b[2]);
    dev_u128_accum_mul(&d, a2, b[1]);
    dev_u128_accum_mul(&d, a3, b[0]);
    /* [d 0 0 0] = [p3 0 0 0] */
    dev_u128_mul(&c, a4, b[4]);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    dev_u128_accum_mul(&d, R, dev_u128_to_u64(&c)); dev_u128_rshift(&c, 64);
    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    dev_u128_accum_mul(&d, a0, b[4]);
    dev_u128_accum_mul(&d, a1, b[3]);
    dev_u128_accum_mul(&d, a2, b[2]);
    dev_u128_accum_mul(&d, a3, b[1]);
    dev_u128_accum_mul(&d, a4, b[0]);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    dev_u128_accum_mul(&d, R << 12, dev_u128_to_u64(&c));
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    dev_u128_mul(&c, a0, b[0]);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    dev_u128_accum_mul(&d, a1, b[4]);
    dev_u128_accum_mul(&d, a2, b[3]);
    dev_u128_accum_mul(&d, a3, b[2]);
    dev_u128_accum_mul(&d, a4, b[1]);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    dev_u128_accum_mul(&c, u0, R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    dev_u128_accum_mul(&c, a0, b[1]);
    dev_u128_accum_mul(&c, a1, b[0]);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    dev_u128_accum_mul(&d, a2, b[4]);
    dev_u128_accum_mul(&d, a3, b[3]);
    dev_u128_accum_mul(&d, a4, b[2]);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    dev_u128_accum_mul(&c, dev_u128_to_u64(&d) & M, R); dev_u128_rshift(&d, 52);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    dev_u128_accum_mul(&c, a0, b[2]);
    dev_u128_accum_mul(&c, a1, b[1]);
    dev_u128_accum_mul(&c, a2, b[0]);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    dev_u128_accum_mul(&d, a3, b[4]);
    dev_u128_accum_mul(&d, a4, b[3]);
    /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    dev_u128_accum_mul(&c, R, dev_u128_to_u64(&d)); dev_u128_rshift(&d, 64);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[2] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    dev_u128_accum_mul(&c, R << 12, dev_u128_to_u64(&d));
    dev_u128_accum_u64(&c, t3);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = dev_u128_to_u64(&c) + t4;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

__device__ static inline void dev_fe_impl_mul(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe * b) {
    dev_fe_mul_inner(r->n, a->n, b->n);
}

__device__ static void dev_fe_impl_normalize_weak(rustsecp256k1_v0_10_0_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    // VERIFY_CHECK(t4 >> 49 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
}

__device__ inline static void dev_fe_sqr_inner(uint64_t *r, const uint64_t *a) {
    unsigned __int128 c, d;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t t3, t4, tx, u0;
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    /**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    dev_u128_mul(&d, a0*2, a3);
    dev_u128_accum_mul(&d, a1*2, a2);
    /* [d 0 0 0] = [p3 0 0 0] */
    dev_u128_mul(&c, a4, a4);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    dev_u128_accum_mul(&d, R, dev_u128_to_u64(&c)); dev_u128_rshift(&c, 64);
    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    a4 *= 2;
    dev_u128_accum_mul(&d, a0, a4);
    dev_u128_accum_mul(&d, a1*2, a3);
    dev_u128_accum_mul(&d, a2, a2);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    dev_u128_accum_mul(&d, R << 12, dev_u128_to_u64(&c));
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    dev_u128_mul(&c, a0, a0);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    dev_u128_accum_mul(&d, a1, a4);
    dev_u128_accum_mul(&d, a2*2, a3);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = dev_u128_to_u64(&d) & M; dev_u128_rshift(&d, 52);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    dev_u128_accum_mul(&c, u0, R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    a0 *= 2;
    dev_u128_accum_mul(&c, a0, a1);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    dev_u128_accum_mul(&d, a2, a4);
    dev_u128_accum_mul(&d, a3, a3);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    dev_u128_accum_mul(&c, dev_u128_to_u64(&d) & M, R); dev_u128_rshift(&d, 52);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    dev_u128_accum_mul(&c, a0, a2);
    dev_u128_accum_mul(&c, a1, a1);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    dev_u128_accum_mul(&d, a3, a4);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    dev_u128_accum_mul(&c, R, dev_u128_to_u64(&d)); dev_u128_rshift(&d, 64);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    dev_u128_accum_mul(&c, R << 12, dev_u128_to_u64(&d));
    dev_u128_accum_u64(&c, t3);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = dev_u128_to_u64(&c) & M; dev_u128_rshift(&c, 52);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = dev_u128_to_u64(&c) + t4;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

__device__ inline static void dev_fe_impl_sqr(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a) {
    dev_fe_sqr_inner(r->n, a->n);
}

__device__ inline static void dev_fe_impl_negate_unchecked(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int m) {
    /* Due to the properties above, the left hand in the subtractions below is never less than
     * the right hand. */
    r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
}

__device__ static void dev_fe_to_signed62(rustsecp256k1_v0_10_0_modinv64_signed62 *r, const rustsecp256k1_v0_10_0_fe *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];

    r->v[0] = (a0       | a1 << 52) & M62;
    r->v[1] = (a1 >> 10 | a2 << 42) & M62;
    r->v[2] = (a2 >> 20 | a3 << 32) & M62;
    r->v[3] = (a3 >> 30 | a4 << 22) & M62;
    r->v[4] =  a4 >> 40;
}

__device__ static void dev_fe_from_signed62(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_modinv64_signed62 *a) {
    const uint64_t M52 = UINT64_MAX >> 12;
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    r->n[0] =  a0                   & M52;
    r->n[1] = (a0 >> 52 | a1 << 10) & M52;
    r->n[2] = (a1 >> 42 | a2 << 20) & M52;
    r->n[3] = (a2 >> 32 | a3 << 30) & M52;
    r->n[4] = (a3 >> 22 | a4 << 40);
}

__device__ static inline int dev_ctz64_var_debruijn(uint64_t x) {
    static const uint8_t debruijn[64] = {
        0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
        62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
        63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
        51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
    };
    return debruijn[(uint64_t)((x & -x) * 0x022FDD63CC95386DU) >> 58];
}


typedef struct {
    int64_t u, v, q, r;
} rustsecp256k1_v0_10_0_modinv64_trans2x2;

__device__ static int64_t dev_modinv64_divsteps_62_var(int64_t eta, uint64_t f0, uint64_t g0, rustsecp256k1_v0_10_0_modinv64_trans2x2 *t) {
    /* Transformation matrix; see comments in rustsecp256k1_v0_10_0_modinv64_divsteps_62. */
    uint64_t u = 1, v = 0, q = 0, r = 1;
    uint64_t f = f0, g = g0, m;
    uint32_t w;
    int i = 62, limit, zeros;

    for (;;) {
        /* Use a sentinel bit to count zeros only up to i. */
        zeros = dev_ctz64_var_debruijn(g | (UINT64_MAX << i));// zeros = rustsecp256k1_v0_10_0_ctz64_var(g | (UINT64_MAX << i));
        /* Perform zeros divsteps at once; they all just divide g by two. */
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;
        /* We're done once we've done 62 divsteps. */
        if (i == 0) break;
        /* If eta is negative, negate it and replace f,g with g,-f. */
        if (eta < 0) {
            uint64_t tmp;
            eta = -eta;
            tmp = f; f = g; g = -tmp;
            tmp = u; u = q; q = -tmp;
            tmp = v; v = r; r = -tmp;
            /* Use a formula to cancel out up to 6 bits of g. Also, no more than i can be cancelled
             * out (as we'd be done before that point), and no more than eta+1 can be done as its
             * sign will flip again once that happens. */
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            /* m is a mask for the bottom min(limit, 6) bits. */
            m = (UINT64_MAX >> (64 - limit)) & 63U;
            /* Find what multiple of f must be added to g to cancel its bottom min(limit, 6)
             * bits. */
            w = (f * g * (f * f - 2)) & m;
        } else {
            /* In this branch, use a simpler formula that only lets us cancel up to 4 bits of g, as
             * eta tends to be smaller here. */
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            /* m is a mask for the bottom min(limit, 4) bits. */
            m = (UINT64_MAX >> (64 - limit)) & 15U;
            /* Find what multiple of f must be added to g to cancel its bottom min(limit, 4)
             * bits. */
            w = f + (((f + 1) & 4) << 1);
            w = (-w * g) & m;
        }
        g += f * w;
        q += u * w;
        r += v * w;
    }
    /* Return data in t and return value. */
    t->u = (int64_t)u;
    t->v = (int64_t)v;
    t->q = (int64_t)q;
    t->r = (int64_t)r;

    return eta;
}

__device__ static inline void dev_i128_mul(__int128 *r, int64_t a, int64_t b) {
   *r = (__int128)a * b;
}

__device__ static inline void dev_i128_accum_mul(__int128 *r, int64_t a, int64_t b) {
   __int128 ab = (__int128)a * b;
   *r += ab;
}

__device__ static inline uint64_t dev_i128_to_u64(const __int128 *a) {
   return (uint64_t)*a;
}

__device__ static inline void dev_i128_rshift(__int128 *r, unsigned int n) {
   *r >>= n;
}

__device__ static inline int64_t dev_i128_to_i64(const __int128 *a) {
   return *a;
}

__device__ static void dev_modinv64_update_de_62(rustsecp256k1_v0_10_0_modinv64_signed62 *d, rustsecp256k1_v0_10_0_modinv64_signed62 *e, const rustsecp256k1_v0_10_0_modinv64_trans2x2 *t) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const int64_t d0 = d->v[0], d1 = d->v[1], d2 = d->v[2], d3 = d->v[3], d4 = d->v[4];
    const int64_t e0 = e->v[0], e1 = e->v[1], e2 = e->v[2], e3 = e->v[3], e4 = e->v[4];
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    int64_t md, me, sd, se;
    __int128 cd, ce;

    /* [md,me] start as zero; plus [u,q] if d is negative; plus [v,r] if e is negative. */
    sd = d4 >> 63;
    se = e4 >> 63;
    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);
    /* Begin computing t*[d,e]. */
    dev_i128_mul(&cd, u, d0);
    dev_i128_accum_mul(&cd, v, e0);
    dev_i128_mul(&ce, q, d0);
    dev_i128_accum_mul(&ce, r, e0);
    /* Correct md,me so that t*[d,e]+modulus*[md,me] has 62 zero bottom bits. */
    md -= (0x27C7F6E22DDACACFLL * dev_i128_to_u64(&cd) + md) & M62;
    me -= (0x27C7F6E22DDACACFLL * dev_i128_to_u64(&ce) + me) & M62;
    /* Update the beginning of computation for t*[d,e]+modulus*[md,me] now md,me are known. */
    dev_i128_accum_mul(&cd, -0x1000003D1LL, md);
    dev_i128_accum_mul(&ce, -0x1000003D1LL, me);
    /* Verify that the low 62 bits of the computation are indeed zero, and then throw them away. */
    dev_i128_rshift(&cd, 62);
    dev_i128_rshift(&ce, 62);
    /* Compute limb 1 of t*[d,e]+modulus*[md,me], and store it as output limb 0 (= down shift). */
    dev_i128_accum_mul(&cd, u, d1);
    dev_i128_accum_mul(&cd, v, e1);
    dev_i128_accum_mul(&ce, q, d1);
    dev_i128_accum_mul(&ce, r, e1);
    d->v[0] = dev_i128_to_u64(&cd) & M62; dev_i128_rshift(&cd, 62);
    e->v[0] = dev_i128_to_u64(&ce) & M62; dev_i128_rshift(&ce, 62);
    /* Compute limb 2 of t*[d,e]+modulus*[md,me], and store it as output limb 1. */
    dev_i128_accum_mul(&cd, u, d2);
    dev_i128_accum_mul(&cd, v, e2);
    dev_i128_accum_mul(&ce, q, d2);
    dev_i128_accum_mul(&ce, r, e2);
    d->v[1] = dev_i128_to_u64(&cd) & M62; dev_i128_rshift(&cd, 62);
    e->v[1] = dev_i128_to_u64(&ce) & M62; dev_i128_rshift(&ce, 62);
    /* Compute limb 3 of t*[d,e]+modulus*[md,me], and store it as output limb 2. */
    dev_i128_accum_mul(&cd, u, d3);
    dev_i128_accum_mul(&cd, v, e3);
    dev_i128_accum_mul(&ce, q, d3);
    dev_i128_accum_mul(&ce, r, e3);
    d->v[2] = dev_i128_to_u64(&cd) & M62; dev_i128_rshift(&cd, 62);
    e->v[2] = dev_i128_to_u64(&ce) & M62; dev_i128_rshift(&ce, 62);
    /* Compute limb 4 of t*[d,e]+modulus*[md,me], and store it as output limb 3. */
    dev_i128_accum_mul(&cd, u, d4);
    dev_i128_accum_mul(&cd, v, e4);
    dev_i128_accum_mul(&ce, q, d4);
    dev_i128_accum_mul(&ce, r, e4);
    
    dev_i128_accum_mul(&cd, 256, md);
    dev_i128_accum_mul(&ce, 256, me);
    d->v[3] = dev_i128_to_u64(&cd) & M62; dev_i128_rshift(&cd, 62);
    e->v[3] = dev_i128_to_u64(&ce) & M62; dev_i128_rshift(&ce, 62);
    /* What remains is limb 5 of t*[d,e]+modulus*[md,me]; store it as output limb 4. */
    d->v[4] = dev_i128_to_i64(&cd);
    e->v[4] = dev_i128_to_i64(&ce);
}

__device__ static void dev_modinv64_update_fg_62_var(int len, rustsecp256k1_v0_10_0_modinv64_signed62 *f, rustsecp256k1_v0_10_0_modinv64_signed62 *g, const rustsecp256k1_v0_10_0_modinv64_trans2x2 *t) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    int64_t fi, gi;
    __int128 cf, cg;
    int i;
    /* Start computing t*[f,g]. */
    fi = f->v[0];
    gi = g->v[0];
    dev_i128_mul(&cf, u, fi);
    dev_i128_accum_mul(&cf, v, gi);
    dev_i128_mul(&cg, q, fi);
    dev_i128_accum_mul(&cg, r, gi);
    /* Verify that the bottom 62 bits of the result are zero, and then throw them away. */
    dev_i128_rshift(&cf, 62);
    dev_i128_rshift(&cg, 62);
    /* Now iteratively compute limb i=1..len of t*[f,g], and store them in output limb i-1 (shifting
     * down by 62 bits). */
    for (i = 1; i < len; ++i) {
        fi = f->v[i];
        gi = g->v[i];
        dev_i128_accum_mul(&cf, u, fi);
        dev_i128_accum_mul(&cf, v, gi);
        dev_i128_accum_mul(&cg, q, fi);
        dev_i128_accum_mul(&cg, r, gi);
        f->v[i - 1] = dev_i128_to_u64(&cf) & M62; dev_i128_rshift(&cf, 62);
        g->v[i - 1] = dev_i128_to_u64(&cg) & M62; dev_i128_rshift(&cg, 62);
    }
    /* What remains is limb (len) of t*[f,g]; store it as output limb (len-1). */
    f->v[len - 1] = dev_i128_to_i64(&cf);
    g->v[len - 1] = dev_i128_to_i64(&cg);
}

__device__ static void dev_modinv64_normalize_62(rustsecp256k1_v0_10_0_modinv64_signed62 *r, int64_t sign) {
    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    int64_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4];
    volatile int64_t cond_add, cond_negate;

    /* In a first step, add the modulus if the input is negative, and then negate if requested.
     * This brings r from range (-2*modulus,modulus) to range (-modulus,modulus). As all input
     * limbs are in range (-2^62,2^62), this cannot overflow an int64_t. Note that the right
     * shifts below are signed sign-extending shifts (see assumptions.h for tests that that is
     * indeed the behavior of the right shift operator). */
    cond_add = r4 >> 63;
    // {{-0x1000003D1LL, 0, 0, 0, 256}},
    r0 += -0x1000003D1LL & cond_add;
    // r1 += modinfo->modulus.v[1] & cond_add;
    // r2 += modinfo->modulus.v[2] & cond_add;
    // r3 += modinfo->modulus.v[3] & cond_add;
    r4 += 256 & cond_add;
    cond_negate = sign >> 63;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    /* Propagate the top bits, to bring limbs back to range (-2^62,2^62). */
    r1 += r0 >> 62; r0 &= M62;
    r2 += r1 >> 62; r1 &= M62;
    r3 += r2 >> 62; r2 &= M62;
    r4 += r3 >> 62; r3 &= M62;

    /* In a second step add the modulus again if the result is still negative, bringing
     * r to range [0,modulus). */
    cond_add = r4 >> 63;
    // {{-0x1000003D1LL, 0, 0, 0, 256}},
    r0 += -0x1000003D1LL & cond_add;
    // r1 += modinfo->modulus.v[1] & cond_add;
    // r2 += modinfo->modulus.v[2] & cond_add;
    // r3 += modinfo->modulus.v[3] & cond_add;
    r4 += 256 & cond_add;
    /* And propagate again. */
    r1 += r0 >> 62; r0 &= M62;
    r2 += r1 >> 62; r1 &= M62;
    r3 += r2 >> 62; r2 &= M62;
    r4 += r3 >> 62; r3 &= M62;

    r->v[0] = r0;
    r->v[1] = r1;
    r->v[2] = r2;
    r->v[3] = r3;
    r->v[4] = r4;
}

__device__ static void dev_modinv64_var(rustsecp256k1_v0_10_0_modinv64_signed62 *x) {
    /* Start with d=0, e=1, f=modulus, g=x, eta=-1. */
    rustsecp256k1_v0_10_0_modinv64_signed62 d = {{0, 0, 0, 0, 0}};
    rustsecp256k1_v0_10_0_modinv64_signed62 e = {{1, 0, 0, 0, 0}};
    rustsecp256k1_v0_10_0_modinv64_signed62 f = {{-0x1000003D1LL, 0, 0, 0, 256}};
    rustsecp256k1_v0_10_0_modinv64_signed62 g = *x;
    int j, len = 5;
    int64_t eta = -1; /* eta = -delta; delta is initially 1 */
    int64_t cond, fn, gn;

    /* Do iterations of 62 divsteps each until g=0. */
    while (1) {
        /* Compute transition matrix and new eta after 62 divsteps. */
        rustsecp256k1_v0_10_0_modinv64_trans2x2 t;
        eta = dev_modinv64_divsteps_62_var(eta, f.v[0], g.v[0], &t);
        /* Update d,e using that transition matrix. */
        dev_modinv64_update_de_62(&d, &e, &t);
        /* Update f,g using that transition matrix. */

        dev_modinv64_update_fg_62_var(len, &f, &g, &t);
        /* If the bottom limb of g is zero, there is a chance that g=0. */
        if (g.v[0] == 0) {
            cond = 0;
            /* Check if the other limbs are also 0. */
            for (j = 1; j < len; ++j) {
                cond |= g.v[j];
            }
            /* If so, we're done. */
            if (cond == 0) break;
        }

        /* Determine if len>1 and limb (len-1) of both f and g is 0 or -1. */
        fn = f.v[len - 1];
        gn = g.v[len - 1];
        cond = ((int64_t)len - 2) >> 63;
        cond |= fn ^ (fn >> 63);
        cond |= gn ^ (gn >> 63);
        /* If so, reduce length, propagating the sign of f and g's top limb into the one below. */
        if (cond == 0) {
            f.v[len - 2] |= (uint64_t)fn << 62;
            g.v[len - 2] |= (uint64_t)gn << 62;
            --len;
        }
    }

    /* Optionally negate d, normalize to [0,modulus), and return it. */
    dev_modinv64_normalize_62(&d, f.v[len - 1]);
    *x = d;
}

// __device__ static const rustsecp256k1_v0_10_0_modinv64_modinfo copy_const_modinfo_fe = {
//     {{-0x1000003D1LL, 0, 0, 0, 256}},
//     0x27C7F6E22DDACACFLL
// };

__device__ static void dev_fe_impl_inv_var(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *x) {
    rustsecp256k1_v0_10_0_fe tmp = *x;
    rustsecp256k1_v0_10_0_modinv64_signed62 s;

    dev_fe_impl_normalize_weak(&tmp); // rustsecp256k1_v0_10_0_fe_normalize_var(&tmp);
    dev_fe_to_signed62(&s, &tmp);
    dev_modinv64_var(&s);
    dev_fe_from_signed62(r, &s);
}

// Increment a point by using the official point add operation, using precomputed value for negated coordinates of the generator point.
__device__ static void dev_inc(rustsecp256k1_v0_10_0_ge *key) {
    static const rustsecp256k1_v0_10_0_fe ngx ={{0x3d7ea0e907d924, 0x324d231d726a5d, 0x3178f4f8fd6400, 0x34453aa5f9d6a0, 0x3864199810620}}, ngy = {{0x382f6c04ef1c04, 0x3b7597aabe6638, 0x31eef75702e848, 0x33b9aa25b0403c, 0x3b7c52588d959}}; // TODO precompute
    rustsecp256k1_v0_10_0_fe y1mngy = key->y, x1mngx = key->x, x2, y2, temp, lambda;
    // λ = (y1 - gy) / (x1 - gx)
    dev_fe_impl_add(&y1mngy, &ngy);                         // ngy = y1 - gy (3)
    dev_fe_impl_add(&x1mngx, &ngx);                         // ngx = x1 - gx (3)
    dev_fe_impl_inv_var(&x1mngx, &x1mngx);                  // ngx = 1 / (x1 - gx) (3)
    dev_fe_impl_mul(&lambda, &y1mngy, &x1mngx);             // lambda = (y1 - gy) / (x1 - gx) (9)
    dev_fe_impl_normalize_weak(&lambda);                    // lambda = λ (1)

    // // x2 = λ^2 - x1 - gx
    dev_fe_impl_sqr(&x2, &lambda);                          // x2 = λ^2 (1)
    dev_fe_impl_negate_unchecked(&temp, &key->x, 1);        // temp = -x1 (2)
    dev_fe_impl_add(&x2, &temp);                            // x2 = λ^2 - x1 (3)
    dev_fe_impl_add(&x2, &ngx);                             // x2 = λ^2 - x1 - gx (5)
    dev_fe_impl_normalize_weak(&x2);

    // // y2 = λ(x1 - x2) - y1

    dev_fe_impl_negate_unchecked(&temp, &x2, 1);            // temp = -x2 (6)
    dev_fe_impl_add(&temp, &key->x);                        // temp = x1 - x2 (7)
    dev_fe_impl_mul(&y2, &lambda, &temp);                   // y2 = λ(x1 - x2) (7)
    dev_fe_impl_negate_unchecked(&temp, &key->y, 1);        // temp = -y1 (2)
    dev_fe_impl_add(&y2, &temp);                            // y2 = λ(x1 - x2) - y1 (9)

    key->x = x2;
    key->y = y2;
}

__device__ static void dev_fe_impl_get_b32(unsigned char *r, const rustsecp256k1_v0_10_0_fe *a) {
    r[0] = (a->n[4] >> 40) & 0xFF;
    r[1] = (a->n[4] >> 32) & 0xFF;
    r[2] = (a->n[4] >> 24) & 0xFF;
    r[3] = (a->n[4] >> 16) & 0xFF;
    r[4] = (a->n[4] >> 8) & 0xFF;
    r[5] = a->n[4] & 0xFF;
    r[6] = (a->n[3] >> 44) & 0xFF;
    r[7] = (a->n[3] >> 36) & 0xFF;
    r[8] = (a->n[3] >> 28) & 0xFF;
    r[9] = (a->n[3] >> 20) & 0xFF;
    r[10] = (a->n[3] >> 12) & 0xFF;
    r[11] = (a->n[3] >> 4) & 0xFF;
    r[12] = ((a->n[2] >> 48) & 0xF) | ((a->n[3] & 0xF) << 4);
    r[13] = (a->n[2] >> 40) & 0xFF;
    r[14] = (a->n[2] >> 32) & 0xFF;
    r[15] = (a->n[2] >> 24) & 0xFF;
    r[16] = (a->n[2] >> 16) & 0xFF;
    r[17] = (a->n[2] >> 8) & 0xFF;
    r[18] = a->n[2] & 0xFF;
    r[19] = (a->n[1] >> 44) & 0xFF;
    r[20] = (a->n[1] >> 36) & 0xFF;
    r[21] = (a->n[1] >> 28) & 0xFF;
    r[22] = (a->n[1] >> 20) & 0xFF;
    r[23] = (a->n[1] >> 12) & 0xFF;
    r[24] = (a->n[1] >> 4) & 0xFF;
    r[25] = ((a->n[0] >> 48) & 0xF) | ((a->n[1] & 0xF) << 4);
    r[26] = (a->n[0] >> 40) & 0xFF;
    r[27] = (a->n[0] >> 32) & 0xFF;
    r[28] = (a->n[0] >> 24) & 0xFF;
    r[29] = (a->n[0] >> 16) & 0xFF;
    r[30] = (a->n[0] >> 8) & 0xFF;
    r[31] = a->n[0] & 0xFF;
}

__device__ inline static int dev_fe_impl_is_odd(const rustsecp256k1_v0_10_0_fe *a) {
    return a->n[0] & 1;
}

__device__ static int dev_eckey_pubkey_serialize(rustsecp256k1_v0_10_0_ge *elem, unsigned char *pub) {
    dev_fe_impl_normalize_weak(&elem->x);
    dev_fe_impl_normalize_weak(&elem->y);
    dev_fe_impl_get_b32(&pub[1], &elem->x);
    pub[0] = dev_fe_impl_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    return 1;
}


#endif // KEY_H