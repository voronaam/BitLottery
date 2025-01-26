/******************************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra, Jonas Nick  *
 * Distributed under the MIT software license, see the accompanying           *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.       *
 ******************************************************************************/

#ifndef SECP256K1_ECMULT_IMPL_H
#define SECP256K1_ECMULT_IMPL_H

#include <string.h>
#include <stdint.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "util.h"

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#include <stdio.h>
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
/* We need to lower these values for exhaustive tests because
 * the tables cannot have infinities in them (this breaks the
 * affine-isomorphism stuff which tracks z-ratios) */
#  if EXHAUSTIVE_TEST_ORDER > 128
#    define WINDOW_A 5
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define WINDOW_A 4
#  else
#    define WINDOW_A 2
#  endif
#else
/* optimal for 128-bit and 256-bit exponents. */
#  define WINDOW_A 5
/** Larger values for ECMULT_WINDOW_SIZE result in possibly better
 *  performance at the cost of an exponentially larger precomputed
 *  table. The exact table size is
 *      (1 << (WINDOW_G - 2)) * sizeof(rustsecp256k1_v0_10_0_ge_storage)  bytes,
 *  where sizeof(rustsecp256k1_v0_10_0_ge_storage) is typically 64 bytes but can
 *  be larger due to platform-specific padding and alignment.
 *  Two tables of this size are used (due to the endomorphism
 *  optimization).
 */
#endif

#define WNAF_BITS 128
#define WNAF_SIZE_BITS(bits, w) (((bits) + (w) - 1) / (w))
#define WNAF_SIZE(w) WNAF_SIZE_BITS(WNAF_BITS, w)

/* The number of objects allocated on the scratch space for ecmult_multi algorithms */
#define PIPPENGER_SCRATCH_OBJECTS 6
#define STRAUSS_SCRATCH_OBJECTS 5

#define PIPPENGER_MAX_BUCKET_WINDOW 12

/* Minimum number of points for which pippenger_wnaf is faster than strauss wnaf */
#define ECMULT_PIPPENGER_THRESHOLD 88

#define ECMULT_MAX_POINTS_PER_BATCH 5000000

/** Fill a table 'pre_a' with precomputed odd multiples of a.
 *  pre_a will contain [1*a,3*a,...,(2*n-1)*a], so it needs space for n group elements.
 *  zr needs space for n field elements.
 *
 *  Although pre_a is an array of _ge rather than _gej, it actually represents elements
 *  in Jacobian coordinates with their z coordinates omitted. The omitted z-coordinates
 *  can be recovered using z and zr. Using the notation z(b) to represent the omitted
 *  z coordinate of b:
 *  - z(pre_a[n-1]) = 'z'
 *  - z(pre_a[i-1]) = z(pre_a[i]) / zr[i] for n > i > 0
 *
 *  Lastly the zr[0] value, which isn't used above, is set so that:
 *  - a.z = z(pre_a[0]) / zr[0]
 */
static void rustsecp256k1_v0_10_0_ecmult_odd_multiples_table(int n, rustsecp256k1_v0_10_0_ge *pre_a, rustsecp256k1_v0_10_0_fe *zr, rustsecp256k1_v0_10_0_fe *z, const rustsecp256k1_v0_10_0_gej *a) {
    rustsecp256k1_v0_10_0_gej d, ai;
    rustsecp256k1_v0_10_0_ge d_ge;
    int i;

    VERIFY_CHECK(!a->infinity);

    rustsecp256k1_v0_10_0_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions using an isomorphic curve Y^2 = X^3 + 7*C^6 where C := d.z.
     * The isomorphism, phi, maps a secp256k1 point (x, y) to the point (x*C^2, y*C^3) on the other curve.
     * In Jacobian coordinates phi maps (x, y, z) to (x*C^2, y*C^3, z) or, equivalently to (x, y, z/C).
     *
     *     phi(x, y, z) = (x*C^2, y*C^3, z) = (x, y, z/C)
     *   d_ge := phi(d) = (d.x, d.y, 1)
     *     ai := phi(a) = (a.x*C^2, a.y*C^3, a.z)
     *
     * The group addition functions work correctly on these isomorphic curves.
     * In particular phi(d) is easy to represent in affine coordinates under this isomorphism.
     * This lets us use the faster rustsecp256k1_v0_10_0_gej_add_ge_var group addition function that we wouldn't be able to use otherwise.
     */
    rustsecp256k1_v0_10_0_ge_set_xy(&d_ge, &d.x, &d.y);
    rustsecp256k1_v0_10_0_ge_set_gej_zinv(&pre_a[0], a, &d.z);
    rustsecp256k1_v0_10_0_gej_set_ge(&ai, &pre_a[0]);
    ai.z = a->z;

    /* pre_a[0] is the point (a.x*C^2, a.y*C^3, a.z*C) which is equivalent to a.
     * Set zr[0] to C, which is the ratio between the omitted z(pre_a[0]) value and a.z.
     */
    zr[0] = d.z;

    for (i = 1; i < n; i++) {
        rustsecp256k1_v0_10_0_gej_add_ge_var(&ai, &ai, &d_ge, &zr[i]);
        rustsecp256k1_v0_10_0_ge_set_xy(&pre_a[i], &ai.x, &ai.y);
    }

    /* Multiply the last z-coordinate by C to undo the isomorphism.
     * Since the z-coordinates of the pre_a values are implied by the zr array of z-coordinate ratios,
     * undoing the isomorphism here undoes the isomorphism for all pre_a values.
     */
    rustsecp256k1_v0_10_0_fe_mul(z, &ai.z, &d.z);
}

SECP256K1_INLINE static void rustsecp256k1_v0_10_0_ecmult_table_verify(int n, int w) {
    (void)n;
    (void)w;
    VERIFY_CHECK(((n) & 1) == 1);
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1));
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1));
}

SECP256K1_INLINE static void rustsecp256k1_v0_10_0_ecmult_table_get_ge(rustsecp256k1_v0_10_0_ge *r, const rustsecp256k1_v0_10_0_ge *pre, int n, int w) {
    rustsecp256k1_v0_10_0_ecmult_table_verify(n,w);
    if (n > 0) {
        *r = pre[(n-1)/2];
    } else {
        *r = pre[(-n-1)/2];
        rustsecp256k1_v0_10_0_fe_negate(&(r->y), &(r->y), 1);
    }
}

SECP256K1_INLINE static void rustsecp256k1_v0_10_0_ecmult_table_get_ge_lambda(rustsecp256k1_v0_10_0_ge *r, const rustsecp256k1_v0_10_0_ge *pre, const rustsecp256k1_v0_10_0_fe *x, int n, int w) {
    rustsecp256k1_v0_10_0_ecmult_table_verify(n,w);
    if (n > 0) {
        rustsecp256k1_v0_10_0_ge_set_xy(r, &x[(n-1)/2], &pre[(n-1)/2].y);
    } else {
        rustsecp256k1_v0_10_0_ge_set_xy(r, &x[(-n-1)/2], &pre[(-n-1)/2].y);
        rustsecp256k1_v0_10_0_fe_negate(&(r->y), &(r->y), 1);
    }
}

SECP256K1_INLINE static void rustsecp256k1_v0_10_0_ecmult_table_get_ge_storage(rustsecp256k1_v0_10_0_ge *r, const rustsecp256k1_v0_10_0_ge_storage *pre, int n, int w) {
    rustsecp256k1_v0_10_0_ecmult_table_verify(n,w);
    if (n > 0) {
        rustsecp256k1_v0_10_0_ge_from_storage(r, &pre[(n-1)/2]);
    } else {
        rustsecp256k1_v0_10_0_ge_from_storage(r, &pre[(-n-1)/2]);
        rustsecp256k1_v0_10_0_fe_negate(&(r->y), &(r->y), 1);
    }
}

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int rustsecp256k1_v0_10_0_ecmult_wnaf(int *wnaf, int len, const rustsecp256k1_v0_10_0_scalar *a, int w) {
    rustsecp256k1_v0_10_0_scalar s;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    VERIFY_CHECK(wnaf != NULL);
    VERIFY_CHECK(0 <= len && len <= 256);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(2 <= w && w <= 31);

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    s = *a;
    if (rustsecp256k1_v0_10_0_scalar_get_bits(&s, 255, 1)) {
        rustsecp256k1_v0_10_0_scalar_negate(&s, &s);
        sign = -1;
    }

    while (bit < len) {
        int now;
        int word;
        if (rustsecp256k1_v0_10_0_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = rustsecp256k1_v0_10_0_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
#ifdef VERIFY
    {
        int verify_bit = bit;

        VERIFY_CHECK(carry == 0);

        while (verify_bit < 256) {
            VERIFY_CHECK(rustsecp256k1_v0_10_0_scalar_get_bits(&s, verify_bit, 1) == 0);
            verify_bit++;
        }
    }
#endif
    return last_set_bit + 1;
}

struct rustsecp256k1_v0_10_0_strauss_point_state {
    int wnaf_na_1[129];
    int wnaf_na_lam[129];
    int bits_na_1;
    int bits_na_lam;
};

struct rustsecp256k1_v0_10_0_strauss_state {
    /* aux is used to hold z-ratios, and then used to hold pre_a[i].x * BETA values. */
    rustsecp256k1_v0_10_0_fe* aux;
    rustsecp256k1_v0_10_0_ge* pre_a;
    struct rustsecp256k1_v0_10_0_strauss_point_state* ps;
};

/** Set r equal to the sum of a and b (with b given in affine coordinates).
 *  this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
// rustsecp256k1_v0_10_0_gej_add_ge_var(rustsecp256k1_v0_10_0_gej *r, const rustsecp256k1_v0_10_0_gej *a, const rustsecp256k1_v0_10_0_ge *b, rustsecp256k1_v0_10_0_fe *rzr);

/** A group element in affine coordinates on the secp256k1 curve, or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6. */
// typedef struct {
//     rustsecp256k1_v0_10_0_fe x;
//     rustsecp256k1_v0_10_0_fe y;
//     int infinity; /* whether this represents the point at infinity */
// } rustsecp256k1_v0_10_0_ge;

/** This field implementation represents the value as 5 uint64_t limbs in base 2^52. */
// typedef struct {
//     uint64_t n[5];
// } rustsecp256k1_v0_10_0_fe;

// /** A group element of the secp256k1 curve, in jacobian coordinates. */
// typedef struct {
//     rustsecp256k1_v0_10_0_fe x; /* actual X: x/z^2 */
//     rustsecp256k1_v0_10_0_fe y; /* actual Y: y/z^3 */
//     rustsecp256k1_v0_10_0_fe z;
//     int infinity; /* whether this represents the point at infinity */
// } rustsecp256k1_v0_10_0_gej;

SECP256K1_INLINE static void print_fe(const rustsecp256k1_v0_10_0_fe *fe) {
    #ifdef DEBUG_PRINT
    printf("fe{%lx %lx %lx %lx %lx}\n", fe->n[0], fe->n[1], fe->n[2], fe->n[3], fe->n[4]);
    #endif
}

SECP256K1_INLINE static void print_ge(const rustsecp256k1_v0_10_0_ge *ge) {
    #ifdef DEBUG_PRINT
    printf("ge: {\n x: ");
    print_fe(&ge->x);
    printf(" y: ");
    print_fe(&ge->y);
    printf("}\n");
    #endif
}

SECP256K1_INLINE static void print_gej(const rustsecp256k1_v0_10_0_gej *gej) {
    #ifdef DEBUG_PRINT
    printf("gej: {\n x: ");
    print_fe(&gej->x);
    printf(" y: ");
    print_fe(&gej->y);
    printf(" z: ");
    print_fe(&gej->z);
    printf("}\n");
    #endif
}

static void ecmult_increment(rustsecp256k1_v0_10_0_gej *r) {
    static const rustsecp256k1_v0_10_0_ge g1 = {{{0x2815b16f81798, 0xdb2dce28d959f, 0xe870b07029bfc, 0xbbac55a06295c, 0x79be667ef9dc}}, {{0x7d08ffb10d4b8, 0x48a68554199c4, 0xe1108a8fd17b4, 0xc4655da4fbfc0, 0x483ada7726a3}}, 0};
    rustsecp256k1_v0_10_0_gej d;
    rustsecp256k1_v0_10_0_ge prea;
    rustsecp256k1_v0_10_0_fe z1 = {{1, 0, 0, 0, 0}};

    rustsecp256k1_v0_10_0_gej_double_var(&d, r, NULL); // because na and ng are 1
    rustsecp256k1_v0_10_0_ge_set_gej_zinv(&prea, r, &d.z); // pre_a[0] = affine coordinates of Jacobian point (a.x, a.y, 1/d.z).

    r->x = prea.x;
    r->y = prea.y;
    r->z = z1;

    // Use just one value from the precomputed table G
    rustsecp256k1_v0_10_0_gej_add_zinv_var(r, r, &g1, &d.z);
    rustsecp256k1_v0_10_0_fe_mul(&r->z, &r->z, &d.z);
}

static void rustsecp256k1_v0_10_0_ecmult_strauss_wnaf(const struct rustsecp256k1_v0_10_0_strauss_state *state,
            rustsecp256k1_v0_10_0_gej *r,
            size_t num,                                 // always 1
            const rustsecp256k1_v0_10_0_gej *a,         // always the same as r
            const rustsecp256k1_v0_10_0_scalar *na,     // always 1
            const rustsecp256k1_v0_10_0_scalar *ng      // always 1
            ) {
    static const rustsecp256k1_v0_10_0_ge g1 = {{{0x2815b16f81798, 0xdb2dce28d959f, 0xe870b07029bfc, 0xbbac55a06295c, 0x79be667ef9dc}}, {{0x7d08ffb10d4b8, 0x48a68554199c4, 0xe1108a8fd17b4, 0xc4655da4fbfc0, 0x483ada7726a3}}, 0};
    rustsecp256k1_v0_10_0_gej d;
    rustsecp256k1_v0_10_0_ge prea;

    rustsecp256k1_v0_10_0_gej_double_var(&d, a, NULL); // because na and ng are 1
    rustsecp256k1_v0_10_0_ge_set_gej_zinv(&prea, a, &d.z); // pre_a[0] = affine coordinates of Jacobian point (a.x, a.y, 1/d.z).

    // r = prea
    memset(r, 0, sizeof(*r));
    memcpy(r, &prea, 2*sizeof(prea.x)); // copy x and y
    r->z.n[0] = 1; // set z to 1

    // Use just one value from the precomputed table G
    rustsecp256k1_v0_10_0_gej_add_zinv_var(r, r, &g1, &d.z);
    rustsecp256k1_v0_10_0_fe_mul(&r->z, &r->z, &d.z);















    // /* Split G factors. */
    // // rustsecp256k1_v0_10_0_scalar ng_1, ng_128;
    // // int wnaf_ng_1[129];
    // // int bits_ng_1 = 0;
    // // int wnaf_ng_128[129];
    // // int bits_ng_128 = 0;
    // // int i;
    // // int bits = 0;
    // // size_t np;
    // // size_t no = 0;

    // // fprintf(stdout, "na: %lx %lx %lx %lx\n", na->d[0], na->d[1], na->d[2], na->d[3]);
    // // fprintf(stdout, "ng: %lx %lx %lx %lx\n", ng->d[0], ng->d[1], ng->d[2], ng->d[3]);

    // // rustsecp256k1_v0_10_0_fe_set_int(&Z, 1);
    // memset(&Z, 0, sizeof(Z));
    // Z.n[0] = 1;

    // // np = 0; //for (np = 0; np < num; ++np) {
    //     // rustsecp256k1_v0_10_0_gej tmp;
    //     // rustsecp256k1_v0_10_0_scalar na_1 = rustsecp256k1_v0_10_0_scalar_one, na_lam = rustsecp256k1_v0_10_0_scalar_zero;
    //     // if (rustsecp256k1_v0_10_0_scalar_is_zero(&na[np]) || rustsecp256k1_v0_10_0_gej_is_infinity(&a[np])) {
    //     //     continue;
    //     // }
    //     /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
    //     // rustsecp256k1_v0_10_0_scalar_split_lambda(&na_1, &na_lam, &na[np]);
    //     // fprintf(stdout, "np: %lu\n", np);
    //     // Print to stdout na_1, na_lam
    //     // fprintf(stdout, "na_1: %lx %lx %lx %lx\n", na_1.d[0], na_1.d[1], na_1.d[2], na_1.d[3]);
    //     // fprintf(stdout, "na_lam: %lx %lx %lx %lx\n", na_lam.d[0], na_lam.d[1], na_lam.d[2], na_lam.d[3]);

    //     /* build wnaf representation for na_1 and na_lam. */
    //     // state->ps[no].bits_na_1   = rustsecp256k1_v0_10_0_ecmult_wnaf(state->ps[no].wnaf_na_1,   129, &na_1,   WINDOW_A);
    //     // state->ps[0].bits_na_1 = 1;
    //     // memset(state->ps[0].wnaf_na_1, 0, 129 * sizeof(state->ps[0].wnaf_na_1[0]));
    //     // state->ps[0].wnaf_na_1[0] = 1;
    //     // fprintf(stdout, "state->ps[no].bits_na_1: %d\n", state->ps[no].bits_na_1);
    //     // fprintf(stdout, "state->ps[no].wnaf_na_1: ");
    //     // for (i = 0; i < 129; i++) {
    //     //     fprintf(stdout, "%d ", state->ps[no].wnaf_na_1[i]);
    //     // }
    //     // fprintf(stdout, "\n");
    //     // state->ps[no].bits_na_lam = rustsecp256k1_v0_10_0_ecmult_wnaf(state->ps[no].wnaf_na_lam, 129, &na_lam, WINDOW_A);
    //     // state->ps[no].bits_na_lam = 0;
    //     // memset(state->ps[no].wnaf_na_lam, 0, 129 * sizeof(state->ps[no].wnaf_na_lam[0]));
    //     // fprintf(stdout, "state->ps[no].bits_na_lam: %d\n", state->ps[no].bits_na_lam);
    //     // fprintf(stdout, "state->ps[no].wnaf_na_lam: ");
    //     // for (i = 0; i < 129; i++) {
    //     //     fprintf(stdout, "%d ", state->ps[no].wnaf_na_lam[i]);
    //     // }
    //     // fprintf(stdout, "\n");
    //     // if (state->ps[no].bits_na_1 > bits) {
    //     //     bits = state->ps[no].bits_na_1;
    //     // }
    //     // if (state->ps[no].bits_na_lam > bits) {
    //     //     bits = state->ps[no].bits_na_lam;
    //     // }
    //     // bits = 1;
    //     // fprintf(stdout, "bits: %d\n", bits);

    //     /* Calculate odd multiples of a.
    //      * All multiples are brought to the same Z 'denominator', which is stored
    //      * in Z. Due to secp256k1' isomorphism we can do all operations pretending
    //      * that the Z coordinate was 1, use affine addition formulae, and correct
    //      * the Z coordinate of the result once at the end.
    //      * The exception is the precomputed G table points, which are actually
    //      * affine. Compared to the base used for other points, they have a Z ratio
    //      * of 1/Z, so we can use rustsecp256k1_v0_10_0_gej_add_zinv_var, which uses the same
    //      * isomorphism to efficiently add with a known Z inverse.
    //      */
    //     // tmp = a[np];
    //     // if (no) {
    //     //     fprintf(stdout, "rustsecp256k1_v0_10_0_gej_rescale\n");
    //     //     rustsecp256k1_v0_10_0_gej_rescale(&tmp, &Z);
    //     // }
    //     rustsecp256k1_v0_10_0_ecmult_odd_multiples_table(
    //             8, //ECMULT_TABLE_SIZE(WINDOW_A),
    //             state->pre_a/* + no * ECMULT_TABLE_SIZE(WINDOW_A)*/,
    //             state->aux/* + no * ECMULT_TABLE_SIZE(WINDOW_A)*/,
    //             &Z,
    //             a /*&tmp*/); // tmp is the first group of the actual point, so the table is different each time
    //     // if (no) {
    //     //     fprintf(stdout, "rustsecp256k1_v0_10_0_fe_mul\n");
    //     //     rustsecp256k1_v0_10_0_fe_mul(state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), &(a[np].z));
    //     // }

    //     // ++no;
    // // }

    // /* Bring them to the same Z denominator. */
    // // if (no) {
    //     rustsecp256k1_v0_10_0_ge_table_set_globalz(ECMULT_TABLE_SIZE(WINDOW_A)/* * no*/, state->pre_a, state->aux); // Required
    // // }

    // // for (np = 0; np < no; ++np) {
    //     // Oddly not required at all
    //     // for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
    //     //     rustsecp256k1_v0_10_0_fe_mul(
    //     //         &state->aux[/*np * ECMULT_TABLE_SIZE(WINDOW_A) +*/ i],
    //     //         &state->pre_a[/*np * ECMULT_TABLE_SIZE(WINDOW_A) +*/ i].x,
    //     //         &rustsecp256k1_v0_10_0_const_beta);
    //     // }
    // // }

    // // if (ng) {
    //     /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
    //     // rustsecp256k1_v0_10_0_scalar_split_128(&ng_1, &ng_128, ng);
    //     // memset(&ng_1, 0, sizeof(ng_1));
    //     // ng_1.d[0] = 1;
    //     // memset(&ng_128, 0, sizeof(ng_128));
    //     // fprintf(stdout, "ng_1: %lx %lx %lx %lx\n", ng_1.d[0], ng_1.d[1], ng_1.d[2], ng_1.d[3]);
    //     // fprintf(stdout, "ng_128: %lx %lx %lx %lx\n", ng_128.d[0], ng_128.d[1], ng_128.d[2], ng_128.d[3]);

    //     /* Build wnaf representation for ng_1 and ng_128 */
    //     // bits_ng_1   = rustsecp256k1_v0_10_0_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
    //     // bits_ng_1 = 1;
    //     // memset(wnaf_ng_1, 0, 129 * sizeof(wnaf_ng_1[0]));
    //     // wnaf_ng_1[0] = 1;
    //     // fprintf(stdout, "bits_ng_1: %d\n", bits_ng_1);
    //     // fprintf(stdout, "wnaf_ng_1: ");
    //     // for (i = 0; i < 129; i++) {
    //     //     fprintf(stdout, "%d ", wnaf_ng_1[i]);
    //     // }
    //     // fprintf(stdout, "\n");
    //     // bits_ng_128 = rustsecp256k1_v0_10_0_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
    //     // bits_ng_128 = 0;
    //     // memset(wnaf_ng_128, 0, 129 * sizeof(wnaf_ng_128[0]));
    //     // fprintf(stdout, "bits_ng_128: %d\n", bits_ng_128);
    //     // fprintf(stdout, "wnaf_ng_128: ");
    //     // for (i = 0; i < 129; i++) {
    //     //     fprintf(stdout, "%d ", wnaf_ng_128[i]);
    //     // }
    //     // fprintf(stdout, "\n");
    //     // if (bits_ng_1 > bits) {
    //     //     bits = bits_ng_1;
    //     // }
    //     // if (bits_ng_128 > bits) {
    //     //     bits = bits_ng_128;
    //     // }
    //     // bits = 1;
    //     // fprintf(stdout, "bits: %d\n", bits);
    // // }

    // rustsecp256k1_v0_10_0_gej_set_infinity(r); // clear r? // Required

    // // i = 0; // for (i = bits - 1; i >= 0; i--) { // Only one iteration
    //     int n;
    //     rustsecp256k1_v0_10_0_gej_double_var(r, r, NULL);
    //     // np = 0; // for (np = 0; np < no; ++np) { // Only one iteration
    //         // Always entered due to na_1 being 1
    //         // if (i < state->ps[np].bits_na_1 && (n = state->ps[np].wnaf_na_1[i])) {
    //         n = 1;
                
    //             rustsecp256k1_v0_10_0_ecmult_table_get_ge(&tmpa, state->pre_a/* + np * ECMULT_TABLE_SIZE(WINDOW_A)*/, n, WINDOW_A);
    //             rustsecp256k1_v0_10_0_gej_add_ge_var(r, r, &tmpa, NULL);
    //         // }
    //         // Never entered due to na_lam being zero
    //         // if (i < state->ps[np].bits_na_lam && (n = state->ps[np].wnaf_na_lam[i])) {
    //         //     rustsecp256k1_v0_10_0_ecmult_table_get_ge_lambda(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
    //         //     rustsecp256k1_v0_10_0_gej_add_ge_var(r, r, &tmpa, NULL);
    //         // }
    //     // }
    //     // Always entered due to ng_1 being 1
    //     // if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
    //     n = 1;
    //         rustsecp256k1_v0_10_0_ecmult_table_get_ge_storage(&tmpa, rustsecp256k1_v0_10_0_pre_g, n, WINDOW_G);
    //         rustsecp256k1_v0_10_0_gej_add_zinv_var(r, r, &tmpa, &Z);
    //     // }
    //     // Never entered due to ng_128 being zero
    //     // if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
    //     //     fprintf(stdout, "block 4\n");
    //     //     rustsecp256k1_v0_10_0_ecmult_table_get_ge_storage(&tmpa, rustsecp256k1_v0_10_0_pre_g_128, n, WINDOW_G);
    //     //     rustsecp256k1_v0_10_0_gej_add_zinv_var(r, r, &tmpa, &Z);
    //     // }
    // // }

    // if (!r->infinity) {
    //     rustsecp256k1_v0_10_0_fe_mul(&r->z, &r->z, &Z);
    // }
}

static void rustsecp256k1_v0_10_0_ecmult(rustsecp256k1_v0_10_0_gej *r, const rustsecp256k1_v0_10_0_gej *a, const rustsecp256k1_v0_10_0_scalar *na, const rustsecp256k1_v0_10_0_scalar *ng) {
    rustsecp256k1_v0_10_0_fe aux[ECMULT_TABLE_SIZE(WINDOW_A)];
    rustsecp256k1_v0_10_0_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    struct rustsecp256k1_v0_10_0_strauss_point_state ps[1];
    struct rustsecp256k1_v0_10_0_strauss_state state;

    state.aux = aux;
    state.pre_a = pre_a;
    state.ps = ps;
    rustsecp256k1_v0_10_0_ecmult_strauss_wnaf(&state, r, 1, a, na, ng);
}

static size_t rustsecp256k1_v0_10_0_strauss_scratch_size(size_t n_points) {
    static const size_t point_size = (sizeof(rustsecp256k1_v0_10_0_ge) + sizeof(rustsecp256k1_v0_10_0_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct rustsecp256k1_v0_10_0_strauss_point_state) + sizeof(rustsecp256k1_v0_10_0_gej) + sizeof(rustsecp256k1_v0_10_0_scalar);
    return n_points*point_size;
}

/** Convert a number to WNAF notation.
 *  The number becomes represented by sum(2^{wi} * wnaf[i], i=0..WNAF_SIZE(w)+1) - return_val.
 *  It has the following guarantees:
 *  - each wnaf[i] is either 0 or an odd integer between -(1 << w) and (1 << w)
 *  - the number of words set is always WNAF_SIZE(w)
 *  - the returned skew is 0 or 1
 */
static int rustsecp256k1_v0_10_0_wnaf_fixed(int *wnaf, const rustsecp256k1_v0_10_0_scalar *s, int w) {
    int skew = 0;
    int pos;
    int max_pos;
    int last_w;
    const rustsecp256k1_v0_10_0_scalar *work = s;

    if (rustsecp256k1_v0_10_0_scalar_is_zero(s)) {
        for (pos = 0; pos < WNAF_SIZE(w); pos++) {
            wnaf[pos] = 0;
        }
        return 0;
    }

    if (rustsecp256k1_v0_10_0_scalar_is_even(s)) {
        skew = 1;
    }

    wnaf[0] = rustsecp256k1_v0_10_0_scalar_get_bits_var(work, 0, w) + skew;
    /* Compute last window size. Relevant when window size doesn't divide the
     * number of bits in the scalar */
    last_w = WNAF_BITS - (WNAF_SIZE(w) - 1) * w;

    /* Store the position of the first nonzero word in max_pos to allow
     * skipping leading zeros when calculating the wnaf. */
    for (pos = WNAF_SIZE(w) - 1; pos > 0; pos--) {
        int val = rustsecp256k1_v0_10_0_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if(val != 0) {
            break;
        }
        wnaf[pos] = 0;
    }
    max_pos = pos;
    pos = 1;

    while (pos <= max_pos) {
        int val = rustsecp256k1_v0_10_0_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if ((val & 1) == 0) {
            wnaf[pos - 1] -= (1 << w);
            wnaf[pos] = (val + 1);
        } else {
            wnaf[pos] = val;
        }
        /* Set a coefficient to zero if it is 1 or -1 and the proceeding digit
         * is strictly negative or strictly positive respectively. Only change
         * coefficients at previous positions because above code assumes that
         * wnaf[pos - 1] is odd.
         */
        if (pos >= 2 && ((wnaf[pos - 1] == 1 && wnaf[pos - 2] < 0) || (wnaf[pos - 1] == -1 && wnaf[pos - 2] > 0))) {
            if (wnaf[pos - 1] == 1) {
                wnaf[pos - 2] += 1 << w;
            } else {
                wnaf[pos - 2] -= 1 << w;
            }
            wnaf[pos - 1] = 0;
        }
        ++pos;
    }

    return skew;
}

struct rustsecp256k1_v0_10_0_pippenger_point_state {
    int skew_na;
    size_t input_pos;
};

struct rustsecp256k1_v0_10_0_pippenger_state {
    int *wnaf_na;
    struct rustsecp256k1_v0_10_0_pippenger_point_state* ps;
};

/*
 * pippenger_wnaf computes the result of a multi-point multiplication as
 * follows: The scalars are brought into wnaf with n_wnaf elements each. Then
 * for every i < n_wnaf, first each point is added to a "bucket" corresponding
 * to the point's wnaf[i]. Second, the buckets are added together such that
 * r += 1*bucket[0] + 3*bucket[1] + 5*bucket[2] + ...
 */
static int rustsecp256k1_v0_10_0_ecmult_pippenger_wnaf(rustsecp256k1_v0_10_0_gej *buckets, int bucket_window, struct rustsecp256k1_v0_10_0_pippenger_state *state, rustsecp256k1_v0_10_0_gej *r, const rustsecp256k1_v0_10_0_scalar *sc, const rustsecp256k1_v0_10_0_ge *pt, size_t num) {
    size_t n_wnaf = WNAF_SIZE(bucket_window+1);
    size_t np;
    size_t no = 0;
    int i;
    int j;

    for (np = 0; np < num; ++np) {
        if (rustsecp256k1_v0_10_0_scalar_is_zero(&sc[np]) || rustsecp256k1_v0_10_0_ge_is_infinity(&pt[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
        state->ps[no].skew_na = rustsecp256k1_v0_10_0_wnaf_fixed(&state->wnaf_na[no*n_wnaf], &sc[np], bucket_window+1);
        no++;
    }
    rustsecp256k1_v0_10_0_gej_set_infinity(r);

    if (no == 0) {
        return 1;
    }

    for (i = n_wnaf - 1; i >= 0; i--) {
        rustsecp256k1_v0_10_0_gej running_sum;

        for(j = 0; j < ECMULT_TABLE_SIZE(bucket_window+2); j++) {
            rustsecp256k1_v0_10_0_gej_set_infinity(&buckets[j]);
        }

        for (np = 0; np < no; ++np) {
            int n = state->wnaf_na[np*n_wnaf + i];
            struct rustsecp256k1_v0_10_0_pippenger_point_state point_state = state->ps[np];
            rustsecp256k1_v0_10_0_ge tmp;
            int idx;

            if (i == 0) {
                /* correct for wnaf skew */
                int skew = point_state.skew_na;
                if (skew) {
                    rustsecp256k1_v0_10_0_ge_neg(&tmp, &pt[point_state.input_pos]);
                    rustsecp256k1_v0_10_0_gej_add_ge_var(&buckets[0], &buckets[0], &tmp, NULL);
                }
            }
            if (n > 0) {
                idx = (n - 1)/2;
                rustsecp256k1_v0_10_0_gej_add_ge_var(&buckets[idx], &buckets[idx], &pt[point_state.input_pos], NULL);
            } else if (n < 0) {
                idx = -(n + 1)/2;
                rustsecp256k1_v0_10_0_ge_neg(&tmp, &pt[point_state.input_pos]);
                rustsecp256k1_v0_10_0_gej_add_ge_var(&buckets[idx], &buckets[idx], &tmp, NULL);
            }
        }

        for(j = 0; j < bucket_window; j++) {
            rustsecp256k1_v0_10_0_gej_double_var(r, r, NULL);
        }

        rustsecp256k1_v0_10_0_gej_set_infinity(&running_sum);
        /* Accumulate the sum: bucket[0] + 3*bucket[1] + 5*bucket[2] + 7*bucket[3] + ...
         *                   = bucket[0] +   bucket[1] +   bucket[2] +   bucket[3] + ...
         *                   +         2 *  (bucket[1] + 2*bucket[2] + 3*bucket[3] + ...)
         * using an intermediate running sum:
         * running_sum = bucket[0] +   bucket[1] +   bucket[2] + ...
         *
         * The doubling is done implicitly by deferring the final window doubling (of 'r').
         */
        for(j = ECMULT_TABLE_SIZE(bucket_window+2) - 1; j > 0; j--) {
            rustsecp256k1_v0_10_0_gej_add_var(&running_sum, &running_sum, &buckets[j], NULL);
            rustsecp256k1_v0_10_0_gej_add_var(r, r, &running_sum, NULL);
        }

        rustsecp256k1_v0_10_0_gej_add_var(&running_sum, &running_sum, &buckets[0], NULL);
        rustsecp256k1_v0_10_0_gej_double_var(r, r, NULL);
        rustsecp256k1_v0_10_0_gej_add_var(r, r, &running_sum, NULL);
    }
    return 1;
}

/**
 * Returns optimal bucket_window (number of bits of a scalar represented by a
 * set of buckets) for a given number of points.
 */
static int rustsecp256k1_v0_10_0_pippenger_bucket_window(size_t n) {
    if (n <= 1) {
        return 1;
    } else if (n <= 4) {
        return 2;
    } else if (n <= 20) {
        return 3;
    } else if (n <= 57) {
        return 4;
    } else if (n <= 136) {
        return 5;
    } else if (n <= 235) {
        return 6;
    } else if (n <= 1260) {
        return 7;
    } else if (n <= 4420) {
        return 9;
    } else if (n <= 7880) {
        return 10;
    } else if (n <= 16050) {
        return 11;
    } else {
        return PIPPENGER_MAX_BUCKET_WINDOW;
    }
}

/**
 * Returns the maximum optimal number of points for a bucket_window.
 */
static size_t rustsecp256k1_v0_10_0_pippenger_bucket_window_inv(int bucket_window) {
    switch(bucket_window) {
        case 1: return 1;
        case 2: return 4;
        case 3: return 20;
        case 4: return 57;
        case 5: return 136;
        case 6: return 235;
        case 7: return 1260;
        case 8: return 1260;
        case 9: return 4420;
        case 10: return 7880;
        case 11: return 16050;
        case PIPPENGER_MAX_BUCKET_WINDOW: return SIZE_MAX;
    }
    return 0;
}


SECP256K1_INLINE static void rustsecp256k1_v0_10_0_ecmult_endo_split(rustsecp256k1_v0_10_0_scalar *s1, rustsecp256k1_v0_10_0_scalar *s2, rustsecp256k1_v0_10_0_ge *p1, rustsecp256k1_v0_10_0_ge *p2) {
    rustsecp256k1_v0_10_0_scalar tmp = *s1;
    rustsecp256k1_v0_10_0_scalar_split_lambda(s1, s2, &tmp);
    rustsecp256k1_v0_10_0_ge_mul_lambda(p2, p1);

    if (rustsecp256k1_v0_10_0_scalar_is_high(s1)) {
        rustsecp256k1_v0_10_0_scalar_negate(s1, s1);
        rustsecp256k1_v0_10_0_ge_neg(p1, p1);
    }
    if (rustsecp256k1_v0_10_0_scalar_is_high(s2)) {
        rustsecp256k1_v0_10_0_scalar_negate(s2, s2);
        rustsecp256k1_v0_10_0_ge_neg(p2, p2);
    }
}

/**
 * Returns the scratch size required for a given number of points (excluding
 * base point G) without considering alignment.
 */
static size_t rustsecp256k1_v0_10_0_pippenger_scratch_size(size_t n_points, int bucket_window) {
    size_t entries = 2*n_points + 2;
    size_t entry_size = sizeof(rustsecp256k1_v0_10_0_ge) + sizeof(rustsecp256k1_v0_10_0_scalar) + sizeof(struct rustsecp256k1_v0_10_0_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);
    return (sizeof(rustsecp256k1_v0_10_0_gej) << bucket_window) + sizeof(struct rustsecp256k1_v0_10_0_pippenger_state) + entries * entry_size;
}

/* Computes ecmult_multi by simply multiplying and adding each point. Does not
 * require a scratch space */
static int rustsecp256k1_v0_10_0_ecmult_multi_simple_var(rustsecp256k1_v0_10_0_gej *r, const rustsecp256k1_v0_10_0_scalar *inp_g_sc, rustsecp256k1_v0_10_0_ecmult_multi_callback cb, void *cbdata, size_t n_points) {
    size_t point_idx;
    rustsecp256k1_v0_10_0_gej tmpj;

    rustsecp256k1_v0_10_0_gej_set_infinity(r);
    rustsecp256k1_v0_10_0_gej_set_infinity(&tmpj);
    /* r = inp_g_sc*G */
    rustsecp256k1_v0_10_0_ecmult(r, &tmpj, &rustsecp256k1_v0_10_0_scalar_zero, inp_g_sc);
    for (point_idx = 0; point_idx < n_points; point_idx++) {
        rustsecp256k1_v0_10_0_ge point;
        rustsecp256k1_v0_10_0_gej pointj;
        rustsecp256k1_v0_10_0_scalar scalar;
        if (!cb(&scalar, &point, point_idx, cbdata)) {
            return 0;
        }
        /* r += scalar*point */
        rustsecp256k1_v0_10_0_gej_set_ge(&pointj, &point);
        rustsecp256k1_v0_10_0_ecmult(&tmpj, &pointj, &scalar, NULL);
        rustsecp256k1_v0_10_0_gej_add_var(r, r, &tmpj, NULL);
    }
    return 1;
}

/* Compute the number of batches and the batch size given the maximum batch size and the
 * total number of points */
static int rustsecp256k1_v0_10_0_ecmult_multi_batch_size_helper(size_t *n_batches, size_t *n_batch_points, size_t max_n_batch_points, size_t n) {
    if (max_n_batch_points == 0) {
        return 0;
    }
    if (max_n_batch_points > ECMULT_MAX_POINTS_PER_BATCH) {
        max_n_batch_points = ECMULT_MAX_POINTS_PER_BATCH;
    }
    if (n == 0) {
        *n_batches = 0;
        *n_batch_points = 0;
        return 1;
    }
    /* Compute ceil(n/max_n_batch_points) and ceil(n/n_batches) */
    *n_batches = 1 + (n - 1) / max_n_batch_points;
    *n_batch_points = 1 + (n - 1) / *n_batches;
    return 1;
}


#endif /* SECP256K1_ECMULT_IMPL_H */
