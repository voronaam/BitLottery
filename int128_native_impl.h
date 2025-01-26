#ifndef SECP256K1_INT128_NATIVE_IMPL_H
#define SECP256K1_INT128_NATIVE_IMPL_H

#include "int128.h"

static inline void rustsecp256k1_v0_10_0_u128_load(rustsecp256k1_v0_10_0_uint128 *r, uint64_t hi, uint64_t lo) {
    *r = (((uint128_t)hi) << 64) + lo;
}

static inline void rustsecp256k1_v0_10_0_u128_mul(rustsecp256k1_v0_10_0_uint128 *r, uint64_t a, uint64_t b) {
   *r = (uint128_t)a * b;
}

static inline void rustsecp256k1_v0_10_0_u128_accum_mul(rustsecp256k1_v0_10_0_uint128 *r, uint64_t a, uint64_t b) {
   *r += (uint128_t)a * b;
}

static inline void rustsecp256k1_v0_10_0_u128_accum_u64(rustsecp256k1_v0_10_0_uint128 *r, uint64_t a) {
   *r += a;
}

static inline void rustsecp256k1_v0_10_0_u128_rshift(rustsecp256k1_v0_10_0_uint128 *r, unsigned int n) {
   *r >>= n;
}

static inline uint64_t rustsecp256k1_v0_10_0_u128_to_u64(const rustsecp256k1_v0_10_0_uint128 *a) {
   return (uint64_t)(*a);
}

static inline uint64_t rustsecp256k1_v0_10_0_u128_hi_u64(const rustsecp256k1_v0_10_0_uint128 *a) {
   return (uint64_t)(*a >> 64);
}

static inline void rustsecp256k1_v0_10_0_u128_from_u64(rustsecp256k1_v0_10_0_uint128 *r, uint64_t a) {
   *r = a;
}

static inline int rustsecp256k1_v0_10_0_u128_check_bits(const rustsecp256k1_v0_10_0_uint128 *r, unsigned int n) {
   return (*r >> n == 0);
}

static inline void rustsecp256k1_v0_10_0_i128_load(rustsecp256k1_v0_10_0_int128 *r, int64_t hi, uint64_t lo) {
    *r = (((uint128_t)(uint64_t)hi) << 64) + lo;
}

static inline void rustsecp256k1_v0_10_0_i128_mul(rustsecp256k1_v0_10_0_int128 *r, int64_t a, int64_t b) {
   *r = (int128_t)a * b;
}

static inline void rustsecp256k1_v0_10_0_i128_accum_mul(rustsecp256k1_v0_10_0_int128 *r, int64_t a, int64_t b) {
   int128_t ab = (int128_t)a * b;
   *r += ab;
}

static inline void rustsecp256k1_v0_10_0_i128_det(rustsecp256k1_v0_10_0_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d) {
   int128_t ad = (int128_t)a * d;
   int128_t bc = (int128_t)b * c;
   *r = ad - bc;
}

static inline void rustsecp256k1_v0_10_0_i128_rshift(rustsecp256k1_v0_10_0_int128 *r, unsigned int n) {
   *r >>= n;
}

static inline uint64_t rustsecp256k1_v0_10_0_i128_to_u64(const rustsecp256k1_v0_10_0_int128 *a) {
   return (uint64_t)*a;
}

static inline int64_t rustsecp256k1_v0_10_0_i128_to_i64(const rustsecp256k1_v0_10_0_int128 *a) {
   return *a;
}

static inline void rustsecp256k1_v0_10_0_i128_from_i64(rustsecp256k1_v0_10_0_int128 *r, int64_t a) {
   *r = a;
}

static inline int rustsecp256k1_v0_10_0_i128_eq_var(const rustsecp256k1_v0_10_0_int128 *a, const rustsecp256k1_v0_10_0_int128 *b) {
   return *a == *b;
}

static inline int rustsecp256k1_v0_10_0_i128_check_pow2(const rustsecp256k1_v0_10_0_int128 *r, unsigned int n, int sign) {
   return (*r == (int128_t)((uint128_t)sign << n));
}

#endif
