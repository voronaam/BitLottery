/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_UTIL_H
#define SECP256K1_UTIL_H

#include "secp256k1.h"

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#define STR_(x) #x
#define STR(x) STR_(x)
#define DEBUG_CONFIG_MSG(x) "DEBUG_CONFIG: " x
#define DEBUG_CONFIG_DEF(x) DEBUG_CONFIG_MSG(#x "=" STR(x))

# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
#  if SECP256K1_GNUC_PREREQ(2,7)
#   define SECP256K1_INLINE __inline__
#  elif (defined(_MSC_VER))
#   define SECP256K1_INLINE __inline
#  else
#   define SECP256K1_INLINE
#  endif
# else
#  define SECP256K1_INLINE inline
# endif

/** Assert statically that expr is an integer constant expression, and run stmt.
 *
 * Useful for example to enforce that magnitude arguments are constant.
 */
#define ASSERT_INT_CONST_AND_DO(expr, stmt) do { \
    switch(42) { \
        case /* ERROR: integer argument is not constant */ expr: \
            break; \
        default: ; \
    } \
    stmt; \
} while(0)

#if SECP256K1_GNUC_PREREQ(3, 0)
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#ifdef DETERMINISTIC
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed"); \
    } \
} while(0)
#else
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed: " #cond); \
    } \
} while(0)
#endif

/* Like assert(), but when VERIFY is defined. */
#if defined(VERIFYNEVER)
#define VERIFY_CHECK CHECK
#else
#define VERIFY_CHECK(cond)
#endif


#if defined(__BIGGEST_ALIGNMENT__)
#define ALIGNMENT __BIGGEST_ALIGNMENT__
#else
/* Using 16 bytes alignment because common architectures never have alignment
 * requirements above 8 for any of the types we care about. In addition we
 * leave some room because currently we don't care about a few bytes. */
#define ALIGNMENT 16
#endif

#define ROUND_TO_ALIGN(size) ((((size) + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT)

/* Macro for restrict, when available and not in a VERIFY build. */
#   define SECP256K1_RESTRICT __restrict__

# define SECP256K1_GNUC_EXT __extension__

/* Determine the number of trailing zero bits in a (non-zero) 32-bit x.
 * This function is only intended to be used as fallback for
 * rustsecp256k1_v0_10_0_ctz32_var, but permits it to be tested separately. */
static SECP256K1_INLINE int rustsecp256k1_v0_10_0_ctz32_var_debruijn(uint32_t x) {
    static const uint8_t debruijn[32] = {
        0x00, 0x01, 0x02, 0x18, 0x03, 0x13, 0x06, 0x19, 0x16, 0x04, 0x14, 0x0A,
        0x10, 0x07, 0x0C, 0x1A, 0x1F, 0x17, 0x12, 0x05, 0x15, 0x09, 0x0F, 0x0B,
        0x1E, 0x11, 0x08, 0x0E, 0x1D, 0x0D, 0x1C, 0x1B
    };
    return debruijn[(uint32_t)((x & -x) * 0x04D7651FU) >> 27];
}

/* Determine the number of trailing zero bits in a (non-zero) 64-bit x.
 * This function is only intended to be used as fallback for
 * rustsecp256k1_v0_10_0_ctz64_var, but permits it to be tested separately. */
static SECP256K1_INLINE int rustsecp256k1_v0_10_0_ctz64_var_debruijn(uint64_t x) {
    static const uint8_t debruijn[64] = {
        0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
        62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
        63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
        51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
    };
    return debruijn[(uint64_t)((x & -x) * 0x022FDD63CC95386DU) >> 58];
}

/* Determine the number of trailing zero bits in a (non-zero) 32-bit x. */
static SECP256K1_INLINE int rustsecp256k1_v0_10_0_ctz32_var(uint32_t x) {
    VERIFY_CHECK(x != 0);
#if (__has_builtin(__builtin_ctz) || SECP256K1_GNUC_PREREQ(3,4))
    /* If the unsigned type is sufficient to represent the largest uint32_t, consider __builtin_ctz. */
    if (((unsigned)UINT32_MAX) == UINT32_MAX) {
        return __builtin_ctz(x);
    }
#endif
#if (__has_builtin(__builtin_ctzl) || SECP256K1_GNUC_PREREQ(3,4))
    /* Otherwise consider __builtin_ctzl (the unsigned long type is always at least 32 bits). */
    return __builtin_ctzl(x);
#else
    /* If no suitable CTZ builtin is available, use a (variable time) software emulation. */
    return rustsecp256k1_v0_10_0_ctz32_var_debruijn(x);
#endif
}

/* Determine the number of trailing zero bits in a (non-zero) 64-bit x. */
static SECP256K1_INLINE int rustsecp256k1_v0_10_0_ctz64_var(uint64_t x) {
    VERIFY_CHECK(x != 0);
#if (__has_builtin(__builtin_ctzl) || SECP256K1_GNUC_PREREQ(3,4))
    /* If the unsigned long type is sufficient to represent the largest uint64_t, consider __builtin_ctzl. */
    if (((unsigned long)UINT64_MAX) == UINT64_MAX) {
        return __builtin_ctzl(x);
    }
#endif
#if (__has_builtin(__builtin_ctzll) || SECP256K1_GNUC_PREREQ(3,4))
    /* Otherwise consider __builtin_ctzll (the unsigned long long type is always at least 64 bits). */
    return __builtin_ctzll(x);
#else
    /* If no suitable CTZ builtin is available, use a (variable time) software emulation. */
    return rustsecp256k1_v0_10_0_ctz64_var_debruijn(x);
#endif
}

/* Read a uint64_t in big endian */
SECP256K1_INLINE static uint64_t rustsecp256k1_v0_10_0_read_be64(const unsigned char* p) {
    return (uint64_t)p[0] << 56 |
           (uint64_t)p[1] << 48 |
           (uint64_t)p[2] << 40 |
           (uint64_t)p[3] << 32 |
           (uint64_t)p[4] << 24 |
           (uint64_t)p[5] << 16 |
           (uint64_t)p[6] << 8  |
           (uint64_t)p[7];
}

/* Write a uint64_t in big endian */
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_write_be64(unsigned char* p, uint64_t x) {
    p[7] = x;
    p[6] = x >>  8;
    p[5] = x >> 16;
    p[4] = x >> 24;
    p[3] = x >> 32;
    p[2] = x >> 40;
    p[1] = x >> 48;
    p[0] = x >> 56;
}

#endif /* SECP256K1_UTIL_H */
