#ifndef SECP256K1_INT128_NATIVE_H
#define SECP256K1_INT128_NATIVE_H

#include <stdint.h>

#if !defined(UINT128_MAX) && defined(__SIZEOF_INT128__)
__extension__ typedef unsigned __int128 uint128_t;
__extension__ typedef __int128 int128_t;
# define UINT128_MAX ((uint128_t)(-1))
# define INT128_MAX ((int128_t)(UINT128_MAX >> 1))
# define INT128_MIN (-INT128_MAX - 1)
/* No (U)INT128_C macros because compilers providing __int128 do not support 128-bit literals.  */
#endif

typedef uint128_t rustsecp256k1_v0_10_0_uint128;
typedef int128_t rustsecp256k1_v0_10_0_int128;

#endif
