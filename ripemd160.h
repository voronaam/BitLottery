#ifndef _RIPEMD160_CUH
#define _RIPEMD160_CUH

#include <cuda.h>
#include <cuda_runtime.h>
#include <string.h>
#include "dev_sha256.h"


#define RIPEMD160_BLOCK_LENGTH 64
#define RIPEMD160_DIGEST_LENGTH 20

/*
 * 32-bit integer manipulation macros (little endian)
 * CUDA is little-endian, we do not need the bitshift conversion
 */

/*
 * Process one block
 */
__device__ inline void ripemd160_process( uint32_t *state, const uint8_t data[RIPEMD160_BLOCK_LENGTH] )
{
    uint32_t A, B, C, D, E, Ap, Bp, Cp, Dp, Ep;

    uint32_t *X = (uint32_t *)data;

    A = Ap = state[0];
    B = Bp = state[1];
    C = Cp = state[2];
    D = Dp = state[3];
    E = Ep = state[4];

#define F1( x, y, z )   ( x ^ y ^ z )
#define F2( x, y, z )   ( ( x & y ) | ( ~x & z ) )
#define F3( x, y, z )   ( ( x | ~y ) ^ z )
#define F4( x, y, z )   ( ( x & z ) | ( y & ~z ) )
#define F5( x, y, z )   ( x ^ ( y | ~z ) )

#define S( x, n ) ( ( x << n ) | ( x >> (32 - n) ) )

#define P( a, b, c, d, e, r, s, f, k )      \
    a += f( b, c, d ) + X[r] + k;           \
    a = S( a, s ) + e;                      \
    c = S( c, 10 );

#define P2( a, b, c, d, e, r, s, rp, sp )   \
    P( a, b, c, d, e, r, s, F, K );         \
    P( a ## p, b ## p, c ## p, d ## p, e ## p, rp, sp, Fp, Kp );

#define F   F1
#define K   0x00000000
#define Fp  F5
#define Kp  0x50A28BE6
    P2( A, B, C, D, E,  0, 11,  5,  8 );
    P2( E, A, B, C, D,  1, 14, 14,  9 );
    P2( D, E, A, B, C,  2, 15,  7,  9 );
    P2( C, D, E, A, B,  3, 12,  0, 11 );
    P2( B, C, D, E, A,  4,  5,  9, 13 );
    P2( A, B, C, D, E,  5,  8,  2, 15 );
    P2( E, A, B, C, D,  6,  7, 11, 15 );
    P2( D, E, A, B, C,  7,  9,  4,  5 );
    P2( C, D, E, A, B,  8, 11, 13,  7 );
    P2( B, C, D, E, A,  9, 13,  6,  7 );
    P2( A, B, C, D, E, 10, 14, 15,  8 );
    P2( E, A, B, C, D, 11, 15,  8, 11 );
    P2( D, E, A, B, C, 12,  6,  1, 14 );
    P2( C, D, E, A, B, 13,  7, 10, 14 );
    P2( B, C, D, E, A, 14,  9,  3, 12 );
    P2( A, B, C, D, E, 15,  8, 12,  6 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F2
#define K   0x5A827999
#define Fp  F4
#define Kp  0x5C4DD124
    P2( E, A, B, C, D,  7,  7,  6,  9 );
    P2( D, E, A, B, C,  4,  6, 11, 13 );
    P2( C, D, E, A, B, 13,  8,  3, 15 );
    P2( B, C, D, E, A,  1, 13,  7,  7 );
    P2( A, B, C, D, E, 10, 11,  0, 12 );
    P2( E, A, B, C, D,  6,  9, 13,  8 );
    P2( D, E, A, B, C, 15,  7,  5,  9 );
    P2( C, D, E, A, B,  3, 15, 10, 11 );
    P2( B, C, D, E, A, 12,  7, 14,  7 );
    P2( A, B, C, D, E,  0, 12, 15,  7 );
    P2( E, A, B, C, D,  9, 15,  8, 12 );
    P2( D, E, A, B, C,  5,  9, 12,  7 );
    P2( C, D, E, A, B,  2, 11,  4,  6 );
    P2( B, C, D, E, A, 14,  7,  9, 15 );
    P2( A, B, C, D, E, 11, 13,  1, 13 );
    P2( E, A, B, C, D,  8, 12,  2, 11 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F3
#define K   0x6ED9EBA1
#define Fp  F3
#define Kp  0x6D703EF3
    P2( D, E, A, B, C,  3, 11, 15,  9 );
    P2( C, D, E, A, B, 10, 13,  5,  7 );
    P2( B, C, D, E, A, 14,  6,  1, 15 );
    P2( A, B, C, D, E,  4,  7,  3, 11 );
    P2( E, A, B, C, D,  9, 14,  7,  8 );
    P2( D, E, A, B, C, 15,  9, 14,  6 );
    P2( C, D, E, A, B,  8, 13,  6,  6 );
    P2( B, C, D, E, A,  1, 15,  9, 14 );
    P2( A, B, C, D, E,  2, 14, 11, 12 );
    P2( E, A, B, C, D,  7,  8,  8, 13 );
    P2( D, E, A, B, C,  0, 13, 12,  5 );
    P2( C, D, E, A, B,  6,  6,  2, 14 );
    P2( B, C, D, E, A, 13,  5, 10, 13 );
    P2( A, B, C, D, E, 11, 12,  0, 13 );
    P2( E, A, B, C, D,  5,  7,  4,  7 );
    P2( D, E, A, B, C, 12,  5, 13,  5 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F4
#define K   0x8F1BBCDC
#define Fp  F2
#define Kp  0x7A6D76E9
    P2( C, D, E, A, B,  1, 11,  8, 15 );
    P2( B, C, D, E, A,  9, 12,  6,  5 );
    P2( A, B, C, D, E, 11, 14,  4,  8 );
    P2( E, A, B, C, D, 10, 15,  1, 11 );
    P2( D, E, A, B, C,  0, 14,  3, 14 );
    P2( C, D, E, A, B,  8, 15, 11, 14 );
    P2( B, C, D, E, A, 12,  9, 15,  6 );
    P2( A, B, C, D, E,  4,  8,  0, 14 );
    P2( E, A, B, C, D, 13,  9,  5,  6 );
    P2( D, E, A, B, C,  3, 14, 12,  9 );
    P2( C, D, E, A, B,  7,  5,  2, 12 );
    P2( B, C, D, E, A, 15,  6, 13,  9 );
    P2( A, B, C, D, E, 14,  8,  9, 12 );
    P2( E, A, B, C, D,  5,  6,  7,  5 );
    P2( D, E, A, B, C,  6,  5, 10, 15 );
    P2( C, D, E, A, B,  2, 12, 14,  8 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F5
#define K   0xA953FD4E
#define Fp  F1
#define Kp  0x00000000
    P2( B, C, D, E, A,  4,  9, 12,  8 );
    P2( A, B, C, D, E,  0, 15, 15,  5 );
    P2( E, A, B, C, D,  5,  5, 10, 12 );
    P2( D, E, A, B, C,  9, 11,  4,  9 );
    P2( C, D, E, A, B,  7,  6,  1, 12 );
    P2( B, C, D, E, A, 12,  8,  5,  5 );
    P2( A, B, C, D, E,  2, 13,  8, 14 );
    P2( E, A, B, C, D, 10, 12,  7,  6 );
    P2( D, E, A, B, C, 14,  5,  6,  8 );
    P2( C, D, E, A, B,  1, 12,  2, 13 );
    P2( B, C, D, E, A,  3, 13, 13,  6 );
    P2( A, B, C, D, E,  8, 14, 14,  5 );
    P2( E, A, B, C, D, 11, 11,  0, 15 );
    P2( D, E, A, B, C,  6,  8,  3, 13 );
    P2( C, D, E, A, B, 15,  5,  9, 11 );
    P2( B, C, D, E, A, 13,  6, 11, 11 );
#undef F
#undef K
#undef Fp
#undef Kp

    C        = state[1] + C + Dp;
    state[1] = state[2] + D + Ep;
    state[2] = state[3] + E + Ap;
    state[3] = state[4] + A + Bp;
    state[4] = state[0] + B + Cp;
    state[0] = C;
}

// Padding with the embedded length of 32 bytes (there is a 1 in the sea of 0s)
__device__ static const uint8_t ripemd160_padding[32] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
};


/*
 * output = RIPEMD-160( input buffer )
 */
__device__ void ripemd160(const uint8_t msg[32], uint8_t hash[RIPEMD160_DIGEST_LENGTH])
{
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t buffer[RIPEMD160_BLOCK_LENGTH];
    memcpy( (void *) (buffer), msg, 32);
    memcpy( (void *) (buffer + 32), ripemd160_padding, 32);
    ripemd160_process( state, buffer );
    memcpy( (void *) (hash), state, 64);
}

__device__ static void sha256ripemd160(const unsigned char *input, uint8_t hash[RIPEMD160_DIGEST_LENGTH]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t buffer[RIPEMD160_BLOCK_LENGTH];
    uint32_t s[8] = {0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul};
    unsigned char buf[64] = {0};
    memcpy(buf, input, 33);
    buf[33] = 0x80;

    dev_sha256_transform(s, buf);

    int i;
    #pragma unroll 8
    for (i = 0; i < 8; i++) {
        dev_write_be32(&buffer[4*i], s[i]);
    }

    memcpy( (void *) (buffer + 32), ripemd160_padding, 32);
    ripemd160_process( state, buffer );
    memcpy( (void *) (hash), state, 64);
}


#endif