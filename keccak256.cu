#include <cstdint>
#include <cassert>
#include <cuda_runtime.h>

static constexpr int Keccak256_HASH_LEN = 32;

__device__ static void Keccak256_getHash(const uint8_t msg[], size_t len, uint8_t hashResult[Keccak256_HASH_LEN]);

__device__ static void Keccak256_absorb(uint64_t state[5][5]);
__device__ static uint64_t Keccak256_rotl64(uint64_t x, int i);

// #define UINT64_C(c) (c ## ULL)

__device__ constexpr int Keccak256_NUM_ROUNDS = 24;

__device__ constexpr unsigned char Keccak256_ROTATION[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

__device__ __forceinline__ uint64_t Keccak256_rotl64(uint64_t x, int i) {
    return ((0U + x) << i) | (x >> ((64 - i) & 63));
}

__device__ __forceinline__ void Keccak256_absorb(uint64_t state[5][5]) {
    uint64_t (*a)[5] = state;
    uint8_t r = 1;  // LFSR
    for (int i = 0; i < Keccak256_NUM_ROUNDS; i++) {
        // Theta step
        uint64_t c[5] = {};
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                c[x] ^= a[x][y];
        }
        for (int x = 0; x < 5; x++) {
            uint64_t d = c[(x + 4) % 5] ^ Keccak256_rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                a[x][y] ^= d;
        }

        // Rho and pi steps
        uint64_t b[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                b[y][(x * 2 + y * 3) % 5] = Keccak256_rotl64(a[x][y], Keccak256_ROTATION[x][y]);
        }

        // Chi step
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
        }

        // Iota step
        for (int j = 0; j < 7; j++) {
            a[0][0] ^= static_cast<uint64_t>(r & 1) << ((1 << j) - 1);
            r = static_cast<uint8_t>((r << 1) ^ ((r >> 7) * 0x171));
        }
    }
}

__device__ __forceinline__ void Keccak256_getHash(const uint8_t msg[], size_t len, uint8_t hashResult[Keccak256_HASH_LEN]) {
    uint64_t state[5][5] = {};

    // XOR each message byte into the state, and absorb full blocks
    int blockOff = 0;
    const int BLOCK_SIZE = 200 - Keccak256_HASH_LEN * 2; // Define BLOCK_SIZE here
    for (size_t i = 0; i < len; i++) {
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= static_cast<uint64_t>(msg[i]) << ((blockOff & 7) << 3);
        blockOff++;
        if (blockOff == BLOCK_SIZE) {
            Keccak256_absorb(state);
            blockOff = 0;
        }
    }

    // Final block and padding
    {
        int i = blockOff >> 3;
        state[i % 5][i / 5] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
        blockOff = BLOCK_SIZE - 1;
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
        Keccak256_absorb(state);
    }

    // Uint64 array to bytes in little endian
    for (int i = 0; i < Keccak256_HASH_LEN; i++) {
        int j = i >> 3;
        hashResult[i] = static_cast<uint8_t>(state[j % 5][j / 5] >> ((i & 7) << 3));
    }
}
