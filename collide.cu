#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>

#include "helper_cuda.h"
#include "CASerror.h"
#include "helper_timer.h"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "group.h"
#include "ripemd160.h"
#include "dev_key.h"
#include "keccak256.cu"
#include "targets2.h"

// #define DEBUG_MODE 1

#ifndef DEBUG_MODE
#define THREADS 32*6
#define KERNEL_ITERATIONS 1000000
#define HOST_ITERATIONS 1*10
#endif

#ifdef DEBUG_MODE
#define THREADS 1
#define HOST_ITERATIONS 1
#define KERNEL_ITERATIONS 3
#endif

#define TICKETS THREADS*THREADS // Should be THREADS**2

__device__ static int inline compare_dir(const unsigned char *a, const unsigned char *b) {
    #pragma unroll 20
    for (int i = 0; i < 20; i++) {
        if (a[i] > b[i]) {
            return 1;
        } else if (a[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

// Just a regular binary search. From glibc
__device__ static unsigned char *bsearch_dev(const unsigned char *__key,
                                      const unsigned char *__base,
                                      size_t __nmemb, size_t __size) {
  size_t __l, __u, __idx;
  const unsigned char *__p;
  int __comparison;

  __l = 0;
  __u = __nmemb;
  while (__l < __u) {
    __idx = (__l + __u) / 2;
    __p = (const unsigned char *)(((const unsigned char *)__base) +
                                  (__idx * __size));
    __comparison = compare_dir(__key, __p);
    if (__comparison < 0)
      __u = __idx;
    else if (__comparison > 0)
      __l = __idx + 1;
    else {
      return (unsigned char *)__p;
    }
  }

  return NULL;
}

/// 128 bytes for perfect alignment
typedef struct {
    unsigned char seckey[32];
    rustsecp256k1_v0_10_0_ge p;
    uint64_t offset;
} lottery_ticket;

struct WinnerMessage {
    uint64_t offset;
    unsigned char seckey[32];
    unsigned char serialized_pubkey[65];
};

__device__ inline void print20(const char* message, unsigned char *hash) {
    if (hash == NULL) {
        return;
    }
    printf("%s", message);
    for (int j = 0; j < 20; j++) {
        printf("%02x", hash[j]);
    }
    printf("\n");
}

__global__ void incKernel(lottery_ticket *g_idata, lottery_ticket *g_odata, CASError::MappedErrorType<WinnerMessage> device_winner_data) {
    int i;
    unsigned char serialized_pubkey[65], hash2[20], hash3[32];
    const unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;

    #pragma unroll 4
    for (i = 0; i < KERNEL_ITERATIONS; i++, dev_inc(&g_idata[index].p)) {
        // Make first byte of serialized_pubkey to be the oddity tag and bytes 1-33 to be the x coordinate
        dev_eckey_pubkey_serialize(&g_idata[index].p, serialized_pubkey);
        // Make bytes 34-65 to be the y coordinate
        dev_fe_impl_get_b32(serialized_pubkey + 33, &g_idata[index].p.y);

        sha256ripemd160(serialized_pubkey, hash2);

        Keccak256_getHash(serialized_pubkey + 1, 64, hash3); // last 20 bytes of hash3 is the ETH target now

        unsigned char* btc = (unsigned char*) bsearch_dev (hash2, (unsigned char*)targets2btc, MAX_BTC_TARGETS2, 20);
        unsigned char* eth = (unsigned char*) bsearch_dev (hash3 + 12, (unsigned char*)targets2eth, MAX_ETH_TARGETS2, 20);
        unsigned char* xdr = (unsigned char*) bsearch_dev (hash2, (unsigned char*)targets2xdr, MAX_XDR_TARGETS2, 20);
        if (btc != NULL || eth != NULL || xdr != NULL) {
            #ifndef DIRECT_PRINTF
            report_first_error(device_winner_data, [&] (WinnerMessage &error){
               error = WinnerMessage{
                    .offset = g_idata[index].offset + i,
                };
                memcpy(error.seckey, g_idata[index].seckey, 32);
                memcpy(error.serialized_pubkey, serialized_pubkey, 65);
            });
            #endif
            #ifdef DIRECT_PRINTF
            printf("Found a match! Offset from PK: %lx\nPK: ", g_idata[index].offset + i);
            for (int j = 0; j < 32; j++) {
                printf("%02x", g_idata[index].seckey[j]);
            }
            printf("\nPrinting the combined pubkey\n± <...........................x..................................><............................y.................................>\n");
            for (int j = 0; j < 65; j++) {
                printf("%02x", serialized_pubkey[j]);
            }
            printf("\n");
            print20("BTC target: ", btc);
            print20("ETH target: ", eth);
            print20("XDR target: ", xdr);
            #endif
        }
    }

    memcpy(g_odata[index].seckey, g_idata[index].seckey, 32);
    g_odata[index].p = g_idata[index].p;
    g_odata[index].offset = g_idata[index].offset + i;
}

// Use the full secp256k1 library to create the initial keypairs
static void create_tickets(lottery_ticket *tickets) {
    size_t ctx_size = rustsecp256k1_v0_10_0_context_preallocated_size(SECP256K1_CONTEXT_NONE); // 208
    void *ctx_mem = malloc(ctx_size);
    rustsecp256k1_v0_10_0_context *ctx = rustsecp256k1_v0_10_0_context_preallocated_create(ctx_mem, SECP256K1_CONTEXT_NONE);

    // Fill the tickets with keypairs
    for (int i = 0; i < TICKETS; i++) {
        // random 32 bytes of secret key
        for (int j = 0; j < 32; j++) {
            tickets[i].seckey[j] = rand() % 256;
        }
        expose_pubkey_create(ctx, &tickets[i].p, tickets[i].seckey);
    }

    free(ctx_mem);
}

void reportWinner( CASError::MappedErrorType<WinnerMessage> & error_dat) {
   if (error_dat.checkErrorReported()) {
        auto & winner = error_dat.get();
        printf("Found a match! Offset from PK: %lx\nPK: ", winner.offset);
        for (int j = 0; j < 32; j++) {
            printf("%02x", winner.seckey[j]);
        }
        printf("\nPrinting the combined pubkey\n± <...........................x..................................><............................y.................................>\n");
        for (int j = 0; j < 65; j++) {
            printf("%02x", winner.serialized_pubkey[j]);
        }
        printf("\n");
        error_dat.clear();
   }
}

int main(int argc, char **argv) {
    lottery_ticket tickets[TICKETS] = { 0 };
    create_tickets(tickets);

    int devID = findCudaDevice(argc, (const char **)argv); // use command-line specified CUDA device, otherwise use device with highest Gflops/s

    unsigned int mem_size = sizeof(lottery_ticket) * TICKETS;
    // allocate device memory
    lottery_ticket *d_idata;
    checkCudaErrors(cudaMalloc((void **)&d_idata, mem_size));
    lottery_ticket *d_odata;
    checkCudaErrors(cudaMalloc((void **)&d_odata, mem_size));
    // setup execution parameters
    dim3 grid(THREADS);
    dim3 threads(THREADS);

    auto mapped_winner = CASError::MappedErrorType<WinnerMessage>();
    cudaStream_t stream; cudaStreamCreate(&stream);

    StopWatchInterface *timer = 0;
    sdkCreateTimer(&timer);
    sdkStartTimer(&timer);

    for (int k = 0; k < HOST_ITERATIONS; k++) {
        checkCudaErrors(cudaMemcpy(d_idata, &tickets, mem_size, cudaMemcpyHostToDevice));
        incKernel<<<grid, threads, 0, stream>>>(d_idata, d_odata, mapped_winner);
        getLastCudaError("Kernel execution failed");
        checkCudaErrors(cudaMemcpy(&tickets, d_odata, mem_size, cudaMemcpyDeviceToHost));
        reportWinner(mapped_winner);
    }

    sdkStopTimer(&timer);

    unsigned __int128 total = 0;
    for (int i = 0; i < TICKETS; i++) {
        total += tickets[i].offset;
    }
    printf("Total: %llu %llu in %fms\n", (unsigned long long)(total >> 64), (unsigned long long)total, sdkGetTimerValue(&timer));

    // cleanup memory
    checkCudaErrors(cudaFree(d_idata));
    checkCudaErrors(cudaFree(d_odata));
    sdkDeleteTimer(&timer);

    return 0;
}
