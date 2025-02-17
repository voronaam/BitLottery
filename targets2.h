#ifndef TARGETS2_H
#define TARGETS2_H

#include <cuda_runtime.h>

// You should know how many targets you have
#define MAX_BTC_TARGETS2 1
#define MAX_ETH_TARGETS2 1
#define MAX_XDR_TARGETS2 1

__device__ const unsigned char targets2btc[MAX_BTC_TARGETS2][20] = {
	// #include "some-bts.list"
	// Sorted list of 20-byte BTC targets (de base58 and so on)
	// This one is not a real list, just a placeholder
	{0, 34, 222, 7, 21, 147, 81, 240, 46, 92, 152, 207, 141, 25, 177, 137, 235, 111, 126, 115, },
};

__device__ const unsigned char targets2eth[MAX_ETH_TARGETS2][20] = {
	// #include "some-eth.list"
	// Sorted list of 20-byte ETH targets (de base58 and so on)
	// This one is not a real list, just a placeholder
	{0, 0, 0, 0, 0, 163, 155, 178, 114, 231, 144, 117, 173, 225, 37, 253, 53, 24, 135, 173, },
};

__device__ const unsigned char targets2xdr[MAX_XDR_TARGETS2][20] = {
	// #include "150-xdr.list"
	// Sorted list of 20-byte XDR targets (de-base58 with different alphabet and so on)
	{65, 164, 185, 89, 98, 136, 19, 140, 18, 222, 236, 142, 172, 61, 157, 114, 151, 249, 15, 39, },
};


#endif /* TARGETS2_H */
