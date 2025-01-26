/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/* This is a C project. It should not be compiled with a C++ compiler,
 * and we error out if we detect one.
 *
 * We still want to be able to test the project with a C++ compiler
 * because it is still good to know if this will lead to real trouble, so
 * there is a possibility to override the check. But be warned that
 * compiling with a C++ compiler is not supported. */
#if defined(__cplusplus) && !defined(SECP256K1_CPLUSPLUS_TEST_OVERRIDE)
#error Trying to compile a C project with a C++ compiler.
#endif

#define SECP256K1_BUILD

#include <string.h>

#include "secp256k1.h"
#include "secp256k1_preallocated.h"

#include "util.h"

#include "scalar_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "ecmult_gen_impl.h"
#include "eckey_impl.h"


/* Note that whenever you change the context struct, you must also change the
 * context_eq function. */
struct rustsecp256k1_v0_10_0_context_struct {
    rustsecp256k1_v0_10_0_ecmult_gen_context ecmult_gen_ctx;
};

size_t rustsecp256k1_v0_10_0_context_preallocated_size(unsigned int flags) {
    return sizeof(rustsecp256k1_v0_10_0_context);
}
rustsecp256k1_v0_10_0_context* rustsecp256k1_v0_10_0_context_preallocated_create(void* prealloc, unsigned int flags) {
    size_t prealloc_size;
    rustsecp256k1_v0_10_0_context* ret;

    prealloc_size = rustsecp256k1_v0_10_0_context_preallocated_size(flags);
    if (prealloc_size == 0) {
        return NULL;
    }
    VERIFY_CHECK(prealloc != NULL);
    ret = (rustsecp256k1_v0_10_0_context*)prealloc;

    /* Flags have been checked by rustsecp256k1_v0_10_0_context_preallocated_size. */
    VERIFY_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_CONTEXT);
    rustsecp256k1_v0_10_0_ecmult_gen_context_build(&ret->ecmult_gen_ctx);

    return ret;
}

static int rustsecp256k1_v0_10_0_pubkey_load(rustsecp256k1_v0_10_0_ge* ge, const rustsecp256k1_v0_10_0_pubkey* pubkey) {
    if (sizeof(rustsecp256k1_v0_10_0_ge_storage) == 64) {
        /* When the rustsecp256k1_v0_10_0_ge_storage type is exactly 64 byte, use its
         * representation inside rustsecp256k1_v0_10_0_pubkey, as conversion is very fast.
         * Note that rustsecp256k1_v0_10_0_pubkey_save must use the same representation. */
        rustsecp256k1_v0_10_0_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        rustsecp256k1_v0_10_0_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        rustsecp256k1_v0_10_0_fe x, y;
        rustsecp256k1_v0_10_0_ge_set_xy(ge, &x, &y);
    }
    return 1;
}

int rustsecp256k1_v0_10_0_ec_pubkey_serialize(unsigned char *output, size_t *outputlen, const rustsecp256k1_v0_10_0_pubkey* pubkey, unsigned int flags) {
    rustsecp256k1_v0_10_0_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    len = *outputlen;
    *outputlen = 0;
    memset(output, 0, len);
    if (rustsecp256k1_v0_10_0_pubkey_load(&Q, pubkey)) {
        ret = rustsecp256k1_v0_10_0_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static int rustsecp256k1_v0_10_0_ec_pubkey_create_helper(const rustsecp256k1_v0_10_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1_v0_10_0_scalar *seckey_scalar, rustsecp256k1_v0_10_0_ge *p, const unsigned char *seckey) {
    rustsecp256k1_v0_10_0_gej pj;
    int ret;

    ret = rustsecp256k1_v0_10_0_scalar_set_b32_seckey(seckey_scalar, seckey);
    rustsecp256k1_v0_10_0_scalar_cmov(seckey_scalar, &rustsecp256k1_v0_10_0_scalar_one, !ret);

    rustsecp256k1_v0_10_0_ecmult_gen(ecmult_gen_ctx, &pj, seckey_scalar);
    rustsecp256k1_v0_10_0_ge_set_gej(p, &pj);
    return ret;
}

void expose_pubkey_create(const rustsecp256k1_v0_10_0_context *ctx, rustsecp256k1_v0_10_0_ge* p, const unsigned char *seckey) {
    rustsecp256k1_v0_10_0_scalar seckey_scalar;
    rustsecp256k1_v0_10_0_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &seckey_scalar, p, seckey);
}



