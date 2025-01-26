/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_IMPL_H
#define SECP256K1_ECKEY_IMPL_H

#include "field_5x52_impl.h"
#include "secp256k1.h"

static int rustsecp256k1_v0_10_0_eckey_pubkey_serialize(rustsecp256k1_v0_10_0_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (rustsecp256k1_v0_10_0_ge_is_infinity(elem)) {
        return 0;
    }
    rustsecp256k1_v0_10_0_fe_normalize_var(&elem->x);
    rustsecp256k1_v0_10_0_fe_normalize_var(&elem->y);
    rustsecp256k1_v0_10_0_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = rustsecp256k1_v0_10_0_fe_impl_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    } else {
        *size = 65;
        pub[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        rustsecp256k1_v0_10_0_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

#endif /* SECP256K1_ECKEY_IMPL_H */
