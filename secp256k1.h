#ifndef SECP256K1_H
#define SECP256K1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "group.h"

/** Unless explicitly stated all pointer arguments must not be NULL.
 *
 * The following rules specify the order of arguments in API calls:
 *
 * 1. Context pointers go first, followed by output arguments, combined
 *    output/input arguments, and finally input-only arguments.
 * 2. Array lengths always immediately follow the argument whose length
 *    they describe, even if this violates rule 1.
 * 3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
 *    later go first. This means: signatures, public nonces, secret nonces,
 *    messages, public keys, secret keys, tweaks.
 * 4. Arguments that are not data pointers go last, from more complex to less
 *    complex: function pointers, algorithm names, messages, void pointers,
 *    counts, flags, booleans.
 * 5. Opaque data pointers follow the function pointer they are to be passed to.
 */

/** Opaque data structure that holds context information
 */
typedef struct rustsecp256k1_v0_10_0_context_struct rustsecp256k1_v0_10_0_context;

/** Opaque data structure that holds a parsed and valid public key.
 */
typedef struct {
    unsigned char data[64];
} rustsecp256k1_v0_10_0_pubkey;

# if !defined(SECP256K1_GNUC_PREREQ)
#  if defined(__GNUC__)&&defined(__GNUC_MINOR__)
#   define SECP256K1_GNUC_PREREQ(_maj,_min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define SECP256K1_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

/*  When this header is used at build-time the SECP256K1_BUILD define needs to be set
 *  to correctly setup export attributes and nullness checks.  This is normally done
 *  by secp256k1.c but to guard against this header being included before secp256k1.c
 *  has had a chance to set the define (e.g. via test harnesses that just includes
 *  secp256k1.c) we set SECP256K1_NO_BUILD when this header is processed without the
 *  BUILD define so this condition can be caught.
 */
#ifndef SECP256K1_BUILD
# define SECP256K1_NO_BUILD
#endif

/* Symbol visibility. */

#define SECP256K1_API extern

/* Warning attributes
 * NONNULL is not used if SECP256K1_BUILD is set to avoid the compiler optimizing out
 * some paranoid null checks. */
# if defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define SECP256K1_WARN_UNUSED_RESULT
# endif
# if !defined(SECP256K1_BUILD) && defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_ARG_NONNULL(_x)  __attribute__ ((__nonnull__(_x)))
# else
#  define SECP256K1_ARG_NONNULL(_x)
# endif

/* All flags' lower 8 bits indicate what they're for. Do not use directly. */
#define SECP256K1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256K1_FLAGS_TYPE_COMPRESSION (1 << 1)
/* The higher bits contain the actual data. Do not use directly. */
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY (1 << 10)
#define SECP256K1_FLAGS_BIT_COMPRESSION (1 << 8)

/** Context flags to pass to rustsecp256k1_v0_10_0_context_create, rustsecp256k1_v0_10_0_context_preallocated_size, and
 *  rustsecp256k1_v0_10_0_context_preallocated_create. */
#define SECP256K1_CONTEXT_NONE (SECP256K1_FLAGS_TYPE_CONTEXT)

/** Deprecated context flags. These flags are treated equivalent to SECP256K1_CONTEXT_NONE. */
#define SECP256K1_CONTEXT_VERIFY (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
#define SECP256K1_CONTEXT_SIGN (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)

/* Testing flag. Do not use. */
#define SECP256K1_CONTEXT_DECLASSIFY (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY)

/** Flag to pass to rustsecp256k1_v0_10_0_ec_pubkey_serialize. */
#define SECP256K1_EC_COMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION)

/** Prefix byte used to tag various encoded curvepoints for specific purposes */
#define SECP256K1_TAG_PUBKEY_EVEN 0x02
#define SECP256K1_TAG_PUBKEY_ODD 0x03
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 0x06
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD 0x07

/** Serialize a pubkey object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  Out:    output:     a pointer to a 65-byte (if compressed==0) or 33-byte (if
 *                      compressed==1) byte array to place the serialized key
 *                      in.
 *  In/Out: outputlen:  a pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     pubkey:     a pointer to a rustsecp256k1_v0_10_0_pubkey containing an
 *                      initialized public key.
 *          flags:      SECP256K1_EC_COMPRESSED if serialization should be in
 *                      compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
 */
SECP256K1_API int rustsecp256k1_v0_10_0_ec_pubkey_serialize(
    unsigned char *output,
    size_t *outputlen,
    const rustsecp256k1_v0_10_0_pubkey *pubkey,
    unsigned int flags
);


extern void expose_pubkey_create(const rustsecp256k1_v0_10_0_context *ctx, rustsecp256k1_v0_10_0_ge* ge, const unsigned char *seckey);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_H */
