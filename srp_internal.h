#ifndef  _SRP_INTERNAL_H_
#define _SRP_INTERNAL_H_
struct NGConstant {
    BIGNUM     *N;
    BIGNUM     *g;
} ;


typedef struct NGHex {
    const char * n_hex;
    const char * g_hex;
} NGHex;

struct SRPKeyPair {
    BIGNUM     *B;
    BIGNUM     *b;
};

typedef union
{
    mbedtls_sha1_context   sha;
    mbedtls_sha256_context sha256;
    mbedtls_sha512_context sha512;
} HashCTX;

struct SRPSession
{
    SRP_HashAlgorithm  hash_alg;
    NGConstant   *ng;
};

struct SRPVerifier
{
    SRP_HashAlgorithm  hash_alg;
    NGConstant  *ng;

    const char          * username;
    int                   authenticated;

    unsigned char M           [SHA512_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA512_DIGEST_LENGTH];
    unsigned char session_key [SHA512_DIGEST_LENGTH];
};


struct SRPUser
{
    SRP_HashAlgorithm  hash_alg;
    NGConstant  *ng;

    BIGNUM *a;
    BIGNUM *A;
    BIGNUM *S;

    int                   authenticated;

    const char *          username;
    const unsigned char * password;
    int                   password_len;

    unsigned char M           [SHA512_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA512_DIGEST_LENGTH];
    unsigned char session_key [SHA512_DIGEST_LENGTH];
};
#endif