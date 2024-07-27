#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include<openssl/types.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
// #define SELECTION_PRIVATE_KEY 0x01 // Binary: 0001
// #define SELECTION_PUBLIC_KEY 0x02 // Binary: 0010
// #define SELECTION_PARAMETERS 0x04 // Binary: 0100
#define SELECTION_METADATA 0x08 // Binary: 1000
#ifndef OPENSSL_Paillier_MAX_MODULUS_BITS
#define OPENSSL_Paillier_MAX_MODULUS_BITS 10000
#endif
#define Paillier_MIN_MODULUS_BITS 1024
#define Paillier_GENERATOR_2 2
#define Paillier_PRIME "prime"


extern const OSSL_DISPATCH Paillier_store_functions[];
extern const OSSL_DISPATCH Paillierpriv_encoder_PEM[];
extern const OSSL_DISPATCH Paillierpub_encoder_PEM[];
extern const OSSL_DISPATCH PaillierDER_decoder_functions[];
extern const OSSL_DISPATCH PaillierPEM_decoder_functions[];


struct provider_ctx_st {
	const OSSL_CORE_HANDLE *core_handle;
	OSSL_LIB_CTX *libctx;
};
typedef void (*funcptr_t)(void);
typedef struct provider_ctx_st providerctx;
struct key_data {
	providerctx *provctx;
	BN_CTX *bn_ctx; // Big number context for efficient BN operations
	const char *algo_name; //algorithm name
	int prime_len;
	//int generator;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n; // Prime number
	BIGNUM *lambda;
	BIGNUM *g; // Generator
	BIGNUM *mu; // Private key
	int32_t x_key_size;
	int32_t y_key_size; // Size of the key in bits
	int selections;
	size_t dirty_cnt;
	CRYPTO_RWLOCK *lock;
	BN_MONT_CTX *method_mont_p;
	OSSL_LIB_CTX *libctx;
};
typedef struct key_data keyctx;
struct keyctx_gen {
	void *provctx;
	void *template;
	keyctx keydata;//contains the parameters and key information
	int selection;
    /* All these parameters are used for parameter generation only */
    size_t nbits;
    size_t pbits;
	size_t qbits;
    int generator; /* Used by Paillier as there is no FIPS mode */
    OSSL_CALLBACK *cb;
    void *cbarg;
	OSSL_LIB_CTX *libctx;
};
typedef struct keyctx_gen keygenctx;
struct Paillier_ctx {
	providerctx *provctx; //consistes of provider context
	keyctx *keydata;
	unsigned int flags;
	OSSL_LIB_CTX *libctx;
};
typedef struct Paillier_ctx Paillierctx;
// ASN1 structures for Paillier
// typedef struct {
//     ASN1_INTEGER *p;
//     ASN1_INTEGER *g;
// } Paillier_PARAMS;



struct Paillier_encoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
};
typedef struct Paillier_encoder_ctx_st Paillier_ENCODER_CTX;
struct Paillier_decoder_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
	int selection;
};
typedef struct Paillier_decoder_ctx_st Paillier_DECODER_CTX;
typedef struct {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *core;
    BIO *bio;
    char *uri;
    int eof;
} Paillier_STORE_CTX;

typedef struct{
    size_t c1_len;
    size_t c2_len;
    unsigned char *c1;
    unsigned char *c2;
} PaillierCiphertext;
int param_generation_function(keyctx *keydata,int nbits,int pbits,int qbits,BN_GENCB *cb);
int Paillier_builtin_paramgen(keyctx *keydata, int prime_len, int generator);
int Paillier_priv_key_gen(keyctx *keydata, BN_GENCB *cb);
int Paillier_public_key_gen(BN_CTX *ctx,const keyctx *keydata,const BIGNUM *priv,BIGNUM *public);
OSSL_LIB_CTX *getlibctx(void *provctx);
int modular_exp(BN_CTX *ctx,const BIGNUM *g,const BIGNUM *p,BIGNUM *c,const BIGNUM *x,keyctx *keydata);
int modular_mul_mont(BN_CTX *ctx, keyctx *keydata,const BIGNUM *s,const BIGNUM *m,BIGNUM *c2);
int serialize_Paillier_ciphertext_readable(BIGNUM *c1,unsigned char *out, size_t *out_len);
int modular_exp_decrypt(BN_CTX *ctx,const BIGNUM *g,const BIGNUM *p,BIGNUM *c,const BIGNUM *x,keyctx *keydata);
int decryptmodular_mul_mont(BN_CTX *ctx, keyctx *keydata,const BIGNUM *s_inv,const BIGNUM *c2,BIGNUM *m);
int deserialize_Paillier_ciphertext_readable(const unsigned char *in, size_t in_len, BIGNUM **c1);
BIGNUM *calculate_L(const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx );
BIGNUM *calculate_m(const BIGNUM *c, const BIGNUM *lambda, const BIGNUM *n, const BIGNUM *mu);