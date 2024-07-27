#include <assert.h>
#include <stdlib.h>
#include <string.h>
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
#include <openssl/core_object.h>
#include "algorithm/Paillier.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/param_build.h>
#include <openssl/bio.h>
//declare the new function names a s pointer in the format of OSSL_FUNC_{name}_fn
static OSSL_FUNC_provider_gettable_params_fn Paillier_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn Paillier_prov_get_params;
static OSSL_FUNC_provider_query_operation_fn Paillier_prov_operation;
static OSSL_FUNC_asym_cipher_newctx_fn Paillier_newctx;
static OSSL_FUNC_asym_cipher_freectx_fn Paillier_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn Paillier_dupctx;
static OSSL_FUNC_asym_cipher_encrypt_init_fn Paillier_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn Paillier_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn Paillier_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn Paillier_decrypt;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn Paillier_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn Paillier_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn Paillier_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn Paillier_settable_ctx_params;
//Key management functions signatures
static OSSL_FUNC_keymgmt_new_fn Paillierkey_newctx;
static OSSL_FUNC_keymgmt_free_fn Paillierkey_freectx;
static OSSL_FUNC_keymgmt_gen_init_fn Paillierkey_gen_init;
static OSSL_FUNC_keymgmt_gen_fn Paillierkey_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn Paillierkey_clean;
static OSSL_FUNC_keymgmt_load_fn Paillierkey_load;
static OSSL_FUNC_keymgmt_export_fn Paillierkey_export;
static OSSL_FUNC_keymgmt_export_types_fn Paillierkey_export_type;
static OSSL_FUNC_keymgmt_has_fn Paillierkey_has;
static OSSL_FUNC_keymgmt_gen_settable_params_fn Paillierkeygen_settable_params;
static OSSL_FUNC_keymgmt_gen_set_params_fn Paillierkeygen_set_params;
static OSSL_FUNC_keymgmt_import_fn Paillierkey_import;
static OSSL_FUNC_keymgmt_import_types_fn Paillierkey_import_types;
//encoder code


//store functions
//static OSSL_FUNC_store_export_object_fn Paillier_store_export;

static void provider_ctx_free(providerctx *ctx)
{
	if (ctx != NULL) {
		free(ctx);
	}
}

static providerctx *provider_ctx_new(const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in)
{
	providerctx *provctx;
	if ((provctx = malloc(sizeof(*provctx))) != NULL) {
		provctx->core_handle = core;
		provctx->libctx=OSSL_LIB_CTX_new_from_dispatch(core,in);
	} else {
		provider_ctx_free(provctx);
		provctx = NULL;
	}
	return provctx;
}

static void *Paillier_newctx(void *prov_ctx)
{
	Paillierctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx != NULL) {
		ctx->provctx = prov_ctx;
		 
	}
	return ctx;
}
static void Paillier_freectx(void *ctx)
{
	if ((ctx != NULL)) {
		Paillierctx *temp_ctx = (Paillierctx *)ctx;
		free(temp_ctx);
	}
}
static void *Paillier_dupctx(void *ectx)
{
	Paillierctx *src = ectx;
	Paillierctx *dst = OPENSSL_zalloc(sizeof(*src));
	if (dst == NULL) {
		return NULL;
	}
	dst->provctx = src->provctx;
	dst->keydata = src->keydata;
	dst->flags = src->flags;
	return dst;
}
static int Paillier_encrypt_init(void *ctx, void *provkey,
				const OSSL_PARAM params[])
{
    Paillierctx *ectx=ctx;
    keyctx *key=provkey;
    if(provkey!=NULL){
        ectx->keydata=key;
    }

	return 1;
}
static int Paillier_decrypt_init(void *ctx, void *provkey,
				const OSSL_PARAM params[])
{
	Paillierctx *ectx=ctx;
    keyctx *key=provkey;
    if(provkey!=NULL){
        ectx->keydata=key;
    }

	return 1;
	
}



static int Paillier_encrypt(void *ctx, unsigned char *out, size_t *outlen,
                           size_t outsize, const unsigned char *in,
                           size_t inlen)
{
    Paillierctx *ectx = ctx;
    keyctx *tempkey = ectx->keydata;
    BIGNUM *bn_message, *gcd, *one, *p_minus_one, *c, *r,*n_squared,*g_m,*r_n;
    int ret = 0;

    if (ctx == NULL || tempkey == NULL) {
        fprintf(stderr, "Error: Invalid context or key data\n");
        return 1;
    }

    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        return 1;
    }

    BN_CTX_start(bnctx);
    bn_message = BN_CTX_get(bnctx);
    c = BN_CTX_get(bnctx);
    r=BN_CTX_get(bnctx);
    one=BN_CTX_get(bnctx);
    gcd=BN_CTX_get(bnctx);
    n_squared=BN_CTX_get(bnctx);
    r_n=BN_CTX_get(bnctx);
    g_m=BN_CTX_get(bnctx);
    if (bn_message == NULL || r == NULL || c == NULL || one==NULL || n_squared==NULL || r_n==NULL || g_m==NULL) {
        fprintf(stderr, "Error: BN_CTX_get failed\n");
        goto err;
    }


    if (!BN_bin2bn(in, inlen, bn_message)) {
        fprintf(stderr, "Error converting message to BIGNUM\n");
        goto err;
    }

    if (BN_cmp(bn_message, tempkey->n) >= 0) {
        fprintf(stderr, "Error: Message is too large for the prime\n");
        goto err;
    }

    if (!BN_one(one)) {
        fprintf(stderr, "Error: Setting one failed\n");
        goto err;
    }

    do {
        // Generate random r in range [1, n-1]
        if (!BN_rand_range(r, tempkey->n)) {
            fprintf(stderr, "Error: Generating random r failed\n");
            goto err;
        }
        if (!BN_add(r, r, one)) {
            fprintf(stderr, "Error: Adjusting r failed\n");
            goto err;
        }

        // Check gcd(r, n)
        if (!BN_gcd(gcd, r, tempkey->n, bnctx)) {
             unsigned long err_code = ERR_get_error();
    char err_msg[256];
    ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
            fprintf(stderr, "Error: GCD calculation failed\n");
            goto err;
        }
    } while (BN_cmp(gcd, one) != 0);
     // Calculate n^2
    if (!BN_sqr(n_squared, tempkey->n, bnctx)) {
        fprintf(stderr, "Error: Calculating n^2 failed\n");
        goto err;
    }

    // Calculate g^m mod n^2
    if (!BN_mod_exp(g_m, tempkey->g, bn_message, n_squared, bnctx)) {
        fprintf(stderr, "Error: Calculating g^m mod n^2 failed\n");
        goto err;
    }

    // Calculate r^n mod n^2
    if (!BN_mod_exp(r_n, r, tempkey->n, n_squared, bnctx)) {
        fprintf(stderr, "Error: Calculating r^n mod n^2 failed\n");
        goto err;
    }

    // Calculate (g^m * r^n) mod n^2
    if (!BN_mod_mul(c, g_m, r_n, n_squared, bnctx)) {
        fprintf(stderr, "Error: Calculating final result failed\n");
        goto err;
    }

    if (!serialize_Paillier_ciphertext_readable(c, out, outlen)) {
        fprintf(stderr, "Error: Serializing ciphertext\n");
        goto err;
    }

    ret = 1;

err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
}


static int Paillier_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                           size_t outsize, const unsigned char *in,
                           size_t inlen)
{
    Paillierctx *ectx = ctx;
    keyctx *tempkey = ectx->keydata;
    BIGNUM *bn_message, *c1, *c2, *s, *s_inv;
    int ret = 0;

    if (ctx == NULL || tempkey == NULL) {
        fprintf(stderr, "Error: Invalid context or key data\n");
        return 1;
    }

    BN_CTX *bnctx = BN_CTX_new();
    if (bnctx == NULL) {
        fprintf(stderr, "Error: Failed to create BN_CTX\n");
        return 1;
    }

    BN_CTX_start(bnctx);
    bn_message = BN_CTX_get(bnctx);
    c1 = BN_CTX_get(bnctx);
    c2 = BN_CTX_get(bnctx);
    s = BN_CTX_get(bnctx);
    s_inv = BN_CTX_get(bnctx);

    if (bn_message == NULL || c1 == NULL || c2 == NULL || s == NULL || s_inv == NULL) {
        fprintf(stderr, "Error: BN_CTX_get failed\n");
        goto err;
    }

    if (!deserialize_Paillier_ciphertext_readable(in, inlen, &c1)) {
        fprintf(stderr, "Error: Deserialization failed\n");
        goto err;
    }
//    if(!calculate_m(c1,tempkey->lambda,tempkey->n,tempkey->mu))
//    goto err;
   // Calculate the required output length
    size_t bn_message_len = BN_num_bytes(bn_message);
    *outlen = bn_message_len;

    // If out is NULL, return the required length
    if (out == NULL) {
        ret = 1;
        goto err;
    }

    // Check if the output buffer is large enough
    if (*outlen > outsize) {
        fprintf(stderr, "Error: Output buffer is too small\n");
        goto err;
    }

    // Convert BIGNUM to binary and store it in the output buffer
    BN_bn2bin(bn_message, out);

    ret = 1;

err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
}

static int Paillier_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
	 OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "provider-name")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, "Paillier Provider");

    if ((p = OSSL_PARAM_locate(params, "provider-version")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, "1.0.0");

    return 1;
}
static const OSSL_PARAM gettable_params[] = {
    OSSL_PARAM_utf8_ptr("name", NULL, 0),
    OSSL_PARAM_utf8_ptr("version", NULL, 0),
	OSSL_PARAM_utf8_ptr("status", NULL, 0),
    OSSL_PARAM_END
};

 static const OSSL_PARAM *Paillier_gettable_ctx_params(void *ctx, void *provctx)
 {
	printf("hi there");
	return gettable_params;
 }
static int Paillier_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	return 0;
}
static const OSSL_PARAM *Paillier_settable_ctx_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM table[] = {
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}


OSSL_LIB_CTX *ossl_prov_ctx_get0_libctx(providerctx *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

//key management functions
static void *Paillierkey_newctx(void *provctx)
{
	if (provctx == NULL) {
		return NULL;
	}
	keyctx *keydata = OPENSSL_zalloc(sizeof(*keydata));
	if (keydata != NULL) {
		keydata->provctx = provctx;
		keydata->lock=CRYPTO_THREAD_lock_new();
		keydata->libctx=ossl_prov_ctx_get0_libctx(provctx);
    if (keydata->lock == NULL) {
        OPENSSL_free(keydata);
        return NULL;
    }
	}
	return keydata;
}
static void Paillierkey_freectx(void *keydata)
{
	if (keydata != NULL) {
		keyctx *temp_keydata = (keyctx *)keydata;
		free(temp_keydata);
	}
}
static void *Paillierkey_gen_init(void *provctx, int selection,
				 const OSSL_PARAM params[])
{
	keygenctx *keygen = NULL;
     const OSSL_PARAM *p;
	if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                      | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0)
        return NULL;
	if ((keygen = OPENSSL_zalloc(sizeof(*keygen)))!=NULL) {
		keygen->provctx = provctx;
        keygen->selection = selection;
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &keygen->nbits)) {
            // Handle error
            return 0;
        }
        keygen->pbits=keygen->nbits>>1;
        keygen->qbits=keygen->nbits>>1;

    }
    else{
       keygen->nbits = 2048;
       keygen->pbits=2048>>1;
       keygen->qbits=2048>>1;
    }
        
        //keygen->generator = 2;
        keygen->libctx=getlibctx(provctx);
        
		// here ypu can call the set functions if the user is passing some data it can be usefule in future
		
	}
	return keygen;
}
static int Paillier_gencb(int p, int n, BN_GENCB *cb)
{
   keygenctx *ctx= BN_GENCB_get_arg(cb);
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    return ctx->cb(params, ctx->cbarg);
}
int check_prime(BIGNUM *p, BN_CTX *ctx) {
    int ret = BN_check_prime(p, ctx, NULL);
    if (ret == 1) {
        printf("The number is prime.\n");
        return 1;
    } else if (ret == 0) {
        printf("The number is not prime.\n");
    } else {
        printf("Error in primality test.\n");
    }
    return 0;
}

// Function to check if a generator is valid for a given prime
int check_generator(const BIGNUM *g, const BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *p_minus_one_half = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *tmp = BN_new();
    int ret = 0;

    // Set two to the value of 2
    BN_set_word(two, 2);

    // Compute p-1 and (p-1)/2
    BN_sub(p_minus_one, p, BN_value_one());
    BN_rshift1(p_minus_one_half, p_minus_one);

    // Check if g is in the range [2, p-2]
    if (BN_cmp(g, two) < 0 || BN_cmp(g, p_minus_one) >= 0) {
        printf("The generator is not in the valid range [2, p-1].\n");
        goto cleanup;
    }

    // Check g^2 mod p != 1
    BN_mod_exp(tmp, g, two, p, ctx);
    if (BN_is_one(tmp)) {
        printf("The generator is not valid (g^2 mod p == 1).\n");
        goto cleanup;
    }

    // Check g^((p-1)/2) mod p != 1
    BN_mod_exp(tmp, g, p_minus_one_half, p, ctx);
    if (BN_is_one(tmp)) {
        printf("The generator is not valid (g^((p-1)/2) mod p == 1).\n");
        goto cleanup;
    }

    printf("The generator is valid.\n");
    ret = 1;

cleanup:
    BN_free(p_minus_one);
    BN_free(p_minus_one_half);
    BN_free(two);
    BN_free(tmp);
    return ret;
}
static void *Paillierkey_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
	int temp = 0;
	keygenctx *tempctx = genctx;
	BN_GENCB *gencb = NULL;
    // returns the keydata object that will store the key and parameters in it
	keyctx *keydata = Paillierkey_newctx(tempctx->provctx);
	if (keydata != NULL) {
		
		tempctx->cb=cb;
		tempctx->cbarg=cbarg;
		gencb = BN_GENCB_new();
        if (gencb != NULL)
		BN_GENCB_set(gencb, Paillier_gencb, genctx);
        
        temp = param_generation_function(keydata,tempctx->nbits,tempctx->pbits,tempctx->qbits,gencb);
		
		if (tempctx->selection == OSSL_KEYMGMT_SELECT_KEYPAIR &&
		    temp) {
			keydata->selections = tempctx->selection;
			//call the key generation functions in the Pailliersrc.c file
			temp=Paillier_priv_key_gen(keydata,gencb);
            }
		// } else if (tempctx->selection ==
		// 		   OSSL_KEYMGMT_SELECT_PUBLIC_KEY &&
		// 	   temp) {
		// 	//call the key generation functions in the Pailliersrc.c file
		// 	//Paillier_public_key_gen(keydata);
		// }
	}
	end:
    if (temp <= 0) {
        
        keydata = NULL;
    }
    BN_GENCB_free(gencb);
    return keydata;
}
static void Paillierkey_clean(void *genctx)
{
	// set all the values to null
}
static int Paillierkey_has(const void *keydata, int selection){
    
    
    const keyctx *key;

    if (keydata == NULL)
        return 0;  // Changed from goto err

    key = (const keyctx*)keydata;  // Cast keydata to the correct type

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (key->lambda != NULL && key->mu!=NULL)  // Removed (*keyctx), use -> instead of .
            return 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (key->n != NULL&& key->g!=NULL)
            return 1;
    }

    return 0;  // If neither condition is met, return 0
}

static int Paillierkey_import(void *keydata, int selection, const OSSL_PARAM params[]){
    keyctx *tempkey=keydata;
    
    return 1;
}
static const OSSL_PARAM *Paillierkey_import_types(int selection){
   const OSSL_PARAM priv_key[]={ OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_BN(Paillier_PRIME, NULL, 0),
        OSSL_PARAM_END};
}
static void *Paillierkey_load(const void *reference, size_t reference_sz){
    keyctx *tempkey=NULL;
    if(!reference || reference_sz!=sizeof(tempkey))
    return NULL;
    tempkey=*(keyctx**) reference;
    *(keyctx**) reference=NULL;

	return tempkey;
}
static int Paillierkeygen_set_params(void *genctx, const OSSL_PARAM params[])
{
	keygenctx *ctx=genctx;
	const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

   if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS)) != NULL
        && !OSSL_PARAM_get_size_t(p, &ctx->nbits))
        return 0;
    // p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
    // if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->generator))
    //     return 0;
	return 1;
}
static const OSSL_PARAM *Paillierkeygen_settable_params(void *genctx,
                                                        void *provctx)
{
	static const OSSL_PARAM Paillier_gen_settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_GENERATOR, NULL),
        OSSL_PARAM_END
    };
    return Paillier_gen_settable;

}
static const OSSL_PARAM *Paillierkey_export_type(int selection)
{
    
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0){
        static const OSSL_PARAM Paillier_keytype[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0), 
       // OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_P, NULL, 0) ,
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
        OSSL_PARAM_END};
        return Paillier_keytype;
    }
    return NULL;
}
static int Paillierkey_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                       void *cbarg)
{
    keyctx *key = keydata;
    BIGNUM *n = NULL, *lamda = NULL, *g = NULL,*mu=NULL;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (key == NULL || param_cb == NULL)
        return 0;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;
    

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        n=key->n;
        lamda=key->lambda;
        g=key->g;
        mu=key->mu;
       if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, lamda))
    goto err;
if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
    goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);

err:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    return ret;

}

static const OSSL_DISPATCH Paillier_functions[] = {
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX, (funcptr_t)Paillier_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (funcptr_t)Paillier_freectx },
	{ OSSL_FUNC_ASYM_CIPHER_DUPCTX, (funcptr_t)Paillier_dupctx },
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (funcptr_t)Paillier_encrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (funcptr_t)Paillier_decrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (funcptr_t)Paillier_encrypt },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT, (funcptr_t)Paillier_decrypt },
	{ OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
	  (funcptr_t)Paillier_get_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
	  (funcptr_t)Paillier_gettable_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
	  (funcptr_t)Paillier_set_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
	  (funcptr_t)Paillier_settable_ctx_params },
	{ 0, NULL }
};
static const OSSL_DISPATCH Paillierkey_functions[] = {
	{ OSSL_FUNC_KEYMGMT_NEW, (funcptr_t)Paillierkey_newctx },
	{ OSSL_FUNC_KEYMGMT_FREE, (funcptr_t)Paillierkey_freectx },
	{ OSSL_FUNC_KEYMGMT_GEN_INIT, (funcptr_t)Paillierkey_gen_init },
	{ OSSL_FUNC_KEYMGMT_GEN, (funcptr_t)Paillierkey_gen },
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (funcptr_t)Paillierkey_clean },
	{ OSSL_FUNC_KEYMGMT_LOAD, (funcptr_t)Paillierkey_load },
	{ OSSL_FUNC_KEYMGMT_EXPORT, (funcptr_t)Paillierkey_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (funcptr_t)Paillierkey_export_type },
    { OSSL_FUNC_KEYMGMT_IMPORT,(funcptr_t)Paillierkey_import },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (funcptr_t)Paillierkey_import_types },
	{OSSL_FUNC_KEYMGMT_HAS,(funcptr_t)Paillierkey_has},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,(funcptr_t)Paillierkeygen_settable_params},
	{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,(funcptr_t)Paillierkeygen_set_params},
	{0,NULL}
	};




// //extern const OSSL_DISPATCH Paillier_encoder_publickey_PEM[];
static const OSSL_ALGORITHM Paillier_ciphers[] = { { "Paillier", "x.author=ranjith",
						    Paillier_functions},
						  { NULL, NULL, NULL } };
static const OSSL_ALGORITHM Paillierkey_operation[] = { { "Paillier", "x.author=ranjith",
						    Paillierkey_functions},
						  { NULL, NULL, NULL } };
static const OSSL_ALGORITHM Paillierkey_encoders[]={
	{"Paillier","provider=Paillier,output=pem,structure=PrivateKeyInfo",Paillierpriv_encoder_PEM},
    {"Paillier","provider=Paillier,output=pem,structure=SubjectPublicKeyInfo",Paillierpub_encoder_PEM},
	{NULL,NULL,NULL}};




const OSSL_ALGORITHM Paillierkey_decoders[]={
	 { "PEM", "provider=Paillier,input=pem", PaillierPEM_decoder_functions },
     { "DER", "provider=Paillier,input=der,structure=Paillier", PaillierDER_decoder_functions },
	{NULL,NULL,NULL}};


static const OSSL_ALGORITHM *
Paillier_prov_operation(void *vprovctx, int operation_id, int *no_cache)
{
	*no_cache = 0;
	
	switch (operation_id) {
	case OSSL_OP_ASYM_CIPHER:
		return Paillier_ciphers;
	case OSSL_OP_KEYMGMT:
	    return Paillierkey_operation;
	case  OSSL_OP_ENCODER:
	    return Paillierkey_encoders;
	case OSSL_OP_DECODER:
	    return Paillierkey_decoders;
	}

	return NULL;
}

static const OSSL_PARAM *Paillier_prov_gettable_params(void *provctx)
{
return gettable_params;
}
static int Paillier_prov_get_params(void *provctx, OSSL_PARAM *params)
{
	
	 OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, "name")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, "Paillier Provider");

    if ((p = OSSL_PARAM_locate(params, "version")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, "1.0.0");

	if ((p = OSSL_PARAM_locate(params, "status")) != NULL)
        OSSL_PARAM_set_utf8_ptr(p, "active");

    return 1;

}
static const OSSL_DISPATCH provider_functions[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION,
	  (funcptr_t)Paillier_prov_operation },
	  {OSSL_FUNC_PROVIDER_GET_PARAMS,(funcptr_t)Paillier_prov_get_params},
	  {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,(funcptr_t)Paillier_prov_gettable_params},
	{ 0, NULL }
};

OPENSSL_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
				      const OSSL_DISPATCH *in,
				      const OSSL_DISPATCH **out,
				      void **vprovctx)
{
	
	if ((*vprovctx = provider_ctx_new(core,in)) == NULL)
		return 0;
	*out = provider_functions;
	return 1;
}
