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
#include "Paillier.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/param_build.h>
#include <openssl/bio.h>
#include "asn1.h"
static OSSL_FUNC_encoder_newctx_fn Paillier_encoder_newctx;
static OSSL_FUNC_encoder_freectx_fn Paillier_encoder_freectx;
static OSSL_FUNC_encoder_encode_fn Paillierpriv_encode_key;
static OSSL_FUNC_encoder_encode_fn Paillierpub_encode_key;
// Helper function to convert BIGNUM to ASN1_INTEGER
static ASN1_INTEGER *bn_to_asn1_integer(const BIGNUM *bn)
{
    ASN1_INTEGER *ai = ASN1_INTEGER_new();
    if (ai == NULL)
        return NULL;
    if (!BN_to_ASN1_INTEGER(bn, ai)) {
        ASN1_INTEGER_free(ai);
        return NULL;
    }
    return ai;
}

static int Paillierpriv_encode_key(void *vctx, OSSL_CORE_BIO *out, const void *key, const OSSL_PARAM obj_abstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    const struct key_data *kdata = key;
    Paillier_ENCODER_CTX *ectx=vctx;
    unsigned char *der = NULL;
    int der_len;
    BIO *bout = NULL;
    int ret = 0;
    Paillier_PRIVATEKEY *privkey=NULL;
    Paillier_PUBLICKEY *pubkey =NULL;
    if(kdata->selections == OSSL_KEYMGMT_SELECT_KEYPAIR)
    {
    privkey = Paillier_PRIVATEKEY_new();
    if (privkey == NULL)
        return 0;

    privkey->x = bn_to_asn1_integer(kdata->x);
	privkey->g = bn_to_asn1_integer(kdata->g);
	privkey->p=bn_to_asn1_integer(kdata->p);
    privkey->y=bn_to_asn1_integer(kdata->y);
    if (privkey->x == NULL||privkey->g==NULL||privkey->p==NULL || privkey->y==NULL)
        goto err;
	

    der_len = i2d_Paillier_PRIVATEKEY(privkey, &der);
    if (der_len < 0)
        goto err;

    bout = BIO_new_from_core_bio(ectx->libctx, out);
    if (bout == NULL)
        goto err;

    if (PEM_write_bio(bout, "Paillier PRIVATE KEY", NULL, der, der_len) <= 0)
        goto err;
    ret = 1;
    }
    if(selection==OSSL_KEYMGMT_SELECT_PUBLIC_KEY){
     pubkey=Paillier_PUBLICKEY_new();
      if (pubkey == NULL)
        return 0;

    pubkey->y = bn_to_asn1_integer(kdata->y);
    if (pubkey->y == NULL)
        goto err;

    der_len = i2d_Paillier_PUBLICKEY(pubkey, &der);
    if (der_len < 0)
        goto err;

    bout = BIO_new_from_core_bio(ectx->libctx, out);
    if (bout == NULL)
        goto err;

    if (PEM_write_bio(bout, "Paillier PUBLIC KEY", "", der, der_len) <= 0)
        goto err;
     ret=1;
    }

    

err:
    OPENSSL_free(der);
    BIO_free(bout);
    Paillier_PRIVATEKEY_free(privkey);
    Paillier_PUBLICKEY_free(pubkey);


    return ret;
}




static void *
Paillier_encoder_newctx(void *provctx)
{
    providerctx *cprov = provctx;
    Paillier_ENCODER_CTX *ectx = OPENSSL_zalloc(sizeof(Paillier_ENCODER_CTX));

    if (ectx == NULL)
        return NULL;

    ectx->core = cprov->core_handle;
    ectx->libctx = cprov->libctx;
    return ectx;
}

static void
Paillier_encoder_freectx(void *ctx)
{
    Paillier_ENCODER_CTX *ectx = ctx;

    if (ectx == NULL)
        return;

    OPENSSL_clear_free(ectx, sizeof(Paillier_ENCODER_CTX));
}
static int Paillierpub_encode_key(void *vctx, OSSL_CORE_BIO *out, const void *key, const OSSL_PARAM obj_abstract[], int selection,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    const struct key_data *kdata = key;
    Paillier_ENCODER_CTX *ectx=vctx;
    unsigned char *der = NULL;
    int der_len;
    BIO *bout = NULL;
    int ret = 0;
    Paillier_PRIVATEKEY *privkey=NULL;
    Paillier_PUBLICKEY *pubkey =NULL;

    pubkey=Paillier_PUBLICKEY_new();
      if (pubkey == NULL)
        return 0;

    pubkey->y = bn_to_asn1_integer(kdata->y);
    pubkey->p = bn_to_asn1_integer(kdata->p);
    pubkey->g = bn_to_asn1_integer(kdata->g);
    if (pubkey->y == NULL||pubkey->p == NULL||pubkey->g == NULL)
        goto err;

    der_len = i2d_Paillier_PUBLICKEY(pubkey, &der);
    if (der_len < 0)
        goto err;

    bout = BIO_new_from_core_bio(ectx->libctx, out);
    if (bout == NULL)
        goto err;

    if (PEM_write_bio(bout, "Paillier PUBLIC KEY", "", der, der_len) <= 0)
        goto err;
     ret=1;
    

    

err:
    OPENSSL_free(der);
    BIO_free(bout);
    Paillier_PRIVATEKEY_free(privkey);
    Paillier_PUBLICKEY_free(pubkey);


    return ret;
}
const OSSL_DISPATCH Paillierpriv_encoder_PEM[] = {
     { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))Paillier_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))Paillier_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))Paillierpriv_encode_key },
    { 0, NULL }
};
const OSSL_DISPATCH Paillierpub_encoder_PEM[] = {
     { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))Paillier_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))Paillier_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))Paillierpub_encode_key },
    { 0, NULL }
};