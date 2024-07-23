#include "Paillier.h"
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
#include "asn1.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/param_build.h>
#include <openssl/bio.h>

//decoder
static OSSL_FUNC_decoder_newctx_fn Paillierkey_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn Paillierkey_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn Paillier_decode_key;
static OSSL_FUNC_decoder_export_object_fn PaillierPEM_decoder_export;
static OSSL_FUNC_decoder_export_object_fn PaillierDER_decoder_export;

static BIGNUM *asn1_integer_to_bn(const ASN1_INTEGER *ai)
{
    BIGNUM *bn = BN_new();
    if (bn == NULL)
        return NULL;
    if (!ASN1_INTEGER_to_BN(ai, bn)) {
        BN_free(bn);
        return NULL;
    }
    return bn;
}
int read_der_from_bio(BIO *bio, unsigned char **out_data, long *out_len)
{
    long data_len;
    unsigned char *der_data;
    int bytes_read;

    // Get the length of data in the BIO
    data_len = BIO_get_mem_data(bio, NULL);
    if (data_len <= 0) {
        return 0;  // No data or error
    }

    // Allocate buffer
    der_data = OPENSSL_malloc(data_len);
    if (der_data == NULL) {
        return 0;  // Memory allocation failed
    }

    // Read data from BIO
    bytes_read = BIO_read(bio, der_data, data_len);
    if (bytes_read <= 0) {
        OPENSSL_free(der_data);
        return 0;  // Read failed or EOF
    }

    *out_data = der_data;
    *out_len = bytes_read;

    return 1;  // Success
}
static int Paillier_decode_key(void *ctx, OSSL_CORE_BIO *in, int selection, OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    Paillier_DECODER_CTX *dctx = ctx;
    BIO *bin = NULL;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;
    int ret = 1;
    int object_type;
    struct key_data *kdata = NULL;
    OSSL_PARAM params[3];
    bin = BIO_new_from_core_bio(dctx->libctx, in);
    if (bin == NULL)
        goto err;
 
    if (!PEM_read_bio(bin, &name, &header, &data, &len)){
        goto err;
    }
   

    if (strcmp(name, "Paillier PRIVATE KEY") == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      data, len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)"Paillier", 0);
    
        params[3] = OSSL_PARAM_construct_end();
       ret=data_cb(params,data_cbarg);
          
       
}
     else if (strcmp(name, "Paillier PUBLIC KEY") == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      data, len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)"Paillier", 0);
    
        params[3] = OSSL_PARAM_construct_end();
       ret=data_cb(params,data_cbarg);
    } else {
        goto err;
    }

  // data_cb

    

err:
    OPENSSL_free(name);
    OPENSSL_free(header);
    BIO_free(bin);
  
    return ret;
}
static void *
Paillierkey_decoder_newctx(void *provctx)
{
    providerctx *cprov = provctx;
    Paillier_DECODER_CTX *ectx = OPENSSL_zalloc(sizeof(Paillier_DECODER_CTX));

    if (ectx == NULL)
        return NULL;

    ectx->core = cprov->core_handle;
    ectx->libctx = cprov->libctx;
    return ectx;
}

static void
Paillierkey_decoder_freectx(void *ctx)
{
    Paillier_DECODER_CTX *ectx = ctx;

    if (ectx == NULL)
        return;

    OPENSSL_clear_free(ectx, sizeof(Paillier_DECODER_CTX));
}
// static int PaillierPEM_decoder_export(void *ctx,
//                                       const void *objref, size_t objref_sz,
//                                       OSSL_CALLBACK *export_cb,
//                                       void *export_cbarg){

// Paillier_DECODER_CTX *vctx=ctx;
//  keyctx *keydata;
//  if (objref_sz == sizeof(keydata)) {
//         /* The contents of the reference is the address to our object */
//         keydata = *(void **)objref;
// return Paillierkey_export(keydata,vctx->selection,export_cb,export_cbarg);
//  }
// return 1;
// }
const OSSL_DISPATCH PaillierPEM_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (funcptr_t)Paillierkey_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (funcptr_t)Paillierkey_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (funcptr_t)Paillier_decode_key },
   // { OSSL_FUNC_DECODER_EXPORT_OBJECT, (funcptr_t)PaillierPEM_decoder_export },
    { 0, NULL }
};


static int PaillierDER_decode_key(void *ctx, OSSL_CORE_BIO *in, int selection, OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    Paillier_DECODER_CTX *dctx = ctx;
    unsigned char *der_data;
    long der_len;
    struct key_data *kdata = NULL;
    PAILLIER_PRIVATEKEY *pkey=NULL;
    unsigned char *x_buf = NULL, *p_buf = NULL, *g_buf = NULL;
    int x_len = 0, p_len = 0, g_len = 0;
    int object_type;
    BIO *bin = NULL;
    OSSL_PARAM params[4];
    bin = BIO_new_from_core_bio(dctx->libctx, in);
    int ret=1;
    if (bin == NULL)
        goto err;

    if (read_der_from_bio(bin, &der_data, &der_len)) {
    kdata = OPENSSL_zalloc(sizeof(*kdata));
    if (kdata == NULL)
        goto err;
    if(selection==OSSL_KEYMGMT_SELECT_ALL){
     Paillier_PRIVATEKEY *privkey = d2i_Paillier_PRIVATEKEY(NULL, (const unsigned char **)&der_data, der_len);
        if (privkey == NULL)
            goto err;

        kdata->x = asn1_integer_to_bn(privkey->x);
        kdata->p=asn1_integer_to_bn(privkey->p);
        kdata->g=asn1_integer_to_bn(privkey->g);
        kdata->y=asn1_integer_to_bn(privkey->y);
        if (kdata->x == NULL ||kdata->p==NULL || kdata->g==NULL|| kdata->y==NULL)
            goto err;

        kdata->selections |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        // kdata->provctx.core_handle=dctx->core;
        // kdata->provctx->libctx=dctx->libctx;
        kdata->prime_len=BN_num_bits(kdata->p);
        kdata->x_key_size=BN_num_bits(kdata->x);
        kdata->y_key_size=BN_num_bits(kdata->y);
        kdata->algo_name="Paillier";
        object_type=OSSL_OBJECT_PKEY;
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "Paillier", 0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &kdata, sizeof(kdata));
        params[3] = OSSL_PARAM_construct_end();
        ret=data_cb(params,data_cbarg);
        Paillier_PRIVATEKEY_free(privkey);
    }
    if(selection==(OSSL_KEYMGMT_SELECT_PUBLIC_KEY|OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)){
        Paillier_PUBLICKEY *pubkey = d2i_Paillier_PUBLICKEY(NULL, (const unsigned char **)&der_data, der_len);
        if (pubkey == NULL)
            goto err;

        kdata->p=asn1_integer_to_bn(pubkey->p);
        kdata->g=asn1_integer_to_bn(pubkey->g);
        kdata->y=asn1_integer_to_bn(pubkey->y);
        if (kdata->p==NULL || kdata->g==NULL|| kdata->y==NULL)
            goto err;

        kdata->selections = OSSL_KEYMGMT_SELECT_PUBLIC_KEY|OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
        // kdata->provctx.core_handle=dctx->core;
        // kdata->provctx->libctx=dctx->libctx;
        kdata->prime_len=BN_num_bits(kdata->p);
        kdata->y_key_size=BN_num_bits(kdata->y);
        kdata->algo_name="Paillier";
        object_type=OSSL_OBJECT_PKEY;
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "Paillier", 0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &kdata, sizeof(kdata));
        params[3] = OSSL_PARAM_construct_end();
        ret=data_cb(params,data_cbarg);
        Paillier_PUBLICKEY_free(pubkey);

    }

}
err:
  OPENSSL_free(x_buf);
    OPENSSL_free(p_buf);
    OPENSSL_free(g_buf);
return ret;
}
// static int PaillierDER_decoder_export(void *ctx,
//                                       const void *objref, size_t objref_sz,
//                                       OSSL_CALLBACK *export_cb,
//                                       void *export_cbarg){
// Paillier_DECODER_CTX *vctx=ctx;
//  keyctx *keydata;
//  if (objref_sz == sizeof(keydata)) {
//         /* The contents of the reference is the address to our object */
//         keydata = *(void **)objref;
// return Paillierkey_export(keydata,vctx->selection,export_cb,export_cbarg);
//  }
// return 1;
// }
const OSSL_DISPATCH PaillierDER_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (funcptr_t)Paillierkey_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (funcptr_t)Paillierkey_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (funcptr_t)PaillierDER_decode_key },
   // { OSSL_FUNC_DECODER_EXPORT_OBJECT, (funcptr_t)PaillierDER_decoder_export },
    { 0, NULL }
};
