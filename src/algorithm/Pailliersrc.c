#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>

#include "Paillier.h"

int param_generation_function(keyctx *keydata,int nbits,BN_GENCB *cb){
    int ret = -1;
	
	
	BN_CTX *ctx=BN_CTX_new();
	if (ctx == NULL)
		goto err;
	BN_CTX_start(ctx);
	
	
	if (keydata->n == NULL && ((keydata->n = BN_new()) == NULL))
		goto err;
	if (keydata->g == NULL && ((keydata->g = BN_new()) == NULL))
		goto err;

    if (!BN_generate_prime_ex2(keydata->n, nbits, 0, NULL, NULL, cb, ctx))
		goto err;
	
	if (!BN_copy(keydata->g, keydata->n)) {
    // Handle error
    fprintf(stderr, "Failed to copy n to g\n");
    // Appropriate error handling
    goto err; // or handle the error as needed
}

if (!BN_add_word(keydata->g, 1)) {
    // Handle error
    fprintf(stderr, "Failed to add 1 to g\n");
    // Appropriate error handling
    goto err; // or handle the error as needed
}
    keydata->dirty_cnt++;
	ret = 1;
err:
	if (ret == -1) {
		ret = 0;
	}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
	}

OSSL_LIB_CTX *getlibctx(void *provctx){
	providerctx *pctx=provctx;
	if(pctx!=NULL){
		return pctx->libctx;
	}
	return NULL;
}