#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>

#include "Paillier.h"

int param_generation_function(keyctx *keydata,int nbits,int pbits,int qbits,BN_GENCB *cb){
    int ret = -1;
	
	
	BN_CTX *ctx=BN_CTX_new();
	if (ctx == NULL)
		goto err;
	BN_CTX_start(ctx);
	
	if (keydata->p == NULL && ((keydata->p = BN_new()) == NULL))
		goto err;
	if (keydata->q == NULL && ((keydata->q = BN_new()) == NULL))
		goto err;
	if (keydata->n == NULL && ((keydata->n = BN_new()) == NULL))
		goto err;
	if (keydata->g == NULL && ((keydata->g = BN_new()) == NULL))
		goto err;

    if (!BN_generate_prime_ex2(keydata->p, pbits, 0, NULL, NULL, cb, ctx))
		goto err;
	if (!BN_generate_prime_ex2(keydata->q, qbits, 0, NULL, NULL, cb, ctx))
		goto err;
	if (BN_mul(keydata->n, keydata->p, keydata->q, ctx) != 1) {
    // Handle error
    fprintf(stderr, "BN_mul failed\n");
    // Clean up and return or exit
}

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
int Paillier_priv_key_gen(keyctx *keydata, BN_GENCB *cb){
	int ret=-1;
	BIGNUM *t1, *t2,*one;
	BN_CTX *ctx=BN_CTX_new();

	if (ctx == NULL)
		goto err;
	BN_CTX_start(ctx);
	t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
	one = BN_CTX_get(ctx);
	if (t2 == NULL||t1==NULL || one==NULL || !BN_one(one))
		goto err;
	if (keydata->lambda == NULL && ((keydata->lambda = BN_new()) == NULL))
		goto err;
	if (keydata->mu== NULL && ((keydata->mu = BN_new()) == NULL))
		goto err;
	if (BN_sub(t1, keydata->p, one) != 1) {
    // Handle error
    fprintf(stderr, "BN_sub failed\n");
    // Clean up and return or exit
	}
	if (BN_sub(t2, keydata->q, one) != 1) {
		// Handle error
		fprintf(stderr, "BN_sub failed\n");
		// Clean up and return or exit
	}
	if (BN_mul(keydata->lambda, t1, t2, ctx) != 1) {
    // Handle error
    fprintf(stderr, "BN_mul failed\n");
    // Clean up and return or exit
	}
	if (!BN_mod_inverse(keydata->mu, keydata->lambda, keydata->n, ctx)) {
        fprintf(stderr, "Error: BN_mod_inverse failed\n");
        goto err;
    }


ret = 1;
err:
	if (ret == -1) {
		ret = 0;
	}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;

}