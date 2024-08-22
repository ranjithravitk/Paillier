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

int serialize_Paillier_ciphertext_readable(BIGNUM *c1,unsigned char *out, size_t *out_len) {
    unsigned char *c1_bin;
    int c1_len;
    size_t required_len;

    // Calculate the binary length of BIGNUMs
    c1_len = BN_num_bytes(c1);

    // Allocate memory for binary representations
    c1_bin = (unsigned char *)OPENSSL_malloc(c1_len);
   
    if (c1_bin == NULL) {
        return 0;
    }

    // Convert BIGNUMs to binary
    BN_bn2bin(c1, c1_bin);

    // Calculate the required buffer size
    // Format: "c1_bin|c2_bin"
    required_len = (c1_len * 2); // Each byte -> 2 hex chars, 1 delimiter

    // If out is NULL, return the required size and exit
    if (out == NULL) {
        *out_len = required_len;
        OPENSSL_free(c1_bin);
        return 1;
    }

    // Check if the provided buffer is large enough
    if (*out_len < required_len) {
        OPENSSL_free(c1_bin);
        return 0;
    }

    unsigned char *ptr = out;

    // Write c1_bin in hex format
    for (int i = 0; i < c1_len; i++) {
        snprintf((char *)ptr, 3, "%02x", c1_bin[i]);
        ptr += 2;
    }

    *out_len = required_len;

    OPENSSL_free(c1_bin);

    return 1;
}

int calculate_L(BIGNUM *result, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *x_minus_one = BN_new();
    BIGNUM *one = BN_new();
    int ret = 0;

    if (!x_minus_one || !one) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Set one to 1
    if (!BN_one(one)) {
        fprintf(stderr, "Error: Setting one failed\n");
        goto cleanup;
    }

    // Calculate x - 1
    if (!BN_sub(x_minus_one, x, one)) {
        fprintf(stderr, "Error: Calculating x-1 failed\n");
        goto cleanup;
    }

    // Calculate (x-1) / n
    if (!BN_div(result, NULL, x_minus_one, n, ctx)) {
        fprintf(stderr, "Error: Division failed\n");
        goto cleanup;
    }

    ret = 1;  // Success

cleanup:
    BN_free(x_minus_one);
    BN_free(one);
    return ret;
}
int hex_to_bin(const char *hex, unsigned char *bin, int bin_len) {
    for (int i = 0; i < bin_len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bin[i]);
    }
    return 1;
}

int deserialize_Paillier_ciphertext_readable(const unsigned char *in, size_t in_len, BIGNUM **c1) {
    // Check input parameters
    if (in == NULL || c1 == NULL || in_len == 0) {
        return 0;
    }

    // Allocate memory for the binary data
    size_t bin_len = in_len / 2;
    unsigned char *bin_data = (unsigned char *)OPENSSL_malloc(bin_len);
    if (bin_data == NULL) {
        return 0;
    }

    // Convert hex string to binary using the provided hex_to_bin function
    if (!hex_to_bin((const char *)in, bin_data, bin_len)) {
        OPENSSL_free(bin_data);
        return 0;
    }

    // Create BIGNUM from binary data
    *c1 = BN_bin2bn(bin_data, bin_len, NULL);
    
    // Free the temporary binary buffer
    OPENSSL_free(bin_data);

    // Check if BIGNUM creation was successful
    if (*c1 == NULL) {
        return 0;
    }

    return 1;
}

int calculate_m(BIGNUM *m, const BIGNUM *c, const BIGNUM *lambda, const BIGNUM *n, const BIGNUM *mu) {
    BIGNUM *n_squared = BN_new();
    BIGNUM *c_lambda = BN_new();
    BIGNUM *L_result = BN_new();
    BIGNUM *temp = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int ret = 0;

    if (!n_squared || !c_lambda || !L_result || !temp || !ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Calculate n^2
    if (!BN_sqr(n_squared, n, ctx)) {
        fprintf(stderr, "Error: Calculating n^2 failed\n");
        goto cleanup;
    }

    // Calculate c^λ mod n^2
    if (!BN_mod_exp(c_lambda, c, lambda, n_squared, ctx)) {
        fprintf(stderr, "Error: Calculating c^λ mod n^2 failed\n");
        goto cleanup;
    }

    // Calculate L(c^λ mod n^2)
    if (!calculate_L(L_result, c_lambda, n, ctx)) {
        fprintf(stderr, "Error: Calculating L failed\n");
        goto cleanup;
    }

    // Calculate L(c^λ mod n^2) * μ
    if (!BN_mod_mul(temp, L_result, mu, n, ctx)) {
        fprintf(stderr, "Error: Multiplication failed\n");
        goto cleanup;
    }

    // Final result: m = L(c^λ mod n^2) * μ mod n
    if (!BN_nnmod(m, temp, n, ctx)) {
        fprintf(stderr, "Error: Final modulo operation failed\n");
        goto cleanup;
    }

    ret = 1;  // Success

cleanup:
    BN_free(n_squared);
    BN_free(c_lambda);
    BN_free(L_result);
    BN_free(temp);
    BN_CTX_free(ctx);
    return ret;
}