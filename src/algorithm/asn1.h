#ifndef PAILLIER_ASN1_H
#define PAILLIER_ASN1_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct {
    ASN1_INTEGER *n;
	ASN1_INTEGER *g;
	ASN1_INTEGER *lambda;
    ASN1_INTEGER *mu;
} PAILLIER_PRIVATEKEY;

typedef struct {
    ASN1_INTEGER *n;
    ASN1_INTEGER *g;
} PAILLIER_PUBLICKEY;

DECLARE_ASN1_FUNCTIONS(PAILLIER_PRIVATEKEY)
DECLARE_ASN1_FUNCTIONS(PAILLIER_PUBLICKEY)
#endif // PAILLIER_ASN1_H