#include <openssl/hmac.h>


calculate_sha256_hmac(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen, unsigned char key[]) {
	HMAC(EVP_sha256(), key, 16, inbuf, inlen, outbuf, outlen);
}

