#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int main(void) {

//	// ------------------------ Test Encryption ------------------------
//	unsigned char iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//	unsigned char key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//
//	unsigned char inbuf[] = { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
//			0x61, 0x20, 0x74, 0x6F, 0x70, 0x20, 0x73, 0x65,
//			0x63, 0x72, 0x65, 0x74, 0x2E };
//	int inlen = sizeof(inbuf);
//	unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
//	int outlen = 0;
//
//
//	unsigned char outbuf2[1024 + EVP_MAX_BLOCK_LENGTH];
//	int outlen2 = 0;
//
//
//
//	// encrypt
//	do_crypt(inbuf, inlen, outbuf, &outlen, key, iv, 1);
//	// decrypt
//	do_crypt(outbuf, outlen, outbuf2, &outlen2, key, iv, 0);
//
//
//	print_buffer(outbuf2, outlen2);
//	printf("the sum is %i \n", outlen2);


//	// ------------------------ Test Hash ------------------------
//	char inbuf[] = {0x6D, 0x79, 0x20, 0x6E, 0x61, 0x6D, 0x65, 0x20, 0x69, 0x73, 0x20, 0x42, 0x69, 0x6C, 0x61, 0x6C};
//	int inlen = sizeof(inbuf);
//	char outbuf[16];
//	int* outlen;
//	calculate_hash(inbuf, inlen, outbuf, &outlen);
//	print_buffer(outbuf, outlen);



//	// ------------------------ Test HMAC ------------------------
//	unsigned char key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//	unsigned char inbuf[] = {0x6D, 0x79, 0x20, 0x6E, 0x61, 0x6D, 0x65, 0x20, 0x69, 0x73, 0x20, 0x42, 0x69, 0x6C, 0x61, 0x6C};
//	int inlen = sizeof(inbuf);
//	unsigned char outbuf[1024];
//	int outlen = 0;
//	calculate_hmac(inbuf, inlen, outbuf, &outlen, key);
//	print_buffer(outbuf, outlen);


	return 0;
}

int do_crypt(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen,
		unsigned char key[], unsigned char iv[], int do_encrypt) {
	int outlen1, outlen2;
	EVP_CIPHER_CTX ctx;

	/* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	/* Now we can set key and IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	if (!EVP_CipherUpdate(&ctx, outbuf, &outlen1, inbuf, inlen)) {
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	if (!EVP_CipherFinal_ex(&ctx, outbuf + outlen1, &outlen2)) {
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);
	*outlen = outlen1 + outlen2;
	return 1;
}

calculate_hmac(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen, unsigned char key[]) {
	HMAC(EVP_sha256(), key, 16, inbuf, inlen, outbuf, outlen);
}

void calculate_hash(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("md5");
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, inbuf, inlen);
	EVP_DigestFinal_ex(mdctx, outbuf, outlen);
	EVP_MD_CTX_destroy(mdctx);
	/* Call this once before exit. */
	EVP_cleanup();
}

void print_buffer(unsigned char buf[], int buflen) {
	int i;
	printf("\n--------------\n");
	for (i = 0; i < buflen; i++) {
		if (i % 16 == 0) {
			printf("\n");
		} else if (i > 0) {
			printf(":");
		}
		printf("%02X", buf[i]);
	}
	printf("\n--------------\n");
}
