#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096


int do_aes_128_cbc_crypt(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen,
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

//calculate_sha256_hmac(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen, unsigned char key[]) {
//	HMAC(EVP_sha256(), key, 16, inbuf, inlen, outbuf, outlen);
//}

void calculate_md5_hash(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen) {
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

void calculate_sha256_hash(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha256");
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, inbuf, inlen);
	EVP_DigestFinal_ex(mdctx, outbuf, outlen);
	EVP_MD_CTX_destroy(mdctx);
	/* Call this once before exit. */
	EVP_cleanup();
}

void calculate_sha256_hash_with_salt(unsigned char salt[],
		int saltlen, unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen) {
	unsigned char new_inbuf[BUFFER_SIZE];
	int index = 0;
	memcpy(&new_inbuf[index], &salt[0], saltlen);
	index += saltlen;
	memcpy(&new_inbuf[index], &inbuf[0], inlen);
	index += inlen;
	int new_inlen = index;
	calculate_sha256_hash(new_inbuf, new_inlen, outbuf, outlen);
}


void print_buffer(unsigned char buf[], int buflen) {
	int i;
	printf("------------------");
	for (i = 0; i < buflen; i++) {
		if (i % 16 == 0) {
			printf("\n");
		} else if (i > 0) {
			printf(":");
		}
		printf("%02X", buf[i]);
	}
	printf("\n------------------\n \n");
}

void print_buffer_with_title(unsigned char buf[], int buflen, char* title) {
	int i;
	printf("---------- %s ----------", title);
	for (i = 0; i < buflen; i++) {
		if (i % 16 == 0) {
			printf("\n");
		} else if (i > 0) {
			printf(":");
		}
		printf("%02X", buf[i]);
	}
	printf("\n---------- %s ----------\n \n", title);
}

int compare_buffers(unsigned char buf1[], unsigned char buf2[], int buflen) {
	int result = 1;  // 0 means false, 1 means true
	int i;
	for (i = 0; i < buflen; i++) {
		if (buf1[i] != buf2[i]) {
			result = 0;
			return result;
		}
	}
	return result;
}

void generate_random_number(unsigned char generated_number[], int len){
	FILE* random = fopen("/dev/urandom", "r");
	fread(generated_number, sizeof(unsigned char)*len, 1, random);
	fclose(random);
}
int find_char_in_string(char* str, char c){
	int result = -1;
	const char *ptr = strchr(str, c);
	if(ptr) {
	   result = ptr - str;
	}
	return result;
}

void convert_hex_string_to_bytes_array (char* str, unsigned char buf[]){
	const char *pos = str;
	size_t count = 0;
	int bufln = strlen(str) / 2 ;
	for (count = 0; count < bufln; count++) {
		char element_buf[5] = {'0', 'x', pos[0], pos[1], 0};
		buf[count] = strtol(element_buf, NULL, 0);
		pos += 2 * sizeof(char);
	}
}

int is_valid_ip(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int strcmp_ignore_case(char const *a, char const *b)
{
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a)
            return d;
    }
    return -1;
}

void convert_long_to_bytes(unsigned long n, unsigned char bytes[]){
    bytes[3] = (n >> 24) & 0xFF;
    bytes[2] = (n >> 16) & 0xFF;
    bytes[1] = (n >> 8) & 0xFF;
    bytes[0] = n & 0xFF;
}

unsigned long convert_bytes_to_long(unsigned char bytes[]){
    unsigned long n = *(int *)bytes;
    return n;
}

