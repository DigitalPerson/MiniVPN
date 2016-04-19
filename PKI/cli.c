/* cli.cpp  -  Minimal ssleay client for Unix
 30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
 Simplified to be even more minimal
 12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CACERT "ca.crt"
#define SERVER_COMMON_NAME "MiniVPNServer"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1111

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main() {
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	char buf[4096];
	SSL_METHOD *meth;

	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);
	CHK_NULL(ctx);

	CHK_SSL(err);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);


	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */

	sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(SERVER_IP);
	sa.sin_port = htons(SERVER_PORT);

	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
	CHK_ERR(err, "connect");


	/* ----------------------------------------------- */
	/* Now we have TCP connection. Start SSL negotiation. */

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);
	CHK_SSL(err);

	if (verify_common_name(ssl, SERVER_COMMON_NAME) == 0) {
		printf("Server common name can not be verified\n");
		exit(1);
	}


	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	char key[] = "my secret keeyyyyyyyy";
	int key_len = sizeof(key);

	err = SSL_write(ssl, key, key_len);
	CHK_SSL(err);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("Got %d chars:'%s'\n", err, buf);
	SSL_shutdown(ssl); /* send SSL/TLS close_notify */

	/* Clean up. */

	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

int verify_common_name(SSL* ssl, char* server_common_name) {
	int result = 1;
	// Get server's certificate (note: beware of dynamic allocation)
	X509* server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	X509_NAME *subject_name = X509_get_subject_name(server_cert);
	int index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
	X509_NAME_ENTRY *subject_name_entry = X509_NAME_get_entry(subject_name,
			index);
	ASN1_STRING *subject_name_asn1 = X509_NAME_ENTRY_get_data(
			subject_name_entry);
	char* fetched_common_name = ASN1_STRING_data(subject_name_asn1);
	CHK_NULL(fetched_common_name);
	if (strcmp(server_common_name, fetched_common_name) != 0) {
		result = 0;
	}
	OPENSSL_free(fetched_common_name);
	return result;
}
