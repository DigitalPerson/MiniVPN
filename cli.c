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
//#include "crypto.c"

#define CACERT "ca.crt"
#define SERVER_COMMON_NAME "test.MiniVPNServer.com"
#define SERVER_IP "10.0.2.13"
#define SERVER_PORT 1111
#define KEY_LEN 16
#define BUFFER_SIZE 4096
#define BUFFER_SIZE_SMALL 50
#define SEPARATOR ":"
#define SEPARATOR_LEN 1

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int client() {
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	char buf[BUFFER_SIZE];
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

	// SSL_connect is reposnisible for verifying:
	// 1. The effective date
	// 2. Whether the server certificate is signed by an authorized CA
	// 4. Whether the server is indeed the machine that the client wants to talk to
	// (as opposed to a spoofed machine) (ie: server.crt and server.key matches). This also gets checked by the the server code.
	// Note that the function does not verifiy the common name

	err = SSL_connect(ssl);
	CHK_SSL(err);

	if (verify_common_name(ssl, SERVER_COMMON_NAME) == 0) {
		printf("Server common name can not be verified\n");
		exit(1);
	}


	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	// Generate a secret key for the UDP tunnel encryption
	unsigned char key[KEY_LEN];
	generate_random_number(key, KEY_LEN);


	// Get username and password from the user
//	char username [] = "bilalo89";
//	char password [] = "bilal";
	char username [BUFFER_SIZE_SMALL];
	printf("Enter username: ");
	gets(username);
	char password[BUFFER_SIZE_SMALL];
	printf("Enter password: ");
	gets(password);
	int username_len = strlen(username);
	int password_len = strlen(password);



	// Put everything together in one buffer to send it to the server
	int index = 0;
	memcpy(&buf[index], &key[0], KEY_LEN);
	index += KEY_LEN;
	memcpy(&buf[index], &username[0], username_len);
	index += username_len;
	memcpy(&buf[index], &SEPARATOR[0], SEPARATOR_LEN);
	index += SEPARATOR_LEN;
	memcpy(&buf[index], &password[0], password_len);
	index += password_len;
	int buf_len = index;



	err = SSL_write(ssl, buf, buf_len);
	CHK_SSL(err);
	memset(buf, 0, BUFFER_SIZE);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);
	buf[err] = '\0';
	printf("%s\n", buf);
	memset(buf, 0, BUFFER_SIZE);

	SSL_shutdown(ssl); /* send SSL/TLS close_notify */

	/* Clean up. */

	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);


	return 0;
}

int verify_common_name(SSL* ssl, char* fetched_server_common_name) {
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
	char* cert_server_common_name = ASN1_STRING_data(subject_name_asn1);
	CHK_NULL(cert_server_common_name);

	// get the last part of fetched server common name
	int fetched_server_common_name_ln = strlen(fetched_server_common_name);
	int cert_server_common_name_ln = strlen(cert_server_common_name);
	const char *last_part_of_fetched_server_common_name = &fetched_server_common_name[fetched_server_common_name_ln - cert_server_common_name_ln];

	// compare the last part of fetched server common name with the name that we got from the certificate
	if (strcmp(last_part_of_fetched_server_common_name, cert_server_common_name) != 0) {
		result = 0;
	}
	OPENSSL_free(cert_server_common_name);
	return result;
}
