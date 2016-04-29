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
#include <sys/types.h>
#include <signal.h>
#include <termios.h>

/* Define HOME to be dir for key and cert files... */
#define HOME "./files/"
/* Make these what you want for cert & key files */
#define CACERT HOME "ca.crt"

#define SERVER_PORT 1111
#define KEY_LEN 16
#define BUFFER_SIZE 4096
#define BUFFER_SIZE_SMALL 50
#define BUFFER_SIZE_MESSAGE 100
#define SEPARATOR ":"
#define SEPARATOR_LEN 1

#define CHK_NULL(x) if ((x)==NULL) {exit (1);}
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int startTCPClient(int pipe_fd[], int child_pid, char* server_ip, char* server_hostname) {
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL* ssl;
	char buf[BUFFER_SIZE];
	SSL_METHOD *meth;
	int index = 0;


	/* SSL preliminaries. */
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
	sa.sin_addr.s_addr = inet_addr(server_ip);
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


	/* --------------------------------------------------- */
	/* DATA EXCHANGE - Send a message and receive a reply. */

	int common_name_verified = verify_common_name(ssl, server_hostname);



	// ---------------------- Send a packet ----------------------
	// if common name is okay send a packet with the login info and the generated key
	// otherwise send authentication failed message and end everything
	if (common_name_verified == 0) {
		printf("Server common name cannot be verified\n");
		// Send authentication failed message to the server and kill the parent and the child processes
		buf[0] = 0;
		buf[1] = 0;
		err = SSL_write(ssl, buf, 2);
		CHK_SSL(err);
		kill(child_pid, SIGKILL);
		exit(1);

	}

	// If the common name is verified, send a packet with the login info and the generated key

	// Generate a secret key for the UDP tunnel encryption
	unsigned char key[KEY_LEN];
	generate_random_number(key, KEY_LEN);

	// Get username and password from the user
	char username[BUFFER_SIZE_SMALL];
	printf("Enter username: ");
	gets(username);
	char password[BUFFER_SIZE_SMALL];
	printf("Enter password: ");

	//gets(password);
	get_password(password);
	printf("\n ");

	int username_len = strlen(username);
	int password_len = strlen(password);

	// Put everything together in one buffer to send it to the server
	index = 0;
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
	// Zero out the login info
	memset(username, 0, username_len);
	memset(password, 0, password_len);
	memset(buf, 0, BUFFER_SIZE);

	// ---------------------- Receive a packet ----------------------
	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);

	// If we got authentication success message (server was able to verify the client user & pass)
	if (buf[0] == 0 && buf[1] == 1) {
		printf("TCP connection established. \n");
	} else {
		printf("Wrong username or password. \n");
		kill(child_pid, SIGKILL);
		exit(1);
	}

	memset(buf, 0, BUFFER_SIZE);


	// Send the key to the pipe (UDP process)
	index = 0;
	buf[0] = 1;
	index++;
	memcpy(&buf[index], &key[0], KEY_LEN);
	index += KEY_LEN;
	write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);


	// Go to infinite loop to listen to the user control commands and send them to the server
	sleep(1);
	char* command[BUFFER_SIZE_SMALL];
	while (1) {
		printf("Enter command: ");
		gets(command);

		// If it is an update key command
		if (strcmp(command, "1") == 0) {
			printf("Updating key \n");

			// Generate new random key
			memset(buf, 0, BUFFER_SIZE);
			generate_random_number(key, KEY_LEN);

			// Send the new key to the server through the TCP tunnel
			index = 0;
			buf[0] = 1;
			index++;
			memcpy(&buf[index], &key[0], KEY_LEN);
			index += KEY_LEN;
			err = SSL_write(ssl, buf, BUFFER_SIZE_MESSAGE);
			CHK_SSL(err);

			// Send the new key to the pipe (to the UDP program)
			index = 0;
			buf[0] = 1;
			index++;
			memcpy(&buf[index], &key[0], KEY_LEN);
			index += KEY_LEN;
			write(pipe_fd[1], buf, BUFFER_SIZE_MESSAGE);


		// If it is a shutdown command
		} else if (strcmp(command, "2") == 0) {
			printf("Sending shutdown \n");
			buf[0] = 2;
			err = SSL_write(ssl, buf, BUFFER_SIZE_MESSAGE);
			CHK_SSL(err);
			kill(child_pid, SIGKILL);
			break;
		} else {
			printf("Please enter: \n1: to update the key \n2: to shutdown \n");
		}

	}

	SSL_shutdown(ssl); /* send SSL/TLS close_notify */

	/* Clean up. */

	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

int verify_common_name(SSL* ssl, char* server_name) {
	int result = 1;
	// Get server's certificate
	X509* server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);

	// Get the server common name from the certificate
	X509_NAME *subject_name = X509_get_subject_name(server_cert);
	int index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
	X509_NAME_ENTRY *subject_name_entry = X509_NAME_get_entry(subject_name, index);
	ASN1_STRING *subject_name_asn1 = X509_NAME_ENTRY_get_data(subject_name_entry);
	char* cert_server_common_name = ASN1_STRING_data(subject_name_asn1);
	CHK_NULL(cert_server_common_name);

	// Get the last part of server name
	int server_name_ln = strlen(server_name);
	int cert_server_common_name_ln = strlen(cert_server_common_name);
	const char *last_part_of_server_name = &server_name[server_name_ln - cert_server_common_name_ln];

	// Compare the last part of server name with the name that we got from the certificate
	if (strcmp_ignore_case(last_part_of_server_name, cert_server_common_name) != 0) {
		result = 0;
	}

	OPENSSL_free(cert_server_common_name);
	return result;
}

void get_password(char password[])
{
    static struct termios oldt, newt;
    int i = 0;
    int c;

    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    while ((c = getchar())!= '\n' && c != EOF && i < BUFFER_SIZE_SMALL){
        password[i++] = c;
    }
    password[i] = '\0';

    /*resetting our old STDIN_FILENO*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

}
