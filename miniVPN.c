/* Messages structure guide
	byte 0: command type
		----------------
		byte 0 = 0 means it is a authentication status message
			byte 1 = 0 means authentication is  not successful
			byte 1 = 1 means authentication is successful
		----------------
		byte 0 = 1 means it is a update key message
		----------------
		byte 0 = 2 means it is a shutdown message

*/

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include "helper.c"
#include "serv.c"
#include "cli.c"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)
#define BUFFER_SIZE 2000
#define BUFFER_SIZE_MESSAGE 100
#define HMAC_LEN 32
#define IV_LEN 16
#define SEQ_NUM_LN 4
#define SEQ_NUM_HISTORY_LN 10000

unsigned char key[KEY_LEN];
unsigned long seq_num_send = 0;
unsigned long seq_num_recv = 0;
unsigned char seq_num_buf[SEQ_NUM_LN];
unsigned char seq_num_history[SEQ_NUM_HISTORY_LN];
unsigned char original_buf[BUFFER_SIZE];
int original_buf_len;
unsigned char modified_buf[BUFFER_SIZE];
int modified_buf_len;
unsigned char iv[IV_LEN];
unsigned char encrypted_buf[BUFFER_SIZE];
int encrypted_buf_len;
unsigned char hmac[HMAC_LEN];
unsigned char modified_buf_without_hmac[BUFFER_SIZE];
int modified_buf_without_hmac_len;
unsigned char calulated_hmac[HMAC_LEN];



void usage()
{
	fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sin, sout, from;
	struct ifreq ifr;
	int fd, s, fromlen, soutlen, port, PORT, buf_len;
	char c, *p, *server_ip, *server_hostname;
	char buf[BUFFER_SIZE];
	fd_set fdset;
	int MODE = 0;
	int TUNMODE = IFF_TUN;
	int DEBUG = 0;
	int index = 0;

	while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
		switch (c) {
		case 'h':
			usage();
		case 'd':
			DEBUG++;
			break;
		case 's':
			MODE = 1;
			PORT = atoi(optarg);
			break;
		case 'c':
			MODE = 2;
			p = memchr(optarg,':',100);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;

			// Get server ip from hostname
			server_hostname = optarg;
			if (is_valid_ip(server_hostname) == 1){
				server_ip = server_hostname;
			} else {
				char ip [BUFFER_SIZE_SMALL];
				get_ip_from_hostname(server_hostname, ip);
				server_ip = ip;
			}
			printf("server ip = %s\n", server_ip);

			port = atoi(p+1);
			PORT = 0;
			break;
		case 'e':
			TUNMODE = IFF_TAP;
			break;
		default:
			usage();
		}
	}
	if (MODE == 0) usage();


/*
 * This code will use socket "s" to bind the TUN/TAP interface
 * The dev name is toto0 if you are the first one to connect
 * 
 * 
*/
	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TUNMODE;
	strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	







	// Fork and create a pipe to communicate between processes
	int pipe_fd[2];
	pipe(pipe_fd);
	pid_t pid = fork();


	if (pid > 0){
		// Parent process manages the TCP connection
		// Parent process closes up input side of pipe
		close(pipe_fd[0]);


		int child_pid = pid;
		if (MODE == 1){
			startTCPServer(pipe_fd, child_pid);
		} else if (MODE == 2){
			startTCPClient(pipe_fd, child_pid, server_ip, server_hostname);
		}
		exit(0);
	}
	else if (pid == 0){
		// Child process manages the UDP connection
        // Child process closes up output side of pipe
        close(pipe_fd[1]);


        // Check the TCP program to see whether to continue or not (ie: authentication is successful ...)
        // Note that read function will block until we get a decision from the TCP program
        memset(buf, 0, BUFFER_SIZE);
        read(pipe_fd[0], buf, BUFFER_SIZE_MESSAGE);
        if (buf[0] == 0 && buf[1] == 1){
        	printf("I accepted the other side verification, continues to the UDP program \n");
        } else {
        	printf("Something cannot be verified, exiting, cannot continues to the UDP program \n");
        	exit(1);
        }

        // Get the key from the TCP program
        memset(buf, 0, BUFFER_SIZE);
        read(pipe_fd[0], buf, BUFFER_SIZE_MESSAGE);
        index = 0;
        // If it is an update key message
        if (buf[0] == 1){
        	index++;
        	memcpy(&key[0], &buf[index], KEY_LEN);
        	index += KEY_LEN;
        }



	}
	else {
		printf("fork() failed!\n");
		exit(1);
	}







	// Creating a UDP socket
	s = socket(PF_INET, SOCK_DGRAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(PORT);
	if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) {PERROR("bind");}

	fromlen = sizeof(from);






// Send a test packet to let the server know the clients ip address and initialize the UDP connection
// mode = 1 means it is a server and mode = 2 mens it is aclinet	
	char test_packet[] = "test";
	if (MODE == 1) {
			buf_len = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (buf_len < 0) PERROR("recvfrom");
			buf_len = sendto(s, test_packet, sizeof(test_packet), 0, (struct sockaddr *)&from, fromlen);
			if (buf_len < 0) {PERROR("sendto");}
		} else {
			from.sin_family = AF_INET;
			from.sin_port = htons(port);
			inet_aton(server_ip, &from.sin_addr);
			buf_len =sendto(s, test_packet, sizeof(test_packet), 0, (struct sockaddr *)&from, sizeof(from));
			if (buf_len < 0) {PERROR("sendto");}
			buf_len = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (buf_len < 0) {PERROR("recvfrom");}
		}
		printf("UDP Connection established \n");
           
           
/*
 * The next loop would be the UDP channel built for the VPN
 * In this example, no encryption or signature is done
 * You need to add the encryption and decryption logic as well
 * as the hash signautre checking to make sure the VPN's
 * confidentiality and integraty
 * */

	memset(seq_num_history, 0, SEQ_NUM_HISTORY_LN);
	while (1) {
        // this is to fetch the packet data from TUN/TAP and forward to the remote app
        // you may want to encrypt and sign each packet
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		FD_SET(pipe_fd[0], &fdset);
		if (select(fd+s+pipe_fd[0]+1, &fdset,NULL,NULL,NULL) < 0) {
			PERROR("select");
		}
		if (FD_ISSET(fd, &fdset)) {
			if (DEBUG) write(1,">", 1);
			buf_len = read(fd, buf, sizeof(buf));
			if (buf_len < 0) PERROR("read");


			// Process buffer before sending
			process_buffer_before_sending(buf, buf_len, key, modified_buf, &modified_buf_len);


			if (sendto(s, modified_buf, modified_buf_len, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");


		} else if (FD_ISSET(s, &fdset)) {
        // this is to fetch the packet data from another VPN app and put it into the TUN/TAP 
        // you may want to check the signature and decrypt the packet.
			if (DEBUG) write(1,"<", 1);
			buf_len = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);


			// Process buffer after receiving
			int verifieing_result = process_buffer_after_receiving(buf, buf_len, key, original_buf, &original_buf_len);

			if (verifieing_result == 1){  // do not write the message if it cannot be verified
				if (write(fd, original_buf, original_buf_len) < 0) PERROR("write");
				printf("packet verified \n");
			} else {
				printf("Cannot verify the the packet \n");
			}




		}  else if (FD_ISSET(pipe_fd[0], &fdset)) {
			// Get the key from the TCP program
			memset(buf, 0, BUFFER_SIZE_MESSAGE);
			read(pipe_fd[0], buf, BUFFER_SIZE_MESSAGE);
			index = 0;
			// If it is an update key message
			if (buf[0] == 1){
				index++;
				memcpy(&key[0], &buf[index], KEY_LEN);
				index += KEY_LEN;
			}

		}
	}

}

void process_buffer_before_sending(unsigned char* buf, int buf_len, unsigned char key[] ,unsigned char modified_buf[], int* modified_buf_len){

	printf("---------------------- Sending packet ---------------------- \n");
	int index = 0;

	// Create the IV
	generate_random_number(iv, IV_LEN);

	// Form the encrypted buffer (encrypting the original buffer)
	do_aes_128_cbc_crypt(buf, buf_len, encrypted_buf, &encrypted_buf_len, key, iv, 1);

	// Put everything needed to calculate the HMAC in one buffer
	index = 0;
	memcpy(&modified_buf_without_hmac[index], &iv[0], IV_LEN);
	index += IV_LEN;
	seq_num_send++;
	printf("seq_send = %i \n", seq_num_send);
	convert_long_to_bytes(seq_num_send, seq_num_buf);
	memcpy(&modified_buf_without_hmac[index], &seq_num_buf[0], SEQ_NUM_LN);
	index += SEQ_NUM_LN;
	memcpy(&modified_buf_without_hmac[index], &encrypted_buf[0], encrypted_buf_len);
	index += encrypted_buf_len;
	modified_buf_without_hmac_len = index;

	// Calculate the HMAC
	calculate_sha256_hmac(modified_buf_without_hmac, modified_buf_without_hmac_len, hmac, NULL, key);

	// Put everything together in a new buffer
	index = 0;
	memcpy(&modified_buf[index], &modified_buf_without_hmac[0], modified_buf_without_hmac_len);
	index += modified_buf_without_hmac_len;
	memcpy(&modified_buf[index], &hmac[0], HMAC_LEN);
	index += HMAC_LEN;
	*modified_buf_len = index;
}
	       
int process_buffer_after_receiving(unsigned char* buf, int buf_len, unsigned char key[], unsigned char original_buf[], int* original_buf_len){

	printf("---------------------- Receiving packet ---------------------- \n");
	int index = 0;

	// Get the IV
	index = 0;
	memcpy(&iv[0], &buf[index], IV_LEN);
	index += IV_LEN;


	// Get the Sequence number
	memcpy(&seq_num_buf[0], &buf[index], SEQ_NUM_LN);
	index += SEQ_NUM_LN;
	seq_num_recv = convert_bytes_to_long(seq_num_buf);
	printf("recv = %i \n", seq_num_recv);
	if (seq_num_history[seq_num_recv] == 1){
		return 0;
	}
	seq_num_history[seq_num_recv] = 1;



	// Get the encrypted buffer
	encrypted_buf_len = buf_len -IV_LEN - SEQ_NUM_LN -HMAC_LEN ;
	memcpy(&encrypted_buf[0], &buf[index], encrypted_buf_len);
	index += encrypted_buf_len;

	// Get the HMAC
	memcpy(&hmac[0], &buf[index], HMAC_LEN);
	index += HMAC_LEN;

	// Get the original buffer
	do_aes_128_cbc_crypt(encrypted_buf, encrypted_buf_len, original_buf, original_buf_len, key, iv, 0);

	// Put everything needed to calculate the HMAC in one buffer
	modified_buf_without_hmac_len = buf_len - HMAC_LEN;
	memcpy(&modified_buf_without_hmac[0], &buf[0], modified_buf_without_hmac_len);

	// Verify the HMAC
	calculate_sha256_hmac(modified_buf_without_hmac, modified_buf_without_hmac_len, calulated_hmac, NULL, key);
	int hmac_verifieing_result = compare_buffers(hmac, calulated_hmac, HMAC_LEN);

	return hmac_verifieing_result;
}

void get_ip_from_hostname(const char* hostname , char ip[])
{
    struct hostent *he;
    struct in_addr **addr_list;
    he = gethostbyname(hostname);
    addr_list = (struct in_addr **) he->h_addr_list;
    strcpy(ip, inet_ntoa(*addr_list[0]));
}

void calculate_sha256_hmac(unsigned char inbuf[], int inlen, unsigned char outbuf[], int* outlen, unsigned char key[]) {
	HMAC(EVP_sha256(), key, 16, inbuf, inlen, outbuf, outlen);
}







