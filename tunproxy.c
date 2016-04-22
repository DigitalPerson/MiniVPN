/*
 * tunproxy.c --- small demo program for tunneling over UDP with tun/tap
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */


/* Pipe messages guide
	byte 0: command type

		----------------
		byte 0 = 1 means it is a authentication status message
			byte 1 = 0 means authentication is  not successful
			byte 1 = 1 means authentication is successful
		----------------
		byte 0 = 2 means it is a update key message



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
#include "crypto.c"
#include "hmac.c"
#include "serv.c"
#include "cli.c"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)
#define BUFFER_SIZE 2000
#define BUFFER_SIZE_PIPE 100
#define HMAC_LEN 32
#define IV_LEN 16

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";
unsigned char key[KEY_LEN];
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
	char c, *p, *ip;
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
			p = memchr(optarg,':',16);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;
			ip = optarg;
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


		if (MODE == 1){
			startTCPServer(pipe_fd);
		} else if (MODE == 2){
			startTCPClient(pipe_fd);
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
        read(pipe_fd[0], buf, BUFFER_SIZE_PIPE);
        if (buf[0] == 1 && buf[1] == 1){
        	printf("I accepted the other side verification, continues to the UDP program \n");
        } else {
        	printf("Something cannot be verified, exiting, cannot continues to the UDP program \n");
        	exit(1);
        }

        // Get the key from the TCP program
        memset(buf, 0, BUFFER_SIZE);
        read(pipe_fd[0], buf, BUFFER_SIZE_PIPE);
        index = 0;
        // If it is an update key message
        if (buf[0] == 2){
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





/*
 * The next code module will be the authentication for the client/server
 * based on the MODE value.(MODE==1 means server; or it is client)
 * In this example, we just exchange the magic word for authentication.
 * However, in your case, you need to use PKI and password/username to handle
 * the case.
 */


	if (MODE == 1) {
			while(1) {
				buf_len = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
				if (buf_len < 0) PERROR("recvfrom");
				if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0){
					break;
				}
				printf("Bad magic word");
			}
			buf_len = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
			if (buf_len < 0) {PERROR("sendto");}
		} else {
			from.sin_family = AF_INET;
			from.sin_port = htons(port);
			inet_aton(ip, &from.sin_addr);
			buf_len =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
			if (buf_len < 0) {PERROR("sendto");}
			buf_len = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (buf_len < 0) {PERROR("recvfrom");}
			if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0)){
				ERROR("Bad magic word for peer\n");
			}
		}
		printf("UDP Connection established \n");
           
           
/*
 * The next loop would be the UDP channel built for the VPN
 * In this example, no encryption or signature is done
 * You need to add the encryption and decryption logic as well
 * as the hash signautre checking to make sure the VPN's
 * confidentiality and integraty
 * */
	while (1) {
        // this is to fetch the packet data from TUN/TAP and forward to the remote app
        // you may want to encrypt and sign each packet
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			if (DEBUG) write(1,">", 1);
			buf_len = read(fd, buf, sizeof(buf));
			if (buf_len < 0) PERROR("read");


			// Process buffer before sending
			process_buffer_before_sending(buf, buf_len, key, modified_buf, &modified_buf_len);


			if (sendto(s, modified_buf, modified_buf_len, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");


		} else {
        // this is to fetch the packet data from another VPN app and put it into the TUN/TAP 
        // you may want to check the signature and decrypt the packet.
			if (DEBUG) write(1,"<", 1);
			buf_len = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
//			if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port)){
//				printf("Got packet from  %s:%i instead of %s:%i\n",
//				       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
//				       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
//			}


			// Process buffer after receiving
			int hmac_verifieing_result = process_buffer_after_receiving(buf, buf_len, key, original_buf, &original_buf_len);

			if (hmac_verifieing_result == 1){  // do not write the message if HMAC cannot be verified
				if (write(fd, original_buf, original_buf_len) < 0) PERROR("write");
			} else {
				printf("Cannot verify the HMAC \n \n");
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

	// Get the encrypted buffer
	encrypted_buf_len = buf_len -IV_LEN -HMAC_LEN ;
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
