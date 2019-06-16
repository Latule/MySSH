#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <mcrypt.h>
#include <math.h>

#define bool int
#define true 1
#define false 0

/* codul de eroare returnat de anumite apeluri */
extern int errno;

/* portul de conectare la server*/
int port;

char *IV = "AAAAAAAAAAAAAAAA";
char *key = "0123456789abcdef";
int buffer_len = 10000;

int encrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
	MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
	int blocksize = mcrypt_enc_get_block_size(td);
	if (buffer_len % blocksize != 0) { return 1; }

	mcrypt_generic_init(td, key, key_len, IV);
	mcrypt_generic(td, buffer, buffer_len);
	mcrypt_generic_deinit(td);
	mcrypt_module_close(td);

	return 0;
}

int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
	MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
	int blocksize = mcrypt_enc_get_block_size(td);
	if (buffer_len % blocksize != 0) { return 1; }

	mcrypt_generic_init(td, key, key_len, IV);
	mdecrypt_generic(td, buffer, buffer_len);
	mcrypt_generic_deinit(td);
	mcrypt_module_close(td);

	return 0;
}


char *trimwhitespace(char *str)
{
	char *end;

	while (isspace((unsigned char)*str)) str++;

	if (*str == 0)
		return str;


	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) end--;

	end[1] = '\0';

	return str;
}

int main(int argc, char *argv[])
{
	int sd;			// descriptorul de socket
	struct sockaddr_in server;	// structura folosita pentru conectare 
	char * msg;		// mesajul trimis

					/* exista toate argumentele in linia de comanda? */
	if (argc != 3)
	{
		printf("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
		return -1;
	}

	/* stabilim portul */
	port = atoi(argv[2]);

	/* cream socketul */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[client] Eroare la socket().\n");
		return errno;
	}


	/* umplem structura folosita pentru realizarea conexiunii cu serverul */
	/* familia socket-ului */
	server.sin_family = AF_INET;
	/* adresa IP a serverului */
	server.sin_addr.s_addr = inet_addr(argv[1]);
	/* portul de conectare */
	server.sin_port = htons(port);

	/* ne conectam la server */
	if (connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1)
	{
		perror("[client]Eroare la connect().\n");
		return errno;
	}

	/* citirea mesajului */
	bool terminat = false;
	// int buffer_len;
	char * buffer;
	while (!terminat) {
		msg = malloc(1024 * sizeof(char));
		bzero(msg, 1024);
		printf("[client]Introduceti o comanda: ");
		fflush(stdout);
		read(0, msg, 1024);
		if (strncmp(trimwhitespace(msg), "exit", strlen("exit")) == 0) {
			terminat = true;
		}
		//criptam
		// buffer_len = sizeof(msg)*sizeof(char *);
		buffer = calloc(1, buffer_len);
		strncpy(buffer, msg, buffer_len);
		encrypt(buffer, buffer_len, IV, key, 16);

		/* trimiterea mesajului la server */
		if (write(sd, buffer, buffer_len) <= 0) {
			perror("[client]Eroare la write() spre server.\n");
			return errno;
		}


		int len = 0;
		char * msgP = NULL;
		sleep(2);
		ioctl(sd, FIONREAD, &len);

		if (len > 0) {

			msgP = calloc(1,len * sizeof(char));
			len = read(sd, msgP, len);


			decrypt(msgP, buffer_len, IV, key, 16);

			printf("[client]Mesajul a fost receptionat...%s\n", msgP);
			fflush(stdout);
		}
	}
	/* inchidem conexiunea, am terminat */
	close(sd);

}