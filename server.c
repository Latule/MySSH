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
#include <signal.h>
#include <mcrypt.h>
#include <math.h>
#include <sqlite3.h>

#define bool int
#define true 1
#define false 0
#define PORT 2026

char *IV = "AAAAAAAAAAAAAAAA";
char *key = "0123456789abcdef";
int buffer_len =10000;

int encrypt(void* buffer,int buffer_len, char* IV,char* key,int key_len ){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt(void* buffer,int buffer_len,char* IV,char* key,int key_len ){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}


int popenRWE(int *rwepipe) {
	int in[2];
	int out[2];
	int err[2];
	int pid;
	int rc;

	rc = pipe(in);
	if (rc<0)
		goto error_in;

	rc = pipe(out);
	if (rc<0)
		goto error_out;

	rc = pipe(err);
	if (rc<0)
		goto error_err;

	pid = fork();
	if (pid > 0) { /* parinte */
		close(in[0]);
		close(out[1]);
		close(err[1]);
		rwepipe[0] = in[1];
		rwepipe[1] = out[0];
		rwepipe[2] = err[0];
		return pid;
	} else if (pid == 0) { /* copil */
		close(in[1]);
		close(out[0]);
		close(err[0]);

		close(0);
		dup(in[0]);
		
		close(1);
		dup(out[1]);
		
		close(2);
		dup(err[1]);

		execl( "/bin/sh", "sh", NULL );
		_exit(1);
	} else
		goto error_fork;

	return pid;

	error_fork:
		close(err[0]);
		close(err[1]);
	error_err:
		close(out[0]);
		close(out[1]);
	error_out:
		close(in[0]);
		close(in[1]);
	error_in:
		return -1;
}

int pcloseRWE(int pid, int *rwepipe)
{
	int status;
	close(rwepipe[0]);
	close(rwepipe[1]);
	close(rwepipe[2]);
	waitpid(pid, &status, 0);
	return status;
}

char * parseaza(char * sir) {
	char * ret = NULL;
	if (sir != NULL) {

		bool stare = false;
		int inceput = 0;
		int parcurs = 0;
		for (int i = 0; i < strlen(sir); i++)
			if (stare) {
				if (sir[i] == '"') {
					stare = false;
					break;
				}

				else
					++parcurs;

			}
			else {
				if (sir[i] == '"') {
					stare = true;
					inceput = i;
				}
			}

			ret = (char *)malloc(parcurs * sizeof(char) + 1);
			strncpy(ret, sir + inceput + 1, parcurs);
			ret[parcurs] = '\0';
	}
	return ret;
}


void handler(int sig)
{
	while (waitpid(-1, NULL, WNOHANG)>0);
}


int main(){

	int optval = 1; 			/* optiune folosita pentru setsockopt()*/
	struct sockaddr_in server;	// structura folosita de server
	struct sockaddr_in from;

	char msgrasp[100] = " ";        //mesaj de raspuns pentru client
	int sd;			//descriptorul de socket 

	/* crearea unui socket */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[server]Eroare la socket().\n");
		return errno;
	}

	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	/* pregatirea structurilor de date */
	bzero(&server, sizeof(server));
	bzero(&from, sizeof(from));

	/* umplem structura folosita de server */
	/* stabilirea familiei de socket-uri */
	server.sin_family = AF_INET;
	/* acceptam orice adresa */
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	/* utilizam un port utilizator */
	server.sin_port = htons(PORT);


	/* atasam socketul */
	if (bind(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1)
	{
		perror("[server]Eroare la bind().\n");
		return errno;
	}

	/* punem serverul sa asculte daca vin clienti sa se conecteze */
	if (listen(sd, 5) == -1)
	{
		perror("[server]Eroare la listen().\n");
		return errno;
	}

	/* servim in mod concurent clientii... */
	while (1)
	{
		int client;
		int length = sizeof(from);

		printf("[server]Asteptam la portul %d...\n", PORT);
		fflush(stdout);

		/* acceptam un client (stare blocanta pina la realizarea conexiunii) */
		client = accept(sd, (struct sockaddr *) &from, &length);


		/* eroare la acceptarea conexiunii de la un client */
		if (client < 0)
		{
			perror("[server]Eroare la accept().\n");
			continue;
		}
		else {
			signal(SIGCHLD, handler);
			int child;
			if ((child = fork()) == -1) perror("Err...fork");
			else
				if (child) {}//parinte
				else{
			int pipe[3];
			int pid=popenRWE(pipe);

			if(pid!=-1){
				char * msgP;
				char * msg;
				char* buffer;
				int len;
				bool terminat=false;
				bool logat=false;
				
				while(!terminat){
					
					
					do{
						ioctl(client, FIONREAD, &len);
					}while(len==0);

					msg=malloc(sizeof(char)*len);
					read (client, msg, len);
					
					
					//decriptam
					decrypt(msg, buffer_len, IV, key, 16);

					if(logat==true){
						if(strncmp(msg,"exit",strlen("exit"))==0) 
							terminat=true;

						strcat(msg," \n");

						if(write(pipe[0],msg,strlen(msg))!= strlen(msg))
							perror("eroare scriere in pipe");
						
						sleep(1);

						for(int i =1;i<=2;++i)	
						{
							ioctl(pipe[i], FIONREAD, &len);
							if (len > 0) {	
								msgP = malloc(len * sizeof(char));
								len = read(pipe[i], msgP, len);
								//criptam 
								
  								buffer = calloc(1, buffer_len);
   								strncpy(buffer, msgP, buffer_len);
								encrypt(buffer, buffer_len, IV, key, 16);
								//trimitem mesajul 
								if (write(client,buffer, buffer_len) != buffer_len)
									perror("child - partial/failed write");
							}
						}
					}
					else {
						if(strncmp(msg,"login",strlen("login"))==0) {
							char * nume ;
							char * pass;
							char * re= strstr(msg,"-n");
							nume=parseaza(re);
							re=strstr(msg,"-p");
							pass=parseaza(re);
							
							if(nume!= NULL && pass!=NULL){
								sqlite3 *db;
								char *err_msg = 0;
								sqlite3_stmt *res;
								char *zErrMsg = 0;

								int rc = sqlite3_open("login", &db);
								if (rc != SQLITE_OK) {
									msgP="Baza de date nu poate fi deschisa";
									goto error_sqlopen;
								}

								char *sql = "SELECT * from user where nume = ?1 and pass=?2 ";
		
								
								rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
								sqlite3_bind_text(res, 1, nume, -1, SQLITE_STATIC);
								sqlite3_bind_text(res, 2, pass, -1, SQLITE_STATIC);
						

								int step = sqlite3_step(res);
								if (step == SQLITE_ROW) {
								
									logat=true;
									msgP="Logat cu succes!";
								}
								else {
									msgP="Datele nu corespund";
								}
								sqlite3_finalize(res);
								error_sqlopen:
								sqlite3_close(db);
							}
							else{
								msgP="Date insuficiente! \nSintaxa: login -n \"user\" -p \"parola\" ";
								//criptam
  								buffer = calloc(1, buffer_len);
   								strncpy(buffer, msgP, buffer_len);
								encrypt(buffer, buffer_len, IV, key, 16);
								//trimitem mesajul
								if (write(client,buffer, buffer_len) != buffer_len)
									perror("child - partial/failed write");
							}
						}
						else {
							msgP="Nu sunteti logat!";

						}
						
						//criptam
  						buffer = calloc(1, buffer_len);
   						strncpy(buffer, msgP, buffer_len);
						encrypt(buffer, buffer_len, IV, key, 16);
						//trimitem mesajul
						if (write(client,buffer, buffer_len) != buffer_len)
							perror("child - partial/failed write");
					}
				}
				int status= pcloseRWE(pid,pipe);
			}
		}
	}
}
}