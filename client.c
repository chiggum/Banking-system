//client.c

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#define MAX_MSG_LEN 257
#define RESPONSE_BYTES 512
#define REQUEST_BYTES 512

void error(char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void msg(char *str) {
	printf("%s", str);
}

char* receiveMsgFromServer(int sockFD) {
	int numPacketsToReceive = 0;
	int n = read(sockFD, &numPacketsToReceive, sizeof(int));
	if(n <= 0) {
		shutdown(sockFD, SHUT_WR);
		return NULL;
	}
	char *str = (char*)malloc(numPacketsToReceive*RESPONSE_BYTES);
	memset(str, 0, numPacketsToReceive*RESPONSE_BYTES);
	char *str_p = str;
	int i;
	for(i = 0; i < numPacketsToReceive; ++i) {
		int n = read(sockFD, str, RESPONSE_BYTES);
		str = str+RESPONSE_BYTES;
	}
	return str_p;
}

void sendMsgToServer(int sockFD, char *str) {
	int numPacketsToSend = (strlen(str)-1)/REQUEST_BYTES + 1;
	int n = write(sockFD, &numPacketsToSend, sizeof(int));
	char *msgToSend = (char*)malloc(numPacketsToSend*REQUEST_BYTES);
	strcpy(msgToSend, str);
	int i;
	for(i = 0; i < numPacketsToSend; ++i) {
		int n = write(sockFD, msgToSend, REQUEST_BYTES);
		msgToSend += REQUEST_BYTES;
	}
}

int main(int argc, char **argv) {
	int sockFD, portNO;
	struct sockaddr_in serv_addr;
	char *msgFromServer;
	char msgToServer[MAX_MSG_LEN];

	if(argc < 3) {
		fprintf(stderr, "Usage: %s host_addr port_number\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	portNO = atoi(argv[2]);
	if((sockFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error in opening socket.\n");
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	//setting sockaddr_in serv_addr
	serv_addr.sin_family = AF_INET;			//setting DOMAIN
	serv_addr.sin_port = htons(portNO);		//setting port numbet
	if((inet_aton(argv[1], &serv_addr.sin_addr)) == 0) {
		error("Error Invalid Host Name");
	}

	if(connect(sockFD, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		error("Error in connecting.\n");
	}

	msg("Connection Established.\n");
	msg("Asking server what to do(by receiving input from server).\n");

	while(1) {
		msgFromServer = receiveMsgFromServer(sockFD);
		if(msgFromServer == NULL)
			break;
		if(strncmp(msgFromServer, "unauth", 6) == 0) {
			msg("Unautherized User.\n");
			shutdown(sockFD, SHUT_WR);
			break;
		}
		msg(msgFromServer);
		msg("\n");
		free(msgFromServer);
		

		memset(msgToServer, 0, sizeof(msgToServer));
		scanf("%s", msgToServer);
		sendMsgToServer(sockFD, msgToServer);
		if(strncmp(msgToServer, "exit", 4) == 0) {
			shutdown(sockFD, SHUT_WR);
			break;
		}
	}

	msg("Receiving Pending Messages from server.\n");

	while(1) {
		msgFromServer = receiveMsgFromServer(sockFD);
		if(msgFromServer == NULL)
			break;
		msg(msgFromServer);
		msg("\n");
		free(msgFromServer);
	}
	msg("Write end closed by the server.\n");
	shutdown(sockFD, SHUT_RD);
	msg("Connection closed gracefully.\n");
	return 0;
}