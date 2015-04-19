/*
 * Copyright (C) 2013 - Dhruv Kohli <codechiggum at gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * 
 * This code heavily borrows from ns3 itself which are copyright of their
 * respective authors and redistributable under the same conditions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>

#define MAX_USERID_LEN 256
#define MAX_PASS_LEN 256
#define MAX_LEN 256
#define MAX_LINES_IN_MS 5

#define CREDIT 10
#define DEBIT 11

#define USER 0
#define POLICE 1
#define ADMIN 2
#define UNAUTH_USER -1

#define RESPONSE_BYTES 512
#define REQUEST_BYTES 512

struct userInfo{
	char userId[MAX_USERID_LEN+1];
	char pass[MAX_PASS_LEN+1];
};

void error(char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void msg(char *str) {
	printf("%s", str);
}

void sendMsgToClient(int clientFD, char *str) {
	int numPacketsToSend = (strlen(str)-1)/RESPONSE_BYTES + 1;
	int n = write(clientFD, &numPacketsToSend, sizeof(int));
	char *msgToSend = (char*)malloc(numPacketsToSend*RESPONSE_BYTES);
	strcpy(msgToSend, str);
	int i;
	for(i = 0; i < numPacketsToSend; ++i) {
		int n = write(clientFD, msgToSend, RESPONSE_BYTES);
		msgToSend += RESPONSE_BYTES;
	}
}

char* receiveMsgFromClient(int clientFD) {
	int numPacketsToReceive = 0;
	int n = read(clientFD, &numPacketsToReceive, sizeof(int));
	if(n <= 0) {
		shutdown(clientFD, SHUT_WR);
		return NULL;
	}
	
	char *str = (char*)malloc(numPacketsToReceive*REQUEST_BYTES);
	memset(str, 0, numPacketsToReceive*REQUEST_BYTES);
	char *str_p = str;
	int i;
	for(i = 0; i < numPacketsToReceive; ++i) {
		int n = read(clientFD, str, REQUEST_BYTES);
		str = str+REQUEST_BYTES;
	}
	return str_p;
}

struct userInfo getUserInfo(int clientFD) {
	int n;
	char *username = "Username:";
	char *password = "Password:";
	char *buffU;
	char *buffP;

	//asking for username
	sendMsgToClient(clientFD, username);
	buffU = receiveMsgFromClient(clientFD);

	//asking for password
	sendMsgToClient(clientFD, password);
	buffP = receiveMsgFromClient(clientFD);

	struct userInfo uInfo;
	memset(&uInfo, 0, sizeof(uInfo));
	//copy username and password with triming to uInfo

	int i;
	for(i = 0; i < MAX_USERID_LEN; ++i) {
		if(buffU[i] != '\n' && buffU[i] != '\0') {
			uInfo.userId[i] = buffU[i];
		} else {
			break;
		}
	}
	uInfo.userId[i] = '\0';

	for(i = 0; i < MAX_PASS_LEN; ++i) {
		if(buffP[i] != '\n' && buffP[i] != '\0') {
			uInfo.pass[i] = buffP[i];
		} else {
			break;
		}
	}
	uInfo.pass[i] = '\0';
	if(buffU != NULL)
		free(buffU);
	buffU = NULL;
	if(buffP != NULL)
		free(buffP);
	buffP = NULL;
	return uInfo;
}

char* readFromFile(FILE *fp) {
	fseek(fp, 0, SEEK_END);	
	long sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if(sz == 0)
		return NULL;
	char *str = (char *)malloc((sz+1)*sizeof(char));
	fread(str, sizeof(char), sz, fp);
	str[sz] = 0;
	return str;
}

int authorizeUser(struct userInfo uInfo) {
	msg("Authorizing the Following User: \n");
	msg(uInfo.userId);
	msg("\n");
	msg(uInfo.pass);
	msg("\n");

	FILE *fp = fopen("login_file", "r");
	char delim[] = ", \n";
	char *str = readFromFile(fp);
	fclose(fp);
	char *save_ptr;
	char *tok = strtok_r(str, delim, &save_ptr);
	do {
		if(strcmp(uInfo.userId, tok) == 0) {//user name matched
			tok = NULL;
			tok = strtok_r(NULL, delim, &save_ptr);
			if(strcmp(uInfo.pass, tok) == 0) {//password matched
				tok = NULL;
				tok = strtok_r(NULL, delim, &save_ptr);
				if(strcmp(tok, "U") == 0)
					return USER;	//return the user type
				else if(strcmp(tok, "A") == 0)
					return ADMIN;
				else if(strcmp(tok, "P") == 0)
					return POLICE;
			}
		} else {
			tok = strtok_r(NULL, delim, &save_ptr);
			tok = strtok_r(NULL, delim, &save_ptr);
		}
		tok = NULL;
	} while((tok = strtok_r(NULL, delim, &save_ptr)) != NULL);
	if(str!=NULL)
		free(str);
	return UNAUTH_USER;
}

int validate(struct userInfo uInfo) {
	return authorizeUser(uInfo);
}

void closeWithMsg(char *str, int clientFD) {
	sendMsgToClient(clientFD, str);
	shutdown(clientFD, SHUT_RDWR);
}

void addStrings(char** str1, const char* str2,char del)
{
    size_t len1 = *str1 ? strlen(*str1) : 0;
    size_t len2 = str2 ? strlen(str2) : 0;
    char *res = realloc(*str1, len1 + len2 + 2);
    if (res)
    {
        res[len1] = del;
        memcpy(res + len1 + 1, str2, len2);
        res[len1 + 1 + len2] = 0;
        *str1 = res;
    }
}

void printMiniStatement(int clientFD, char *fileName) {
	FILE *fp = fopen(fileName, "r");
	char delim[] = "\n";
	char *str = readFromFile(fp);
	fclose(fp);

	char *miniSt = NULL;
	char *tok = strtok(str, delim);
	int cnt = 0;
	do {
		if(cnt == 0 && tok != NULL) {
			//addStrings(&miniSt, tok, '>');
			miniSt = (char*)malloc(((strlen(tok)+1))*sizeof(char));
			strcpy(miniSt, tok);
			miniSt[strlen(tok)] = 0;
		}
		else
			addStrings(&miniSt, tok, '\n');
		tok = NULL;
		cnt++;
	} while((tok = strtok(NULL, delim)) != NULL && cnt < MAX_LINES_IN_MS);
	if(str!=NULL)
		free(str);
	if(miniSt == NULL)
		sendMsgToClient(clientFD, "None");
	else
		sendMsgToClient(clientFD, miniSt);
	if(miniSt != NULL)
		free(miniSt);
	miniSt = NULL;
	str = NULL;
}

char* returnBalance(char *fileName) {
	FILE *fp = fopen(fileName, "r");
	char delim[] = ",\n";
	char *str = readFromFile(fp);
	fclose(fp);

	char *save_ptr;

	char *bal = (char*)malloc(2*sizeof(char));
	bal[0] = '0';
	bal[1] = 0;
	char *tok = strtok_r(str, delim, &save_ptr);
	int cnt = 0;
	do {
		if(cnt == 2) {
			bal = (char*)malloc(((strlen(tok)+1))*sizeof(char));
			strcpy(bal, tok);
			bal[strlen(tok)] = 0;
		}
		tok = NULL;
		cnt++;
	} while((tok = strtok_r(NULL, delim, &save_ptr)) != NULL && cnt < 3);
	if(str!=NULL)
		free(str);
	str = NULL;
	return bal;
}


void processUserRequests(int clientFD, struct userInfo uInfo) {
	int n;
	char *buff = NULL;
	sendMsgToClient(clientFD, "Enter M for Mini-Statement, B for Available Balance exit to terminate");
	while(1) {
		if(buff != NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "M") == 0) {
			printMiniStatement(clientFD, uInfo.userId);
		} else if(strcmp(buff, "B") == 0) {
			char *bal = returnBalance(uInfo.userId);
			sendMsgToClient(clientFD, bal);
			free(bal);
			bal = NULL;
		} else if(strcmp(buff, "exit") == 0) {
			break;
		} else {
			sendMsgToClient(clientFD, "Unknown Query");
		}
	}
	if(buff != NULL)
		free(buff);
	buff = NULL;
}

void printBalanceOfAllUsers(int clientFD) {
	FILE *fp = fopen("login_file", "r");
	char delim[] = ", \n";
	char *str = readFromFile(fp);
	fclose(fp);
	char *miniSt = (char*)malloc((strlen("User  Avail. Balance")+1)*sizeof(char));
	strcpy(miniSt, "User  Avail. Balance");
	miniSt[strlen("User  Avail. Balance")] = 0;
	char *save_ptr;
	char *tok = strtok_r(str, delim, &save_ptr);
	do {
		char *probableFileName = (char*)malloc(((strlen(tok)+1))*sizeof(char));
		strcpy(probableFileName, tok);
		probableFileName[strlen(tok)] = 0;
		tok = strtok_r(NULL, delim, &save_ptr);
		tok = strtok_r(NULL, delim, &save_ptr);
		if(strcmp(tok, "U") == 0) {
			char *bal = returnBalance(probableFileName);
			addStrings(&miniSt, probableFileName, '\n');
			addStrings(&miniSt, bal, ' ');
			free(bal);
			bal = NULL;
		}
		free(probableFileName);
		probableFileName = NULL;
		tok = NULL;
	} while((tok = strtok_r(NULL, delim, &save_ptr)) != NULL);
	if(str!=NULL)
		free(str);
	if(miniSt != NULL)
		sendMsgToClient(clientFD, miniSt);
	else
		sendMsgToClient(clientFD, "No User in bank");
	if(miniSt!=NULL)
		free(miniSt);
	miniSt = NULL;
}

void processPoliceRequests(int clientFD, struct userInfo userId) {
	int n;
	char *buff = NULL;
	sendMsgToClient(clientFD, "Enter B for Available Balance of all users and exit to terminate");
	while(1) {
		if(buff != NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "B") == 0) {
			printBalanceOfAllUsers(clientFD);
		} else if(strcmp(buff, "exit") == 0) {
			break;
		} else {
			sendMsgToClient(clientFD, "Unknown Query");
		}
	}
	if(buff != NULL)
		free(buff);
	buff = NULL;
}

int checkIfUserExists(char *userName) {
	FILE *fp = fopen("login_file", "r");
	char delim[] = ", \n";
	char *str = readFromFile(fp);
	fclose(fp);

	char *save_ptr;
	char *tok = strtok_r(str, delim, &save_ptr);
	do {
		int check = 0;
		if(tok!=NULL && strcmp(tok, userName) == 0) {
			check = 1;
		}
		tok = strtok_r(NULL, delim, &save_ptr);
		tok = strtok_r(NULL, delim, &save_ptr);
		if(strcmp(tok, "U") == USER && check == 1)
			return 1;
		tok = NULL;
	} while((tok = strtok_r(NULL, delim, &save_ptr)) != NULL);
	if(str!=NULL)
		free(str);
	return 0;
}

int getUserName(int clientFD, char **userName) {
	int n;
	char *buff=NULL;
	int toRet = -1;
	sendMsgToClient(clientFD, "Enter Username of the account to Credit or Debit into and exit to terminate");
	while(1) {
		if(buff != NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "exit") == 0) {
			toRet = -1;
			break;
		} else if(checkIfUserExists(buff)) {
			*userName = (char*)malloc((n+1)*sizeof(char));
			strcpy(*userName, buff);
			toRet = 1;
			break;
		} else {
			sendMsgToClient(clientFD, "Unknow user. Please enter a valid username.");
		}
	}
	if(buff != NULL)
		free(buff);
	buff = NULL;
	return toRet;
}

int getQuery(int clientFD) {
	int n;
	char *buff=NULL;
	int toRet = -1;
	sendMsgToClient(clientFD, "Enter C to credit, D to debit and exit to terminate");
	while(1) {
		if(buff != NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "exit") == 0) {
			toRet = -1;
			break;
		} else if(strcmp(buff, "C") == 0) {
			toRet = CREDIT;
			break;
		} else if(strcmp(buff, "D") == 0) {
			toRet = DEBIT;
			break;
		} else {
			sendMsgToClient(clientFD, "Unknow Query. Please enter C to credit, D to debit and exit to terminate");
		}
	}
	if(buff!=NULL)
		free(buff);
	buff=NULL;
	return toRet;
}

int isANumber(char *num) {
	int i = 0;
	int check = 0;
	for(i = 0; i < strlen(num); ++i) {
		if(isdigit(num[i])) {
			continue;
		}
		else if(num[i] == '.' && check == 0) {
			check = 1;
		}
		else {
			return 0;
		}
	}
	return 1;
}

double getAmount(int clientFD) {
	int n;
	double toRet = -1;
	char *buff=NULL;
	sendMsgToClient(clientFD, "Enter Numerical Amount and exit to terminate");
	while(1) {
		if(buff!=NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "exit") == 0) {
			toRet = -1.0;
			break;
		} else if(isANumber(buff)) {
			toRet = strtod(buff, NULL);
			if(toRet < 0.0f)
				sendMsgToClient(clientFD, "Negative Amount Not Allowed. Please enter a positive amount");
			break;
		} else {
			sendMsgToClient(clientFD, "Invalid amount. Please enter a valid amount and exit to terminate");
		}
	}
	if(buff!=NULL)
		free(buff);
	buff=NULL;
	return toRet;
}

void updateUserTransFile(char *fileName, int toCorD, double amount, double curBal) {
	FILE *fp = fopen(fileName, "r");
	char *str = readFromFile(fp);
	fclose(fp);
	if(str == NULL) {
		str = "";
	}
	char c_d;
	if(toCorD == CREDIT) {
		curBal += amount;
		c_d = 'C';
	}
	else if(toCorD == DEBIT) {
		curBal -= amount;
		c_d = 'D';
	}

	time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */

	char *data = (char*)malloc((1 + strlen(asctime(localtime(&ltime))) + 1000 + strlen(str))*sizeof(char));
	sprintf(data, "%.*s,%c,%f\n%s", (int)strlen(asctime(localtime(&ltime)))-1, asctime(localtime(&ltime)), c_d, curBal, str);

	fp = fopen(fileName, "w");
	fwrite(data, sizeof(char), strlen(data), fp);
	fclose(fp);
}

int showInSuffBal(int clientFD) {
	int n;
	int toRet = -1;
	char *buff=NULL;
	sendMsgToClient(clientFD, "Insufficient Balance. Do you want to continue?[Y/N]");
	while(1) {
		if(buff!=NULL)
			free(buff);
		buff = receiveMsgFromClient(clientFD);
		if(strcmp(buff, "N") == 0) {
			toRet -1;
			break;
		} else if(strcmp(buff, "Y") == 0) {
			toRet = 1;
			break;
		} else {
			sendMsgToClient(clientFD, "Unknow Query. Enter [Y/N]");
		}
	}
	if(buff!=NULL)
		free(buff);
	buff=NULL;
	return toRet;
}

void processAdminRequests(int clientFD) {
	while(1) {
		char *userName;
		int ret = getUserName(clientFD, &userName);
		if(ret < 0)
			return;
		ret = getQuery(clientFD);
		if(ret < 0)
			return;
		int toCorD = ret;
		double amount  = getAmount(clientFD);
		if(amount < 0.0)
			return;
		char *bal = returnBalance(userName);
		double curBal = strtod(bal, NULL);
		free(bal);
		bal = NULL;

		if(curBal < amount && toCorD == DEBIT) {
			ret = showInSuffBal(clientFD);
			if(ret < 0)
				return;
			else
				continue;
		}
		updateUserTransFile(userName, toCorD, amount, curBal);
	}
}

void processRequests(int uType, int clientFD, struct userInfo uInfo) {
	if(uType == UNAUTH_USER) {
		msg("Unautherized user.\n");
		closeWithMsg("unauth", clientFD);
	} else if(uType == USER) {
		msg("USER.\n");
		processUserRequests(clientFD, uInfo);
		closeWithMsg("Thanks User!", clientFD);
	} else if(uType == ADMIN) {
		msg("ADMIN.\n");
		processAdminRequests(clientFD);
		closeWithMsg("Thanks Admin!", clientFD);
	} else if(uType == POLICE) {
		msg("POLICE.\n");
		processPoliceRequests(clientFD, uInfo);
		closeWithMsg("Thanks Police!", clientFD);
	}
}

void talkToClient(int clientFD) {
	struct userInfo uInfo = getUserInfo(clientFD);
	int uType = validate(uInfo);
	processRequests(uType, clientFD, uInfo);
}

int main(int argc, char **argv) {
	int sockFD, clientFD, portNO, cliSz;
	struct sockaddr_in serv_addr, cli_addr;

	if(argc < 2) {
		fprintf(stderr, "Usage: %s port_number\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/*
		socket(DOMAIN, TYPE, PROTOCOL) returns int
	*/
	if((sockFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		error("Error opening socket.\n");
	}

	//initializing variables
	memset((void*)&serv_addr, 0, sizeof(serv_addr));
	portNO = atoi(argv[1]);

	//setting serv_addr
	serv_addr.sin_family = AF_INET;				//setting DOMAIN
	serv_addr.sin_addr.s_addr = INADDR_ANY;		//permits any incoming IP
	/*
		Note: to permit a fixed IP:
		ret = inet_aton((char *)"a.b.c.d", &serv_addr.sin_addr);
		if(ret == 0)
			address is invalid
		else
			valid
	*/
	serv_addr.sin_port = htons(portNO);			//set the port number

	//binding the socket with the server logistics which are in sockaddr_in serv_addr
	if(bind(sockFD, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		error("Error on binding.\n");
	}

	//setting socket option to reuse the same port immmediately after closing socket
	//BUT with a caveat: Client should close first
	int reuse = 1;
	setsockopt(sockFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

	/*
		listen(SOCKETFD, BACKLOG) returns 0 on success -1 on failure
		backlog is the maximum number of connections the kernel should queue for this socket. 
		The backlog argument provides an hint to the system of the number of outstanding connect 
		requests that is should enqueue in behalf of the process. Once the queue is full, the 
		system will reject additional connection requests. 
	*/


	if(listen(sockFD, 7) < 0) {
		error("Error on listening.\n");
	}

	cliSz = sizeof(cli_addr);

	while(1) {
		//blocking call
		memset(&cli_addr, 0, sizeof(cli_addr));
		if((clientFD = accept(sockFD, (struct sockaddr*)&cli_addr, &cliSz)) < 0) {
			error("Error on accept.\n");
		}

		switch(fork()) {
			case -1:
				msg("Error in fork.\n");
				break;
			case 0: {
				close(sockFD);
				talkToClient(clientFD);
				exit(EXIT_SUCCESS);
				break;
			}
			default:
				close(clientFD);
				break;
		}
	}

	return 0;
}