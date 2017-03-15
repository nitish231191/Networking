#include "stdafx.h"
using namespace std;
#pragma pack(push,1) 
struct QueryHeader {
	u_short qType;
	u_short qClass;
};
struct FixedDNSheader {
	u_short ID;
	u_short flags;
	u_short nquestions;
	u_short nanswers;
	u_short nauthority;
	u_short nadditional;	
};
struct FixedResourceHeader {
	u_short qtype;
	u_short qclass;
	int ttl;
	u_short len;

};
struct DNSRecord {
	unsigned char * name;
	struct FixedResourceHeader *fdrrh;
	unsigned char *actualresult;
};
#pragma pack(pop)
#pragma warning( disable: C4996 )

class DNS {
public :
	void DNS::preprocess(char *ip, char *dns_server);
	void DNS::QueryConstructor(char *ip, char *dns_server);
	void DNS::QueryConstructorptr(char *ip,char *buf);
	int DNS::QueryConstructorINADDR(char*buf, char*host);
	unsigned char* DNS::ParseResponse(unsigned char *query, unsigned char* recvbuf, int *delim,int pktsize);

};

unsigned char* DNS::ParseResponse(unsigned char *query,unsigned char* recvbuf, int *delim,int pkt_size) {
	unsigned char *response = (unsigned char*)malloc(256);
	unsigned int k = 0, jumped = 0, offset = 0;
	int i, j;
	*delim = 1;
	while (*query != 0) {
	
		if (*query >= 0xC0) {
			unsigned char *temp = query + 1;
			//if (*(temp) == '\f') {
				//cout << "\t\t++Jump Offset Truncated" << endl;
				//break;
			//}
			offset = ((*(query) & 0x3F) << 8) + *(query + 1);
			query = recvbuf + offset ;
			if (offset < 12) {
				cout << "\t++Invalid reply jump into fixed header\n" << endl;
				return NULL;
			}
			if ( query ==0) {
				cout << "\t++invalid record jump beyond packet boundary\n" << endl;
			}
			jumped = 1;
		}
		else {
			response[k++] = *query++;
		}
		if (jumped == 0) {
			*(delim) += 1;
		}
	}
	response[k] = 0;
	if (jumped == 1) {
		*(delim) += 1;
	}
	 i = 0;
	 unsigned char number = 0;
	for (i = 0; i<(int)strlen((const char*)response); i++)
	 {
		 number= response[i];
		 for (j = 0; j<(int)(number); j++)
		 {
			 response[i] = response[i + 1];
			 i = i + 1;
		 }
		 response[i] = '.';
	 }
	response[i - 1] = '\0';
	return response;
}
void DNS::QueryConstructorptr(char *host, char *buf) {
	char *firstdot, *secondot, *thirdot;
	char* url[4];
	int m = 0;
	firstdot = strchr(host, '.') + 1;
	if (firstdot == NULL) {
		return ;
	}
	*(host + (firstdot - host - 1)) = '\0';
	url[0] = host;
	secondot = strchr(firstdot, '.') + 1;
	if (secondot == NULL) {
		return ;
	}
	*(firstdot + (secondot - firstdot - 1)) = '\0';
	thirdot = strchr(secondot, '.') + 1;
	if (thirdot == NULL) {
		return ;
	}
	*(secondot + (thirdot - secondot - 1)) = '\0';
	url[1] = firstdot;
	url[2] = secondot;
	url[3] = thirdot;

	for (int i = 3; i >= 0; i--) {
		int j = 0;
		while (j < strlen(url[i])) {
			*buf++ = url[i][j];
			j += 1;
		}
		*buf++ = '.';
	}
	char temp[] = "in-addr.arpa.";
	for (int k = 0; k < strlen(temp); k++) {
		*buf++ = temp[k];
	}
	*buf = 0;
}
int DNS::QueryConstructorINADDR(char*buf, char*host) {
	char* url[10];
	int i = 0;
	char *firstoccur = NULL;
	while (strchr(host, '.') != NULL) {
		firstoccur = strchr(host, '.') + 1;
		if (firstoccur == NULL) {
			return -1;
		}
		*(host + (firstoccur - host - 1)) = '\0';
		url[i++] = host;
		host = firstoccur;

	}
	url[i++] = host;
	url[i] = 0;
	for (int j = 0; j < i; j++) {
		*buf++ = strlen(url[j]);
		int k = 0;
		while (k < strlen(url[j]) && url[j][k] != 0) {
			*buf++ = url[j][k];
			k += 1;
		}
		if (k < strlen(url[j]) && url[j][k]!= 0) {
			cout << "\t++Truncated Name " << endl;
			return -1;
		}
	}
	*buf = 0;
	return 0;

}
void DNS::QueryConstructor(char* buf, char*host) {
	char *firstdot, *secondot;
	char* url[3];
	firstdot = strchr(host, '.')+1;
	if (firstdot == NULL) {
		return;
	}
	*(host + (firstdot - host-1)) = '\0';
	url[0] = host;
	secondot = strchr(firstdot, '.')+1;
	if (secondot == NULL) {
		return;
	}
	*(firstdot + (secondot - firstdot-1)) = '\0';
	url[1] = firstdot;
	url[2] = secondot;

	for (int i = 0; i < 3; i++) {
		*buf++ = strlen(url[i]);
		int j = 0;
		while (j < strlen(url[i])) {
			*buf++ = url[i][j];
			j += 1;
		}
	}
	*buf = 0;


}

void DNS::preprocess(char *host, char *dns_server) {
	WSADATA wsaData;
	int iResult;
	int length = 0;
	int dot = 0;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return;
	}
	char packet[512];
	char ip[1024];
	int type = 0;
	int val = inet_addr(host);
	if (val == -1) {
		type = DNS_A;
		length = strlen(host);
		dot = 2;
	}
	else {
		type = DNS_PTR;
		QueryConstructorptr(host, ip);
		length += strlen(ip);
		dot = 6 - 5;
		//host = QueryConstructorptr(host);
	}
	SOCKET sock;
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		printf("LAst error %d", WSAGetLastError());
		return;
	}

	int pkt_size = dot + length + sizeof(FixedDNSheader) + sizeof(QueryHeader);
	FixedDNSheader *fdh = (FixedDNSheader *)&packet;
	QueryHeader *qh = (QueryHeader *)(packet + pkt_size - sizeof(QueryHeader));
	u_short id = static_cast<u_short>(GetCurrentProcessId());
	fdh->ID = htons(static_cast<u_short>(GetCurrentProcessId()));
	fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	fdh->nadditional = 0;
	fdh->nanswers = 0;
	fdh->nquestions = htons(1);
	fdh->nauthority = 0;
	int truncated = 0;

	if (type == DNS_A) {
		printf("Lookup : %s\n", host);
		printf("Query : %s, type %d, TXID 0x%.4x\n", host, DNS_A, ntohs(fdh->ID));
		if (QueryConstructorINADDR((char*)(fdh + 1), host) == -1) {
			return;
		}
	}
	else {
		printf("Lookup : %s\n", ip);
		printf("Query : %s, type %d, TXID 0x%.4x\n", ip, DNS_PTR, ntohs(fdh->ID));
		QueryConstructorINADDR((char *)(fdh + 1), ip);
		if (QueryConstructorINADDR((char*)(fdh + 1), ip) == -1) {
			return;
		}
		//	QueryConstructorptr((char *)(fdh + 1), host);
	}
	qh->qClass = htons(DNS_INET);
	struct DNSRecord answers[20], authority[20], additional[20];
	qh->qType = htons(type);
	printf("Server : %s\n", dns_server);
	printf("*********************************\n");
	struct sockaddr_in remote, response;
	memset(&remote, 0, sizeof(remote));

	remote.sin_family = AF_INET;
	remote.sin_addr.S_un.S_addr = inet_addr(dns_server); // server’
	remote.sin_port = htons(53);
	struct sockaddr_in ipaddress;
	timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	unsigned char recvbuf[512] = { -1 };
	int count = 0;
	DWORD t = timeGetTime();
	while (count++ < 3) {
		cout << endl;
		if (sendto(sock, packet, 512, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
			printf("++Last error %d", WSAGetLastError());
			continue;
		}
		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		
		int available = select(0, &fd, NULL, NULL, &tv);
		if (available == 0) {
			printf("\t++Timeout has occured \n");
			continue;
			}
		
		int i = sizeof(response);
		int iresult = 0;
		if (available > 0) {
			 iresult = recvfrom(sock, (char*)recvbuf, 512, 0, (struct sockaddr*)&response, &i);
		}
		if (iresult == SOCKET_ERROR) {
			printf("++Last Error Status %d\n", WSAGetLastError());
			continue;
		}
	
		DWORD time = timeGetTime() - t;
		if (response.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || response.sin_port != remote.sin_port) {
			printf("\t\t++Bogus Different Request Address : %s and Response Address : %s \n ",inet_ntoa(remote.sin_addr),inet_ntoa(response.sin_addr));
			continue;
		}
		FixedDNSheader *fdhRecv = (FixedDNSheader *)(char*)recvbuf;
		cout << "Attempt " << count - 1 << " with " << pkt_size << " bytes ..... ";
		if (iresult == 512) {
			cout << "++Response Size has exceeded 512 bytes " << endl;
			continue;
		}
		cout << " response in " << time << " ms with " << iresult << " bytes " << endl;
		
		if (fdhRecv->ID != fdh->ID) {
			printf("\t\t++ invalid reply: TXID mismatch, sent 0x%.4x, received 0x%.4x ", fdh->ID, fdhRecv->ID);
			continue;
		}
		
		
		
		printf("\tTXID  0x%.4x flags 0x%.4x questions %d answers %d authority %d additional %d\n", ntohs(fdhRecv->ID), ntohs(fdhRecv->flags), ntohs(fdhRecv->nquestions), ntohs(fdhRecv->nanswers), ntohs(fdhRecv->nauthority), ntohs(fdhRecv->nadditional));
		u_short rcode = ntohs(fdhRecv->flags) & (u_short)15;
		if (rcode == 0) {
			printf("\tsucceeded with rcode %d ", rcode);
		}
		else {
			printf("\tfailed with rcode %d ", rcode);
			continue;
		}

		printf("\n\t-----------------------[Questions]---------------\n");
		QueryHeader *recvqh = (QueryHeader *)((char *)recvbuf + pkt_size - sizeof(QueryHeader));
		unsigned char *query = (unsigned char *)malloc(256);
		unsigned char *temp = (unsigned char *)(fdhRecv + 1);
		i = 0;
		int k = 0;
		int temp_Size = (const char *)recvqh - (const char*)temp;
		while (i < temp_Size) {
			query[k++] = *temp++;
			i++;
		}
		query[k] = 0;
		i = 0;
		while (i < strlen((const char *)query)) {
			int incrementer = query[i] + 1;
			query[i] = '.';
			i += incrementer;

		}
		if (fdh->nquestions != fdhRecv->nquestions) {
			cout << "\t++ The number of questions does not match in request and response " << endl;
			continue;
		}
		if (ntohs(fdhRecv->flags) & 512 == 512) {
			cout << "\t\t++ the message is truncated\n" << endl;
		}

		query += 1;
		printf("\t\t%s type %d class %d \n", query, ntohs(recvqh->qType), ntohs(recvqh->qClass));
		

		const char *temper = (const char *)(fdhRecv + 1);
		int size_temp = sizeof(FixedDNSheader) + sizeof(QueryHeader) + strlen(temper) + 1;
		unsigned char * query_start = (recvbuf + size_temp);
		int delim = 0;
		int ttl = 0;
		long *p;
		int count = ntohs(fdhRecv->nanswers);
		if (count > 0) {
			printf("\t-------------------[Answers]----------------------------\n");
		}
		u_short qtype, qclass;
		for (int i = 0; i < count; i++) {
			if (query == 0) {
				cout << "\t\t++Not enough Records" << endl;
			}
			char type[6] = { 0 };
			ttl = 0;
			u_short iplen = 0;
			answers[i].name = ParseResponse(query_start, recvbuf, &delim,iresult);
			if (answers[i].name == NULL) {
				break;
			}
			if (strlen((const char *)answers[i].name) == 0) {
				cout << "\t\t++Not enough Records" << endl;
				break;
			}
			query_start += delim;
			answers[i].fdrrh = (FixedResourceHeader*)(query_start);
			query_start += sizeof(struct FixedResourceHeader);		
			qtype = ntohs(answers[i].fdrrh->qtype);
			qclass = ntohs(answers[i].fdrrh->qclass);
			ttl = ntohl(answers[i].fdrrh->ttl);
			iplen = ntohs(answers[i].fdrrh->len);
			if (qtype == 1) {
				strcpy(type, "A");
				answers[i].actualresult = (unsigned char *)malloc(answers[i].fdrrh->len);
				for (int j = 0; j < iplen; j++)
				{
					answers[i].actualresult[j] = query_start[j];
				}
				answers[i].actualresult[ntohs(answers[i].fdrrh->len)] = 0;
				query_start = query_start + ntohs(answers[i].fdrrh->len);
				p = (long*)answers[i].actualresult;
				ipaddress.sin_addr.s_addr = (*p);
				//cout << inet_ntoa(ipaddress.sin_addr) << endl;
				//printf("\t\t %s %s TTL = %d\n", answers[i].name, type, inet_ntoa(ipaddress.sin_addr), ttl);
				cout << "\t\t " << answers[i].name << " " << type << " " << inet_ntoa(ipaddress.sin_addr) << " TTL = " << ttl << endl;
			}
			else if (qtype == 12) {
				strcpy(type, "PTR");
				answers[i].actualresult = ParseResponse(query_start, recvbuf, &delim,iresult);
				query_start = query_start + delim;
				cout << "\t\t " << answers[i].name << " " << type << " " << answers[i].actualresult << " TTL = " << ttl << endl;

			}
			else if (qtype == 2) {
				strcpy(type, "NS");
				answers[i].actualresult = ParseResponse(query_start, recvbuf, &delim,iresult);
				query_start = query_start + delim;
				cout << "\t\t " << answers[i].name << " " << type << " " << answers[i].actualresult << " TTL = " << ttl << endl;
			}
			else if (qtype == 5) {
				strcpy(type, "CNAME");
				answers[i].actualresult = ParseResponse(query_start, recvbuf, &delim,iresult);
				query_start = query_start + delim;
				p = (long*)answers[i].actualresult;
				ipaddress.sin_addr.s_addr = (*p);
				cout << "\t\t " << answers[i].name << " " << type << " " << answers[i].actualresult << " TTL = " << ttl << endl;
			}
			else if (qtype == 28) {
				query_start += 16;
			}


		}
	
		count = ntohs(fdhRecv->nauthority);
		if (count > 0) {
			printf("\t-------------------[Authority]----------------------------\n");
		}	
		for (int i = 0; i < count; i++) {
			if (query == 0) {
				cout << "\t\t++Not enough Records" << endl;
			}
			authority[i].name = ParseResponse(query_start, recvbuf, &delim,iresult);
			if (strlen((const char *)authority[i].name) == 0) {
				cout << "\t\t ++Not enough Records" << endl;
				break;
			}
			if (authority[i].name == NULL) {
				break;
			}
			query_start += delim;
			authority[i].fdrrh = (FixedResourceHeader*)(query_start);

			query_start += sizeof(struct FixedResourceHeader);
			authority[i].actualresult = ParseResponse(query_start, recvbuf, &delim,iresult);
			query_start += delim;
			ttl = ntohl(authority[i].fdrrh->ttl);
			cout << "\t\t " << authority[i].name << " NS " << authority[i].actualresult << " TTL = " << ttl << endl;
		}
		count = ntohs(fdhRecv->nadditional);

		if (count > 0) {
			printf("\t-------------------[Additional]----------------------------\n");
		}
		for (i = 0; i<count; i++)
		{
			if (query == 0) {
				cout << "\t\t++Not enough Records" << endl;
			}
			additional[i].name = ParseResponse(query_start, recvbuf, &delim,iresult);
			if (strlen((const char *)additional[i].name) == 0) {
				cout << "\t\t++Not enough Records" << endl;
				break;
			}
			if (additional[i].name == NULL) {
				break;
			}
			query_start += delim;
			additional[i].fdrrh = (FixedResourceHeader*)(query_start);
			query_start += sizeof(FixedResourceHeader);
			if (sizeof(FixedResourceHeader) > 10) {
				cout << "++ Invalid reply : greater than Fixed Header" << endl;
			}
			if (sizeof(FixedResourceHeader) < 10) {
				cout << "++ Invalid reply : smaller than Fixed Header" << endl;
			}
			
			qtype = ntohs(additional[i].fdrrh->qtype);
			ttl = ntohl(additional[i].fdrrh->ttl);
			if (qtype == 1)
			{
				additional[i].actualresult = (unsigned char*)malloc(ntohs(additional[i].fdrrh->len));
				for (int j = 0; j<ntohs(additional[i].fdrrh->len); j++)
					additional[i].actualresult[j]= query_start[j];

				additional[i].actualresult[ntohs(additional[i].fdrrh->len)] = '\0';
				query_start += ntohs(additional[i].fdrrh->len);
				p = (long*)additional[i].actualresult;
				ipaddress.sin_addr.s_addr = (*p);
				cout << "\t\t " << additional[i].name << " A " << " " << inet_ntoa(ipaddress.sin_addr) << " TTL = " << ttl << endl;
			}
			else if (qtype == 28) {
				query_start += 16;
			}
			else
			{
				additional[i].actualresult = ParseResponse(query_start, recvbuf, &delim,iresult);
				query_start += delim;
			}
		}
		if (recvbuf[iresult - 1] == 192) {
			cout << "\t\t++Jump Offset truncated\n" << endl;
		}
		return;
	}
	closesocket(sock);
}

