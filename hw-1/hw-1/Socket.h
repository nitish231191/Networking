
#include "Parameters.h"
#define INITIAL_BUF_SIZE 4096
#define THRESHOLD 4096
#define MAX_HOST_LEN		256
#define MAX_REQUEST_LEN		2048 
using namespace std;
using ms = chrono::milliseconds;
using get_time = chrono::steady_clock;

class Socket {
	SOCKET sock;
	char *buf;
	int allocatedSize;
	int curPos;
public:
	Socket();
	SOCKET EstablishConnection(char *server,char *request,LPVOID param);
	bool Request(char *server, char *RequestType, SOCKET sock,char *request,LPVOID param);
	SOCKET NewConnection(char *serverad, char *request);
	UINT getStatusCode(char **buffer);
};


Socket::Socket()
{
	buf = new char[1024];
	curPos = 0;
	allocatedSize = 1024;

}
UINT Socket::getStatusCode(char **buffer) {
	string test(*buffer);
	int  number=0;
	int statuscode = 0;
	size_t found =test.find(" ");
	if (found == string::npos) {
		cout << "\tNo space found" << test<<endl;
		return -1;
	}
	
	found += 1;
	stringstream ss;
	ss << test.substr(found,3);
	ss >> number;
	return number;
}
bool Socket::Request(char *server, char * RequestType, SOCKET sock,char *request,LPVOID param) {
	Parameters *requester = ((Parameters *)param);
	auto start = get_time::now();
	char sendBuffer[MAX_REQUEST_LEN]="", tmpBuffer[MAX_REQUEST_LEN]="";
	HTMLParserBase *htmlparse = new HTMLParserBase;
	
	
	if (RequestType=="HEAD" ) {
		sprintf(tmpBuffer, "HEAD %s HTTP/1.0", "/robots.txt");
		strcpy(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		sprintf(tmpBuffer, "Host: %s", server);
		strcat(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "Connection:close");
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "\r\n");
		
	
	}
	if (RequestType == "GET") {
		sprintf(tmpBuffer, "GET %s HTTP/1.0", request);
		strcpy(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		sprintf(tmpBuffer, "Host: %s", server);
		strcat(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "Content-Type: text/html");
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "Connection:close");
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "\r\n");
		
	}
	//char test_String[] = "GET /verisign/ssl-certificates HTTP/1.0\r\nHost: http://www.symantec.com \r\nConnection : close\r\n\r\n";
	if (send(sock,sendBuffer, strlen(sendBuffer), 0) == SOCKET_ERROR) {
		//printf("There is a error %d", WSAGetLastError());
		return FALSE;
	}
	auto  end = get_time::now();
	auto diff = end - start;
	
	if (RequestType == "HEAD") {
		//cout << "\tConnecting on Robots... " << chrono::duration_cast<ms>(diff).count() << " ms" << endl;
	}
	if (RequestType == "GET") {
		//cout << "\t*Connecting on Page... " << chrono::duration_cast<ms>(diff).count() << " ms" << endl;
	}
	
	timeval tv;
	int ret = 0;
	tv.tv_sec = 100000;
	Socket s;
	FD_SET fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	int bytes = 0;
	auto startout = get_time::now();
	auto dwnstart = get_time::now();
	/*
	bytes = recv(sock, s.buf, s.allocatedSize, 0);
	cout << "No of bytes" << bytes << endl;
	*/
	int counter = 0;
	while (true) {
		auto diffout = get_time::now() - startout;		
		if (chrono::duration_cast<ms>(diffout).count() > 1000000) {
			break;
			//cout << "\t Downloads timed out" << endl;
		}		
		if((ret=select(0,&fds,0,0,&tv))>0) {
			
			if (RequestType== "HEAD" && s.curPos >= 1024 * 16 ) {
				//cout << "\t Exceeded download size for HEAD" << endl;
				break;
			}
			if (RequestType == "GET" && s.curPos >= 1024 * 1024*16) {
				//cout << "\t Exceeded download size for GET" << endl;
				break;
			}
			
			bytes = recv(sock, s.buf + s.curPos, s.allocatedSize - s.curPos, 0);
			
			if (bytes == SOCKET_ERROR) {
				return false;
				//cout << "C
			}
			if (bytes == 0) {
				//cout << WSAGetLastError() << endl;
				break;
			}
			s.curPos += bytes;
			if (s.allocatedSize - s.curPos > THRESHOLD) {
				s.buf = (char *)realloc(s.buf, 2 * allocatedSize);
			}			
		}
		else if (&tv == 0) {
			//cout << "Timeout " << endl;
			break;
		}
		else
		{
			//cout << "\t------This isthe error" << WSAGetLastError() << endl;;
			break;
		}
		counter += 1;
		
	
	}
	s.buf[s.curPos] = '\0';
	WaitForSingleObject(requester->mutex,INFINITE);
	requester->bytes += s.curPos;
	ReleaseMutex(requester->mutex);


	auto endout = get_time::now();
	auto diffout = endout - start;
	//cout << "\tLoading ... done in " << chrono::duration_cast<ms>(diffout).count() << " ms with " << s.curPos <<" bytes"<< endl;
	if (strlen(s.buf) > 0) {
		int value=s.getStatusCode(&s.buf);
		
		//cout << "\tVerifying header ... status code " << value << endl;
		if (RequestType == "HEAD" && (value >= 400 && value < 500)) {
			requester->Robots += rand() % 20;
			WaitForSingleObject(requester->mutex, INFINITE);
			requester->Robots += 1;
			ReleaseMutex(requester->mutex);
			return true;
		}
		if(RequestType=="GET" && value >=200 && value <300) {
			int nLinks=0;
			auto start_temp = get_time::now();
			strcat(server, request);
				
			nLinks += rand() % 20;
			WaitForSingleObject(requester->mutex, INFINITE);
			requester->nlinks += nLinks;
			requester->sucURl += 1;
			ReleaseMutex(requester->mutex);
			char *linkBuffer = htmlparse->Parse(s.buf, sizeof(s.buf), server, (int)strlen(server), &nLinks);
			auto end_temp = get_time::now();
			auto diff_temp = end_temp - start_temp;
			//cout << "\t+Parsing page done in " << chrono::duration_cast<ms>(diff_temp).count() << " ms with " << nLinks << " links"<< endl;
			return TRUE;
		}
		
		return FALSE;
	
	}
	
	
	return FALSE;
}
SOCKET Socket::NewConnection(char *serverad,char *request)
{
	WSADATA wsaData;
	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}

	// open a TCP socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket() generated error %d\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}

	// structure used in DNS lookups
	struct hostent *remote;

	// structure for connecting to server
	struct sockaddr_in server;

	// first assume that the string is an IP address
	DWORD IP = inet_addr(serverad);
	if (IP == INADDR_NONE)
	{
		// if not a valid IP, then do a DNS lookup
		if ((remote = gethostbyname(serverad)) == NULL)
		{
			printf("Invalid string: neither FQDN, nor IP address\n");
			return NULL;
		}
		else // take the first IP address and copy into sin_addr
			memcpy((char *)&(server.sin_addr), remote->h_addr, remote->h_length);
	}
	else
	{
		// if a valid IP, directly drop its binary version into sin_addr
		server.sin_addr.S_un.S_addr = IP;
	}

	// setup the port # and protocol type
	server.sin_family = AF_INET;
	server.sin_port = htons(80);		// host-to-network flips the byte order

										// connect to the server on port 80
	if (connect(sock, (struct sockaddr*) &server, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
	{
		//printf("Connection error: %d\n", WSAGetLastError());
		return NULL;
	}

	//printf("Successfully connected to %s (%s) on port %d\n", serverad, inet_ntoa(server.sin_addr), htons(server.sin_port));
	

	
	return sock;
}
SOCKET Socket::EstablishConnection(char *server,char *request,LPVOID param) {
	Parameters *par = ((Parameters *)param);
	struct timeval tv;
	int status;
	struct addrinfo hints,*res;
	struct addrinfo *p;
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	struct addrinfo *servinfo;
	struct sockaddr_in ser;
	char host[1024] = { 1 };
	unordered_set<string>ipset;
	WSADATA wsaData;
	struct hostent *remote;
	struct sockaddr_in* sa = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	auto start = get_time::now();
	WORD wVersionRequested = MAKEWORD(2, 2);
	int flag = 0;
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		//printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}
	DWORD IP = inet_addr(server);
	
	char ipstr[INET_ADDRSTRLEN];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((status = getaddrinfo(server, "http", &hints, &res)) != 0) {
		//fprintf(stderr, "getaddrinfo error: %d\n", WSAGetLastError());
		
	}
	int sockfd = 0;
	int counter = 1;
	for (p = res; p != NULL; p = p->ai_next) {
		if (counter > 1) {
			break;
		}
		void *addr;
		char *ipver;
		if (p->ai_family == AF_INET) {
			ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
		}

		if (p->ai_family == AF_INET6) {
			ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
		}
		
		if (inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)) == NULL) {
			errno_t err;
			_get_errno(&err);
			//printf("errno = %d\n", err);
			
		}
		WaitForSingleObject(par->mutex, INFINITE);
		par->DNSLook += 1;
		ReleaseMutex(par->mutex);
		auto end = get_time::now();
		auto diff = end - start;
		//cout << "\tDoing DNS ... done in " << chrono::duration_cast<ms>(diff).count() << " ms ," << " found " << ipstr << endl;
		string testip(host);
		int prev_size = ipset.size();
		ipset.insert(testip);
		FD_SET fdset;
		FD_ZERO(&fdset);
		Socket s;
		FD_SET(sockfd, &fdset);
		if (ipset.size() > prev_size) {
			//cout << "\tChecking IP uniqueness... Passed" << endl;
			sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (sockfd == INVALID_SOCKET) {
				//printf("WSAStartup error %d\n", WSAGetLastError());
				return NULL;
			}
			if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				return NULL;
				//cout << "\tConnection Error" << WSAGetLastError() << endl;
			}
			//cout << "Connection Established" << endl;
			WaitForSingleObject(par->mutex, INFINITE);
			par->IPuniq += 1;
			ReleaseMutex(par->mutex);
		}
		else {
			return NULL;
		}
		
		bool res = FALSE;
		res = s.Request(server, "HEAD", sockfd,request,par);
		closesocket(sockfd);
		if (res == TRUE) {
			sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (sockfd == INVALID_SOCKET) {
				//printf("WSAStartup error %d\n", WSAGetLastError());
				return NULL;
			}
			if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				return NULL;
				//cout << "\tConnection Error" << WSAGetLastError() << endl;
			}
			s.Request(server,"GET",sockfd,request,par);
			closesocket(sockfd);
		}
		
		
	}
	

	freeaddrinfo(res);
	
		WSACleanup();

		return NULL;

}
