/* main.cpp
* CSCE 463 Sample Code
* by Dmitri Loguinov
*/

#include "stdafx.h"
#include "Socket.h"
#include "HTMLParserBase.h"
#include<sstream>
#include<unordered_set>


using namespace std;
struct fragments {
	char *host;
	char *port;
	char *query;
	char *frag;
	char *path;
};
struct fragments * parseurl(char *line) {
	struct 	fragments *url = (struct fragments *)malloc(sizeof(struct fragments));
	char *host_delim, *port_delim, *path_delim, *query_delim, *frag_delim, *temp;
	host_delim = strchr(line, '/') + 2;
	port_delim = strchr(host_delim, ':');
	if (port_delim == NULL) {
		temp = host_delim;
	}
	else {
		temp = port_delim;
	}
	path_delim = strchr(host_delim, '/');
	if (path_delim == NULL) {
		temp = host_delim;
	}
	else {
		temp = path_delim;
	}
	query_delim = strchr(host_delim, '?');
	if (query_delim == NULL) {
		temp = host_delim;
	}
	else {
		temp = query_delim;
	}
	frag_delim = strchr(host_delim, '#');

	char *prev = NULL;
	//	cout <<"host="<<host_delim<<"port="<<port_delim<<"query="<<query_delim<<"path_delim="<<path_delim<<"frag_delim="<<frag_delim<<endl;
	if (frag_delim != NULL) {
		prev = frag_delim;
		url->frag = frag_delim + 1;
		//cout << "flag " << url->frag << endl;;
	}
	else {
		url->frag = NULL;
	}

	if (prev != NULL && query_delim != NULL) {
		*(query_delim + (prev - query_delim)) = '\0';
	}
	if (query_delim != NULL && ((prev != NULL &&  prev>query_delim) || (prev == NULL))) {
		url->query = query_delim + 1;
		//cout << "query " << url->query << endl;
		prev = query_delim;
	}
	else {
		url->query = NULL;
	}

	if (prev != NULL && path_delim != NULL) {
		*(path_delim + (prev - path_delim)) = '\0';
	}
	if (path_delim != NULL && ((prev != NULL &&  prev>path_delim) || (prev == NULL))) {
		prev = path_delim;
		url->path = path_delim + 1;
		//cout << "path " << url->path << endl;;
	}
	else {
		url->path = NULL;
	}
	if (prev != NULL && port_delim != NULL) {
		*(port_delim + (prev - port_delim)) = '\0';
	}
	if (port_delim != NULL && ((prev != NULL && prev >port_delim) || (prev == NULL))) {
		prev = port_delim;
		url->port = port_delim + 1;

		//cout << "port " << url->port << endl;;
	}
	else {
		url->port = NULL;
	}
	if (prev != NULL && host_delim != NULL) {
		//cout << prev - host_delim << endl;
		*(host_delim + (prev - host_delim)) = '\0';
	}

	if (host_delim != NULL && ((prev != NULL && prev >host_delim) || (prev == NULL))) {
		url->host = host_delim;
		//cout << "host " << url->host << endl;;
	}
	else {
		url->host = NULL;
	}


	return url;
}
queue<url> Producer(LPVOID param, char* fileName) {
	Parameters *p = ((Parameters*)param);

	ifstream file(fileName);
	streampos begin, end;
	if (file.is_open()) {
		begin = file.tellg();
		file.seekg(0, ios::end);
		end = file.tellg();
		printf("Opened URL-input.txt with size %d bytes\n", end - begin);
		file.seekg(0, ios::beg);
		struct url *urltemp = (struct url*)malloc(sizeof(url));
		while (file.getline(urltemp->data, sizeof(urltemp->data))) {
			p->urlque.push(*urltemp);
		}
	}
	else {
		cout << "\tFile Opening Failed" << endl;;
		}
	
	return p->urlque;
}
//scheme://host[:port][/path][?query][#fragment] 
UINT Consumer(LPVOID param) {
	Parameters* p = ((Parameters*)param);
	LONG Semcount = 0;
	while (true) {
		WaitForSingleObject(p->mutex, INFINITE);
		if (p->urlque.size() == 0) {
			ReleaseMutex(p->mutex);
			//ReleaseSemaphore(p->finished, 1, NULL);
			return 0;
		}
		struct url buff;
		buff = p->urlque.front();
		p->urlque.pop();
		struct fragments *url = parseurl(buff.data);
		int prev = p->urlMap.size();
		string my_string(url->host);
		p->urlMap.insert(my_string);
		if (p->urlMap.size() > prev) {
			//printf("\tHost Uniqueness .. .Passed\n");
		}
		else {
			//printf("\tHost Uniqueness .. .Failed\n");
		}
		ReleaseMutex(p->mutex);
		if (ReleaseSemaphore(p->finished, 1, &(p->numActive)) == 0) {
			//printf("\t The error is %d\n", GetLastError());
		}
		Socket s;
		char request[1024] = { 1};;
		strcat(request, "/");
		if (url->path != NULL) {
			strcat(request, url->path);
		}
		if (url->query != NULL) {
			strcat(request, url->query);
		}
		p->time = timeGetTime();
		s.EstablishConnection(url->host, request, p);
		
	}
	//printf("threadA %d quitting on event\n", GetCurrentThreadId());
	//SetEvent(p->eventQuit);
	return 0;
}
UINT Stats(LPVOID param) {
	Parameters *p = ((Parameters*)param);
	int counter = 0;
	while (true) {
		counter += 2;
		int alive = p->totalThread - p->numActive;
		if (alive == 0) {
			break;
		}
		DWORD speed;
		printf("[ 3%d]%dQ%6d%7dE%6dH%6dD%5dI%5dR%5dC%5dL\n",counter,p->totalThread-p->numActive,p->urlque.size(),p->urlMap.size(),p->HostUniq,p->DNSLook,p->IPuniq,p->Robots,p->sucURl,p->nlinks);
		if (timeGetTime() == p->time) {
			speed = 0;
		}
		else {
			speed = p->bytes / (timeGetTime() - p->time);
		}
		printf("***Crawling %d ..@%d Mbps\n", p->bytes/1024,speed);
		Sleep(2000);
		
	}
	SetEvent(p->eventQuit);
	return 0;
}
int main(int argc, char *argv[]) {
	int singlemode = 0;
	int filenode = 0;
	if (argc == 1) {
		printf("Usage info:%s <number>\n", argv[0]);
	}
	else if (argc == 2) {
		printf("You have passed a single url as a commandline arguments");
		singlemode = 1;
	}
	else if (argc == 3) {
		stringstream ss(argv[1]);
		int numthread;
		ss >> numthread;
		Parameters p;
		p.DNSLook = 0;
		p.HostUniq = 0;
		p.IPuniq = 0;
		p.nlinks = 0;
		p.numActive = 0;
		p.totalThread = numthread;
		p.sucURl = 0;
		cout << "Arg" << argv[2] << endl;
		Producer(&p, argv[2]);
		HANDLE *handles = new HANDLE[p.totalThread+1];
		p.mutex = CreateMutex(NULL, 0, NULL);
		p.finished = CreateSemaphore(NULL, 0, numthread, NULL);
		p.eventQuit = CreateEvent(NULL, true, false, NULL);
		p.bytes = 0;
		
		//cout << "producer size" << p.urlque.size() << endl;
		handles[numthread] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Stats, &p, 0, NULL);
		for (int i = 0; i < numthread; i++) {
			handles[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Consumer, &p, 0, NULL);
		}
		for (int i = 0; i <= numthread; i++)
		{
			WaitForSingleObject(handles[i], INFINITE);
			CloseHandle(handles[i]);
		}
	}
	system("pause");
	return 0;
}