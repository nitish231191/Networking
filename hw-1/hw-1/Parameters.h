#pragma once
#include "stdafx.h"

using namespace std;
struct url {
	char data[1024] = { 1 };
};
class Parameters {
public:
	HANDLE mutex;
	HANDLE finished;
	HANDLE eventQuit;
	queue <url> urlque;
	LONG numActive, totalThread, nlinks, DNSLook, IPuniq, sucURl, HostUniq, Robots;
	unordered_set<string> urlMap;
	DWORD time;
	LONG bytes;
};