// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#include "windows.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <winsock.h>
#define DNS_QUERY (0 << 15)
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) 
#define DNS_QUERY (0 << 15)
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11)
#define DNS_AA (1<<10)
#define DNS_TC (1<<9)
#define DNS_RD (1<<8)
#define DNS_RA (1<<7)
#define DNS_PTR 12 
#define DNS_HINFO 13 
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 
#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_INET 1 




// TODO: reference additional headers your program requires here
