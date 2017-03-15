// hw2_4_march.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DNS.h"

int main(int argc,char **argv)
{

	if (argc < 3) {
	
		cout << "please enter the correct number of arguments\n" << endl;
	}
	else {
		DNS dns;
		dns.preprocess(argv[1], argv[2]);
	}
	
	
	
	system("pause");
	return 0;
}

