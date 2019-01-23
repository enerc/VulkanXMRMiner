/*
 Cryptonight Vulkan Mining Software
 Copyright (C) 2019  enerc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#ifdef __MINGW32__
#include <ws2tcpip.h>
#include <winsock.h>
#include <winsock2.h>
#else
#include <termios.h>
#endif
#include <fcntl.h>
#include <unistd.h>


#include "log.hpp"
#include "config.hpp"
#include "miner.hpp"
#include "network.hpp"
#include "mvulkan.hpp"

using namespace std;
static const char *CryptoNames[] = { "monero", "wownero", "aeon" };

Config config;

static const char* getJSONEntryLocation(const char *s, int len, const char *needle, bool isFatal)  {
	const char *loc = strstr(s, needle);
	if (loc == NULL && isFatal) {
		error("Mandatory configuration property not found:",needle);
		exitOnError("Fix config.json file");
	}
	if (loc == NULL)
		return nullptr;

	loc ++;	// skip "
	int i = loc - s;
	while (i < len && (*loc) != '"') {
		i++;
		loc ++;
	}
	if (i == len)
		return nullptr;
	return loc;
}

static void fillStringProperty(char *property, int len, const char*src) {
	while (*src != 0 && *src != '"') src++;
	if (*src == 0) return;
	src++;
	while (*src != 0 && *src != '"') src++;
	if (*src == 0) return;
	src++;
	int i = 0;
	while (i < len-1 && src[i] != '"') {
		property[i] = src[i];
		i++;
	}
	property[i] = 0;
}

static int getIntProperty(const char*src) {
	while (*src != 0 && *src != ':') src++;
	if (*src == 0) return 0;
	src++;	// skip :

	while (*src != 0 && (*src < '0' || *src > '9')) src++;
	if (*src == 0) return 0;

	char tmp[16];
	int i = 0;
	while (*src >= '0' && *src <= '9' && i < 16) {
		tmp[i] = *src;
		src++;
		i++;
	}
	tmp[i] = 0;
	return atoi(tmp);
}

static string createJsonFromConfig() {
	ostringstream s;
	s << "{\n";
	s << " \"crypto\" : \"" << CryptoNames[config.type] << "\",\n";
	s << " \"pool_address\" : \"" << config.poolAddress << ":" << config.poolPort<< "\",\n";
	s << " \"wallet_address\" : \"" << config.address << "\",\n";
	s << " \"pool_password\" : \"" << config.poolPassword << "\",\n";
	s << " \"cards\" : [\n";
	for (int i=0; i < config.nbGpus; i++) {
		s << "  {\n";
		s << "    \"index\"    : \"" << config.gpus[i].index << "\",\n";
		s << "    \"cu\"       : \"" << config.gpus[i].cu << "\",\n";
		s << "    \"factor\"   : \"" << config.gpus[i].factor << "\",\n";
		s << "    \"worksize\" : \"" << config.gpus[i].worksize << "\"\n";
		s << "  }";
		if (i< config.nbGpus -1) s << ",";
		s << "  \n";
	}
	s << " ]\n";
	s << "}\n";
	return s.str();
}

static void decodeConfig(const char *conf)  {
	const char *loc;
	int len = strlen(conf);
	char tmp[256];

	// decode crypto name
	loc = getJSONEntryLocation(conf,len,"crypto",false);
	config.type = MoneroCrypto;
	config.isLight = false;
	if (loc != nullptr) {
		fillStringProperty(tmp,128,loc);
		if (strcmp(tmp,"wownero") == 0) config.type = WowneroCrypto;
		else if (strcmp(tmp,"monero") == 0) config.type = MoneroCrypto;
		else if (strcmp(tmp,"aeon") == 0) {
			config.type = AeonCrypto;
			config.isLight = true;
		} else {
			error("unrecognized crypto name","assume Monero");
		}
	}

	// decode wallet
	loc = getJSONEntryLocation(conf,len,"pool_address",true);
	fillStringProperty(tmp,256,loc);
	int i =0;
	while (tmp[i] != ':' && tmp[i] != 0 && i < MAX_POOLNAME_SIZE) {
		config.poolAddress[i] = tmp[i];
		i ++;
	}
	config.poolAddress[i] = 0;
	i++;
	config.poolPort = atoi(tmp+i);

	// decode wallet
	loc = getJSONEntryLocation(conf,len,"wallet_address",true);
	fillStringProperty(config.address,MAX_ADRESS_SIZE,loc);

	// decode password - can be empty but must be defined
	loc = getJSONEntryLocation(conf,len,"pool_password",true);
	fillStringProperty(config.poolPassword,MAX_PASSWORD_SIZE,loc);

	loc = getJSONEntryLocation(conf,len,"cards",true);
	int cardIndex = 0;
	while (loc != nullptr && cardIndex < MAX_GPUS) {
		const char *p = loc;
		len = strlen(p);
		p = getJSONEntryLocation(p,len,"index",false);
		if (p == nullptr)
			break;
		config.gpus[cardIndex].index = getIntProperty(loc);
		loc = getJSONEntryLocation(p,len,"cu",false);
		if (loc != nullptr)
			config.gpus[cardIndex].cu = getIntProperty(loc);
		else
			config.gpus[cardIndex].cu = 14;
		loc = getJSONEntryLocation(p,len,"factor",false);
		if (loc != nullptr)
			config.gpus[cardIndex].factor = getIntProperty(loc);
		else
			config.gpus[cardIndex].factor = 16;
		loc = getJSONEntryLocation(p,len,"worksize",false);
		if (loc != nullptr)
			config.gpus[cardIndex].worksize = getIntProperty(loc);
		else
			config.gpus[cardIndex].worksize = 8;
		if (config.gpus[cardIndex].worksize != 8 && config.gpus[cardIndex].worksize != 16) {
			exitOnError("unsupported worksize - only 8 and 16 are supported");
		}
		p++;
		while (*p != '}' && *p != 0) p++;

		loc = p;
		if (*loc == 0)
			exitOnError("Malformed JSON configuration file");

		cardIndex ++;
	}
	config.nbGpus = cardIndex;
}

static void setTerminalBehavior() {
#ifndef __MINGW32__
	int oldfl = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL,  oldfl & ~O_NONBLOCK);
#endif
}


static string filterComments(const string & s) {
	string ret;

	for (uint32_t i=0; i< s.size(); i++) {
		if (s.at(i) == '/' && s.at(i+1) == '/') {
			while (s.at(i) != '\n' && i < s.size())
				i++;
		}
		if (s.at(i) == '/' && s.at(i+1) == '*') {
			i += 2;
			while (i < s.size() && !(s.at(i) == '*'  && s.at(i+1) == '/' )) {
				i++;
			}
			i += 2;
		}
		ret.push_back(s.at(i));
	}
	return ret;
}

void makeConfig() {
	std::string input;
	setTerminalBehavior();
	cout << "Please use recent drivers for better support and performance. Vulkan is a pretty new API.\n";
	cout << "You can get more about Vulkan at https://www.amd.com/en/technologies/vulkan or https://developer.nvidia.com/vulkan-driver \n\n";
	cout << "\nNo config.json file found, entering configuration setup...\n";

select1:
	cout << "Select a crypto:\n";
	cout << " 0 for Monero\n";
	cout << " 1 for Wownero\n";
	cout << " 2 for Aeon - cryptonight light\n";
	cout << "Your crypto: ";
	config.type = MoneroCrypto;
    std::getline(cin, input );
    if ( !input.empty() ) {
        istringstream stream( input );
        int s;
        stream >> s;
        config.type = (CryptoType)s;
    }
	if (config.type > AeonCrypto) {
		cout << "Wrong selection!!\n";
		goto select1;
	}

	switch (config.type) {
		case MoneroCrypto:
			cout<<" __  __							 \n";
			cout<<"|  \\/  | ___  _ __   ___ _ __ ___   \n";
			cout<<"| |\\/| |/ _ \\| '_ \\ / _ \\ '__/ _ \\  \n";
			cout<<"| |  | | (_) | | | |  __/ | | (_) | \n";
			cout<<"|_|  |_|\\___/|_| |_|\\___|_|  \\___/  \n";
			break;
		case WowneroCrypto:
			cout<<"__        _______        __  _   \n";
			cout<<"\\ \\      / / _ \\ \\      / / | |  \n";
			cout<<" \\ \\ /\\ / / | | \\ \\ /\\ / /  | |  \n";
			cout<<"  \\ V  V /| |_| |\\ V  V /   |_|  \n";
			cout<<"   \\_/\\_/  \\___/  \\_/\\_/    (_)  \n";
			break;

		case AeonCrypto:
			cout<<"    _                      \n";
			cout<<"   / \\   ___  ___  _ __    \n";
			cout<<"  / _ \\ / _ \\/ _ \\| '_ \\   \n";
			cout<<" / ___ \\  __/ (_) | | | |  \n";
			cout<<"/_/   \\_\\___|\\___/|_| |_|  \n";
			break;
	}

	cout << "\n";
	config.isLight = config.type == AeonCrypto;

select2:
	cout << "Mining pool address (hostname/IP): ";
    getline(cin, input );
    if ( input.empty() ) goto select2;
    else {
        istringstream stream( input );
        stream >> config.poolAddress;
    }

select3:
	cout << "Mining pool port: ";
    getline(cin, input );
    if ( input.empty() ) goto select3;
    else {
        istringstream stream( input );
        stream >> config.poolPort;
    }

	if (!lookForPool(config.poolAddress,config.poolPort,1)) {
		cout << "Can't connect to the pool at " << config.poolAddress << ":" << config.poolPort << "\n";
		goto select2;
	}
	closeConnection(1);

select4:
	cout << "Your address (with optional .something at the end): ";
    getline(cin, input );
    if ( input.empty() ) goto select4;
    else {
        istringstream stream( input );
        stream >> config.address;
    }
	cout << "Password (or x if none): ";
    getline(cin, input );
    if ( !input.empty() ) {
        istringstream stream( input );
        stream >> config.poolPassword;
    } else {
    	config.poolPassword[0] = 'x';
    	config.poolPassword[1] = 0;
    }

	int nbDevices = vulkanInit();

	cout << "\nChecking your cards\n";
	char deviceName[256];
	for (int i=0; i< nbDevices; i++ ) {
		getDeviceName(i,deviceName);
		cout << "Index:" << i <<" MemorySize:" << getMemorySize(i) << " Gb - " << deviceName << "\n";
	}

	cout << "\nFinding best configuration....\n";
	int cardIndex = 0;
	for (int i=0; i< nbDevices; i++ ) {
		VkDevice d = createDevice(i,getComputeQueueFamillyIndex(i));
		int cu,local_size,factor;
		findBestSetting(d,i,cu,factor,local_size,config.isLight);
		cout << "Card:" << i << "  " << cu << " Compute Units/Stream Multiprocessors";
		cout << ", using factor " << factor << " (" << (factor*cu) << " threads)";
		cout << ", local size " << local_size << "\n";
		cout << "Use this card [Y/n]?: ";
	    getline(cin, input );
	    char c = 'y';
	    if ( !input.empty() ) {
	        istringstream stream( input );
	        stream >> c;
	    }
		if (c != 'Y' && c != 'y') continue;

		config.gpus[cardIndex].index = i;
		config.gpus[cardIndex].cu = cu;
		config.gpus[cardIndex].factor = factor;
		config.gpus[cardIndex].worksize = local_size;
		cout << "Number of Compute Units [" << cu << "]:";
	    getline(cin, input );
	    if ( !input.empty() ) {
	        istringstream stream( input );
	        stream >> config.gpus[cardIndex].cu;
	    }
		cout << "Factor [" << factor << "]:";
	    getline(cin, input );
	    if ( !input.empty() ) {
	        istringstream stream( input );
	        stream >> config.gpus[cardIndex].factor;
	    }
selectWS:
		cout << "Worksize [" << local_size << "]:";
	    getline(cin, input );
	    if ( !input.empty() ) {
	        istringstream stream( input );
	        stream >> config.gpus[cardIndex].worksize;
	    }
	    if (config.gpus[cardIndex].worksize != 8 && config.gpus[cardIndex].worksize != 16) {
	    	cout << "Invalid worksize (8 or 16)\n";
	    	goto selectWS;
	    }
		cardIndex++;
		cout << "\n";
	}
	config.nbGpus = cardIndex;

	string confStr = createJsonFromConfig();
	ofstream out("config.json");
	out << confStr;
	out.close();

	cout << "Proposed configuration:\n";
	puts(confStr.c_str());
	cout << "Play with the parameters for optimum hashrate.\n";
	cout << " _____        _               _  \n";
	cout << "| ____|_ __  (_) ___  _   _  | | \n";
	cout << "|  _| | '_ \\ | |/ _ \\| | | | | | \n";
	cout << "| |___| | | || | (_) | |_| | |_| \n";
	cout << "|_____|_| |_|/ |\\___/ \\__, | (_) \n";
	cout << "           |__/       |___/      \n\n";


	vulkanEnd();
#ifdef __MINGW32__
	Sleep(4);				// time to read before cmd exit
#endif
	exit(0);
}

bool readConfig() {
	ifstream in(CONFIG_FILENAME);
	string confStr((istreambuf_iterator<char>(in)),istreambuf_iterator<char>());
	in.close();
	confStr = filterComments(confStr);

	decodeConfig(confStr.c_str());
	return true;
}

bool checkConfig() {
	ifstream in(CONFIG_FILENAME);
	string confStr((istreambuf_iterator<char>(in)),istreambuf_iterator<char>());
	in.close();
	return confStr.size() > 0;
}
