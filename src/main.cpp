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
#include <iostream>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#ifdef __MINGW32__
#include <ws2tcpip.h>
#include <winsock.h>
#include <winsock2.h>
#include <conio.h>
#else
#include <termios.h>
#endif
#include <unistd.h>
#include <iomanip>

#include "config.hpp"
#include "mvulkan.hpp"
#include "constants.hpp"
#include "log.hpp"
#include "miner.hpp"
#include "network.hpp"
#include "slow_hash.hpp"
#include "miner.hpp"
#include "spirv.hpp"
#include "httpConsole.hpp"

using namespace std;

#ifdef __MINGW32__
static const char *START_STUCKED="";
static const char *START_GREEN="";
static const char *START_LIGHT_GREEN = "";
static const char *START_WHITE="";
#else
static const char *START_STUCKED = "\e[91m";
static const char *START_GREEN = "\e[32m";
static const char *START_LIGHT_GREEN = "\e[92m";
static const char *START_WHITE = "\e[39m";
#endif

#ifdef __MINGW32__
int getKey() {
	if(kbhit()) return getch();
	else return 0;
}
#else
int getKey() {
	struct termios oldt, newt;
	int oldf;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

	int ch = getchar();

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);

	if (ch != EOF)
		return ch;
	else
		return 0;
}
#endif

int main(int argc, char **argv) {
#ifdef __MINGW32__
	// init windows tcp sockets
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		error("Error initialising WSA.",NULL);
	}
#endif
	cout << "Vulkan SPIR-V XMR Miner " << VERSION << "\n\n" << flush;

	if (!checkConfig())
		makeConfig();

	readConfig();

	CPUMiner cpuMiner;
	memset(&cpuMiner, 0, sizeof(cpuMiner));
	cpuMiner.memFactor = config.memFactor;
	cpuMiner.type = config.type;
	cpuMiner.debugNetwork = config.debugNetwork;
	cpuMiner.hp_state = nullptr;

	initNetwork(cpuMiner);
	initMiners();

	if (lookForPool(config.poolAddress, config.poolPort, 0))
		connectToPool(config.address, config.poolPassword, 0);

	startNetworkBG();

	prepareGPUConstants();

	vulkanInit();

	while (getVariant() == 0) {
		cout << "Waiting for pool to send blob....\n";
		sleep(5);
	}
	cpuMiner.variant = getVariant();
	cout << "Using XMR Variant: " <<  cpuMiner.variant << "\n";

	pthread_t threads[MAX_GPUS];
	VulkanMiner miners[MAX_GPUS];
	for (int i = 0; i < config.nbGpus; i++) {
		char deviceName[256];
		int devId = config.gpus[i].index;
		getDeviceName(devId,deviceName);
		registerGpuName(i,deviceName);
		VkDevice vkDevice = createDevice(devId, getComputeQueueFamillyIndex(devId));
		initVulkanMiner(miners[i], vkDevice, cpuMiner, config.gpus[i].cu * config.gpus[i].factor, config.gpus[i].worksize, config.gpus[i].cu, devId, i);
		loadSPIRV(miners[i]);
		pthread_create(&threads[i], NULL, MinerThread, &miners[i]);
	}
	pthread_t consoleThread = startConsoleBG(config.consoleListenPort);
	setFrequency(30);

	cout << "Mining started.... (Press q to stop)\n";
	cout << "[Time] 'Total H/s' 'Good shares'/'Invalid shares'/'Expired shares' [GPU] H/s 'good hashes'/'bad hashes' \n";
	bool quit = false;

	float mHashrate[MAX_GPUS];
	int stucked[MAX_GPUS];
	for (int i = 0; i < config.nbGpus; i++) {
		mHashrate[i] = 0;
		stucked[i] = 0;
	}
	int loop = 0;

	while (!quit) {
		char c = getKey();
		quit = c == 'q';

		for (int i = 0; i < config.nbGpus; i++) {
			if (mHashrate[i] == 0)
				mHashrate[i] = hashRates[i];

			if (hashRates[i] != 0) {
				mHashrate[i] = 0.95 * mHashrate[i] + 0.05 * hashRates[i];
				hashRates[i] = 0;
				stucked[i] = 0;
			} else
				stucked[i]++;

			if (stucked[i] > 30)
				mHashrate[i] = 0;			//  stucked
		}
		if (loop == 30) {
			cout << START_GREEN;
			printDate();
			cout.unsetf(std::ios::floatfield);
			cout << fixed;
			cout.precision(1);
			float hashesPerSec = 0;
			for (int i = 0; i < config.nbGpus; i++)
				hashesPerSec += (mHashrate[i] / 1000.0);
			setHashesPerSec(hashesPerSec);

			int totalShares = 0;
			for (int i = 0; i < config.nbGpus; i++)
				totalShares += getGoodHash(i);
			setTotalShares(totalShares);

			cout << START_LIGHT_GREEN << hashesPerSec << "H/s " << START_GREEN << totalShares << "/" << getInvalidShares() << "/" << getExpiredShares() << " ";
			for (int i = 0; i < config.nbGpus; i++) {
				setHashRate(i,mHashrate[i] / 1000.0);
				cout << "[" << i << "]:" << (mHashrate[i] == 0 ? START_STUCKED : "") << (mHashrate[i] / 1000.0) << START_GREEN << "H/s " << getGoodHash(i) << "/" << getBadHash(i) << "  ";
			}
			cout << START_WHITE << "\n";
			loop = 1;
		} else
			loop++;

		cout << flush;
		sleep(1);
	}

	requestStop();
	cout << "Shutdown requested....\n";
	for (int i = 0; i < config.nbGpus; i++)
		pthread_join(threads[i], NULL);

	if (consoleThread != 0)
		pthread_join(consoleThread, NULL);
	stopConsoleBG();

	vulkanEnd();
#ifdef __MINGW32__
	WSACleanup();
#endif
	return 0;
}
