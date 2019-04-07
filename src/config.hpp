#ifndef CONFIG_HPP_
#define CONFIG_HPP_

#define VERSION 		"0.3.x"

#define MAX_ADRESS_SIZE 256
#define MAX_POOLNAME_SIZE 128
#define MAX_PASSWORD_SIZE 256
#define CONFIG_FILENAME "config.json"
#define MAX_GPUS		32
#define DEFAULT_CONSOLE_REFRESH_RATE	30

enum CryptoType {
	MoneroCrypto,
	WowneroCrypto,
	AeonCrypto,
	TurtleCrypto
};

// memory size = cu * factor * sizeof(scratchpad 1 or 2 MB)
typedef struct GpuConfig {
	int index;
	int cu;
	int factor;
	int worksize;
	int chunk2;
} GpuConfig;

typedef struct Config {
	int  memFactor;
	int  iterationFactor;
	char address[MAX_ADRESS_SIZE];
	char poolAddress[MAX_POOLNAME_SIZE];
	char poolPassword[MAX_PASSWORD_SIZE];
	int  poolPort;
	CryptoType type;
	int 	nbGpus;
	bool  debugNetwork;
	int   consoleListenPort;
	int   consoleRefreshRate;
	struct GpuConfig gpus[MAX_GPUS];
} Config;

void makeConfig();
bool readConfig();
bool checkConfig();
uint32_t  getMemFactor(CryptoType);
uint32_t  getIterationFactor(CryptoType c);
extern Config config;

#endif /* CONFIG_HPP_ */
