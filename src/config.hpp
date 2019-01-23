#ifndef CONFIG_HPP_
#define CONFIG_HPP_

#define VERSION 		"0.1"

#define MAX_ADRESS_SIZE 256
#define MAX_POOLNAME_SIZE 128
#define MAX_PASSWORD_SIZE 256
#define CONFIG_FILENAME "config.json"
#define MAX_GPUS		32

enum CryptoType {
	MoneroCrypto,
	WowneroCrypto,
	AeonCrypto
};

// memory size = cu * factor * sizeof(scratchpad 1 or 2 MB)
typedef struct GpuConfig {
	int index;
	int cu;
	int factor;
	int worksize;
} GpuConfig;

typedef struct Config {
	bool isLight;
	char address[MAX_ADRESS_SIZE];
	char poolAddress[MAX_POOLNAME_SIZE];
	char poolPassword[MAX_PASSWORD_SIZE];
	int  poolPort;
	CryptoType type;
	int 	nbGpus;
	struct GpuConfig gpus[MAX_GPUS];
} Config;

void makeConfig();
bool readConfig();
bool checkConfig();
extern Config config;

#endif /* CONFIG_HPP_ */
