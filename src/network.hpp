#ifndef NETWORK_HPP_
#define NETWORK_HPP_

#define CONNECT_TIMEOUT 3
#define MINING_AGENT	"vulkan XMR miner"
#define DEV_HOST		"dev.vulkanmines.net"
#define DEV_PORT		8081
#define MAX_BLOB_SIZE 	256

void initNetwork(const CPUMiner &cpuMiner);
void closeNetwork();
bool lookForPool(const char *hostname, int port, int index);
bool connectToPool(const char *wallet, const char *password, int index);
void closeConnection(int index);
void getCurrentBlob(unsigned char *blob, int *size);
uint64_t getTarget();
uint32_t getHeight();
void applyNonce(unsigned char *input, int nonce);
void notifyResult(int nonce , const unsigned char *hash, unsigned char *blob, uint32_t height);
void startNetworkBG();
bool checkBlob(const unsigned char *blob);
bool getStopRequested();
void requestStop();
uint32_t getRandomNonce(int gpuIndex);
uint32_t getVariant();
int getInvalidShares();
int getExpiredShares();
int getCurrentPool();

#endif /* NETWORK_HPP_ */
