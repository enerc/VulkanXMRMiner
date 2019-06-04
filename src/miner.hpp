#ifndef MINER_HPP_
#define MINER_HPP_

#ifndef __aarch64__
#ifdef __MINGW32__
#include <windows.h>
#endif
#include <vulkan/vulkan.h>

#include "slow_hash.hpp"
#include "config.hpp"
#include "network.hpp"

#define SCRATCHPAD_SPLIT 1792
#define K12_LOCAL_SIZE_AMD	 256
#define K12_LOCAL_SIZE_NV	 128

struct VulkanMiner {
	int deviceId;
	VkDevice vkDevice;
	VkDeviceMemory gpuLocalMemory;
	VkDeviceMemory gpuSharedMemory;
	uint32_t threads[2];
	uint32_t cu;
	uint32_t local_size_x;
	uint32_t local_size_cn1;
	uint32_t groups[2];
	uint32_t stateSize;
	uint32_t inputsSize;
	uint32_t outputSize;
	uint32_t scratchSplit[2];
	uint64_t nonce;
	uint64_t scratchpadSize[2];
	uint64_t scratchpadsSize1;
	uint64_t scratchpadsSize2;
	uint32_t debugSize;
	uint64_t target;
	uint32_t variant;
	uint32_t height;
	uint32_t index;
	uint32_t chunk2;
	uint64_t local_memory_size;
	uint64_t shared_memory_size;
	VkBuffer gpu_scratchpadsBuffer1;
	VkBuffer gpu_scratchpadsBuffer2;
	VkBuffer gpu_statesBuffer;
	VkBuffer gpu_branchesBuffer;
	VkBuffer gpu_params;
	VkBuffer gpu_constants;
	VkBuffer gpu_inputsBuffer;
	VkBuffer gpu_outputBuffer;
	VkBuffer gpu_debugBuffer;
	VkDescriptorSet descriptorSet;
	VkPipelineLayout pipelineLayout;
	VkPipeline pipeline_cn0;
	VkPipeline pipeline_cn1;
	VkPipeline pipeline_cn1b;
	VkPipeline pipeline_cn2;
	VkPipeline pipeline_cn3;
	VkPipeline pipeline_cn4;
	VkPipeline pipeline_cn5;
	VkPipeline pipeline_cn6;
	VkPipeline pipeline_cn7;
	VkPipeline pipeline_k12;
	VkPipeline pipeline_cn8_1;
	VkCommandPool commandPool;
	VkCommandBuffer vkCommandBuffer;
	VkDescriptorPool descriptorPool;
	VkShaderModule shader_module;
	VkDescriptorSetLayout descriptorSetLayout;
	VkQueue queue;
	VkFence drawFence;
	VkMemoryBarrier memoryBarrier;
	uint64_t *resultPtr;
	unsigned char input[MAX_BLOB_SIZE/2];
	unsigned char originalInput[MAX_BLOB_SIZE/2];
	unsigned char noncedInput[MAX_BLOB_SIZE/2];
	int 	inputLen;
	CPUMiner cpuMiner;
	bool	commandBufferFilled;
	int 	nrResults;
	uint32_t iterationFactor;
	uint32_t memFactor;
	uint32_t alignment;
	uint64_t   tmpResults[256];
	uint64_t   cnrHeight;
	uint64_t   cnrSubmittedHeight;
	CryptoType currentCrypto;
};

void initVulkanMiner(VulkanMiner &vulkanMiner,VkDevice vkDevice, CPUMiner cpuMiner, uint32_t threads, uint32_t local_size_cn1, uint32_t cu, uint32_t chunk2, int deviceId, int index);
void loadSPIRV(VulkanMiner &vulkanMiner);
void minerIterate(VulkanMiner &vulkanMiner);
void reloadInput(VulkanMiner &vulkanMiner, int64_t nonce);
void sendMiningParameters(VulkanMiner &vulkanMiner);
void mapMiningResults(VulkanMiner &vulkanMiner);
void unmapMiningResults(VulkanMiner &vulkanMiner);
void shutdownDevice(VulkanMiner &vulkanMiner);
void findBestSetting(VkDevice vkDevice,int deviceId, int &cu, int &factor, int &localSize, int memFactor,CryptoType type);

#ifdef __MINGW32__
DWORD WINAPI MinerThread(LPVOID args);
#else
void *MinerThread(void *args);
#endif

#endif // __aarch64__

#ifdef __MINGW32__
DWORD WINAPI K12CpuMinerThread(LPVOID args);
#else
void *K12CpuMinerThread(void *args);
#endif

void initMiners();
void incGoodHash(int gpuIndex);
void incBadHash(int gpuIndex);
int getGoodHash(int gpuIndex);
int getBadHash(int gpuIndex);
uint64_t getHashRates(int index);
void setHashRates(int index, uint64_t v);

#endif /* MINER_HPP_ */
