#ifndef MINER_HPP_
#define MINER_HPP_
#include "slow_hash.hpp"
#include "config.hpp"
#include "network.hpp"

#define SCRATCHPAD_SPLIT 1792


struct VulkanMiner {
	int deviceId;
	VkDevice vkDevice;
	VkDeviceMemory gpuLocalMemory;
	VkDeviceMemory gpuSharedMemory;
	uint32_t threads;
	uint32_t cu;
	uint32_t local_size_x;
	uint32_t local_size_cn1;
	uint32_t groups;
	uint32_t stateSize;
	uint32_t inputsSize;
	uint32_t outputSize;
	uint32_t scratchSplit;
	uint32_t nonce;
	uint64_t scratchpadSize;
	uint64_t scratchpadsSize1;
	uint64_t scratchpadsSize2;
	uint32_t debugSize;
	uint32_t target;
	uint32_t variant;
	uint32_t height;
	uint32_t index;
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
	VkPipeline pipeline_cn8_1;
	VkCommandPool commandPool;
	VkCommandBuffer vkCommandBuffer;
	VkDescriptorPool descriptorPool;
	VkShaderModule shader_module;
	VkDescriptorSetLayout descriptorSetLayout;
	VkQueue queue;
	VkFence drawFence;
	VkMemoryBarrier memoryBarrier;
	uint32_t *resultPtr;
	unsigned char input[MAX_BLOB_SIZE/2];
	unsigned char originalInput[MAX_BLOB_SIZE/2];
	int 	inputLen;
	CPUMiner cpuMiner;
	bool	commandBufferFilled;
	bool	highMemory;
	int 	nrResults;
	uint32_t 	tmpResults[256];
};

extern uint64_t hashRates[MAX_GPUS];

void initMiners();
void initVulkanMiner(VulkanMiner &vulkanMiner,VkDevice vkDevice, CPUMiner cpuMiner, uint32_t threads, uint32_t local_size_cn1, uint32_t cu, int deviceId, int index);
void loadSPIRV(VulkanMiner &vulkanMiner);
void minerIterate(VulkanMiner &vulkanMiner);
void reloadInput(VulkanMiner &vulkanMiner, int nonce);
void sendMiningParameters(VulkanMiner &vulkanMiner);
void mapMiningResults(VulkanMiner &vulkanMiner);
void unmapMiningResults(VulkanMiner &vulkanMiner);
void shutdownDevice(VulkanMiner &vulkanMiner);
void findBestSetting(VkDevice vkDevice,int deviceId, int &cu, int &factor, int &localSize, bool isLight);
void incGoodHash(int gpuIndex);
void incBadHash(int gpuIndex);
int getGoodHash(int gpuIndex);
int getBadHash(int gpuIndex);
void *MinerThread(void *args);

#endif /* MINER_HPP_ */
