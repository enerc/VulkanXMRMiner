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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <inttypes.h>
#include <iostream>

#include "config.hpp"
#include "mvulkan.hpp"
#include "miner.hpp"
#include "network.hpp"
#include "slow_hash.hpp"
#include "mvulkan.hpp"
#include "constants.hpp"
#include "log.hpp"
#include "spirv.hpp"

static VkCommandBufferBeginInfo commandBufferBeginInfo = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, 0, 0 };
static uint32_t goodHash[MAX_GPUS];
static uint32_t badhash[MAX_GPUS];
#ifdef __MINGW32__
static HANDLE mutex;
#else
static sem_t mutex;
#endif

uint64_t hashRates[MAX_GPUS];

void initMiners() {
#ifdef __MINGW32__
	mutex = CreateMutex(NULL,FALSE,"Miner Mutex");
#else
	sem_init(&mutex, 0, 1);
#endif
}

static bool hasHighMemory(VulkanMiner &vulkanMiner) {
	return  vulkanMiner.threads[getCurrentIndex()] > vulkanMiner.scratchSplit[getCurrentIndex()];
}

uint64_t alignBuffer(uint64_t size, uint64_t align) {
	if (align == 1) return size;
	else return (size+align-1)&(~(align-1));
}

void initVulkanMiner(VulkanMiner &vulkanMiner,VkDevice vkDevice, CPUMiner cpuMiner, uint32_t threads, uint32_t local_size_cn1, uint32_t cu, int deviceId, int index) {
	uint32_t computeQueueFamillyIndex = getComputeQueueFamillyIndex(deviceId);
	uint32_t memFactor = getMemFactor(getCryptoType(1));
	vulkanMiner.currentCrypto = getCryptoType(0);
	vulkanMiner.vkDevice = vkDevice;
	vulkanMiner.cpuMiner = cpuMiner;			// copy constructor
	vulkanMiner.deviceId = deviceId;
	vulkanMiner.threads[0] = threads;
	vulkanMiner.threads[1] = threads*memFactor/getMemFactor(getCryptoType(0));
	uint32_t maxThreads = vulkanMiner.threads[0] < vulkanMiner.threads[1] ? vulkanMiner.threads[1] : vulkanMiner.threads[0];
	vulkanMiner.cu = cu;
	vulkanMiner.local_size_x = 16;
	vulkanMiner.groups[0] = vulkanMiner.threads[0] / vulkanMiner.local_size_x;
	vulkanMiner.groups[1] = vulkanMiner.threads[1] / vulkanMiner.local_size_x;
	vulkanMiner.stateSize = 200;
	vulkanMiner.inputsSize = MAX_BLOB_SIZE/2;
	vulkanMiner.outputSize = 256;
	vulkanMiner.index = index;
	vulkanMiner.iterationFactor = getMemFactor(cpuMiner.type);
	vulkanMiner.memFactor = getMemFactor(cpuMiner.type);
	vulkanMiner.scratchSplit[0] = SCRATCHPAD_SPLIT * vulkanMiner.memFactor;
	vulkanMiner.scratchSplit[1] = SCRATCHPAD_SPLIT * memFactor;
	vulkanMiner.scratchpadSize[0] = 2 * 1024 * 1024 / vulkanMiner.memFactor;
	vulkanMiner.scratchpadSize[1] = 2 * 1024 * 1024 / memFactor;
	if (vulkanMiner.threads[0]  > vulkanMiner.scratchSplit[0]) {
		vulkanMiner.scratchpadsSize1 = (uint64_t) vulkanMiner.threads[0] * vulkanMiner.scratchpadSize[0]/2;
		vulkanMiner.scratchpadsSize2 = (uint64_t) vulkanMiner.threads[0] * vulkanMiner.scratchpadSize[0]/2;
	} else {
		vulkanMiner.scratchpadsSize1 = (uint64_t) vulkanMiner.threads[0] * vulkanMiner.scratchpadSize[0];
		vulkanMiner.scratchpadsSize2 = 64;
	}

	VkDeviceMemory tmpMem = allocateGPUMemory(vulkanMiner.deviceId, vulkanMiner.vkDevice, 1024, true);
	VkBuffer tmpBuf = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, tmpMem, 256, 0);
	uint32_t alignment = getBufferMemoryRequirements(vulkanMiner.vkDevice,tmpBuf);
	vkDestroyBuffer(vulkanMiner.vkDevice,tmpBuf,nullptr);
	vkFreeMemory(vkDevice , tmpMem, NULL);
	
	vulkanMiner.scratchpadsSize1 = alignBuffer(vulkanMiner.scratchpadsSize1,alignment);
	vulkanMiner.scratchpadsSize2 = alignBuffer(vulkanMiner.scratchpadsSize2,alignment);
	vulkanMiner.debugSize = alignBuffer(256 * sizeof(uint64_t),alignment);
	vulkanMiner.local_memory_size = vulkanMiner.scratchpadsSize1 +
			vulkanMiner.scratchpadsSize2 +
			alignBuffer(vulkanMiner.stateSize * maxThreads,alignment) +
			alignBuffer(4L * sizeof(int) * (maxThreads + 2L),alignment);
	vulkanMiner.shared_memory_size = alignBuffer(sizeof(Params),alignment) +
			alignBuffer(sizeof(GpuConstants),alignment) +
			alignBuffer(vulkanMiner.inputsSize,alignment) +
			alignBuffer(vulkanMiner.outputSize * sizeof(int),alignment)+
			alignBuffer(vulkanMiner.debugSize,alignment);

	vulkanMiner.gpuLocalMemory = allocateGPUMemory(deviceId, vulkanMiner.vkDevice, vulkanMiner.local_memory_size, true);
	vulkanMiner.gpuSharedMemory = allocateGPUMemory(deviceId, vulkanMiner.vkDevice, vulkanMiner.shared_memory_size, false);
	vulkanMiner.local_size_cn1 = local_size_cn1;

	uint64_t o = 0;
	// create the local buffers
	vulkanMiner.gpu_scratchpadsBuffer1 = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.scratchpadsSize1, o);
	o += vulkanMiner.scratchpadsSize1;
	vulkanMiner.gpu_scratchpadsBuffer2 = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.scratchpadsSize2, o);
	o += vulkanMiner.scratchpadsSize2;
	vulkanMiner.gpu_statesBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.stateSize * maxThreads, o);
	o += alignBuffer(vulkanMiner.stateSize * maxThreads,alignment);
	vulkanMiner.gpu_branchesBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, 4 * sizeof(int) * (maxThreads + 2), o);
	o += alignBuffer(4 * sizeof(int) * (maxThreads + 2),alignment);

	// create the CPU shared buffers
	o = 0;
	vulkanMiner.gpu_params = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, sizeof(Params), o);
	o += alignBuffer(sizeof(Params),alignment);
	vulkanMiner.gpu_constants = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, sizeof(GpuConstants), o);
	o += alignBuffer(sizeof(GpuConstants),alignment);
	vulkanMiner.gpu_inputsBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.inputsSize, o);
	o += alignBuffer(vulkanMiner.inputsSize,alignment);
	vulkanMiner.gpu_outputBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.outputSize * sizeof(int), o);
	o += alignBuffer(vulkanMiner.outputSize * sizeof(int),alignment);
	vulkanMiner.gpu_debugBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.debugSize, o);
	o += alignBuffer(vulkanMiner.debugSize,alignment);

	vulkanMiner.pipelineLayout = bindBuffers(vulkanMiner.vkDevice, vulkanMiner.descriptorSet,vulkanMiner.descriptorPool,vulkanMiner.descriptorSetLayout,
			vulkanMiner.gpu_scratchpadsBuffer1, vulkanMiner.gpu_scratchpadsBuffer2, vulkanMiner.gpu_statesBuffer,
			vulkanMiner.gpu_branchesBuffer, vulkanMiner.gpu_params, vulkanMiner.gpu_constants, vulkanMiner.gpu_inputsBuffer, vulkanMiner.gpu_outputBuffer, vulkanMiner.gpu_debugBuffer);

	// Transfer constants to GPU
	void *ptr = NULL;
	CHECK_RESULT(vkMapMemory(vulkanMiner.vkDevice, vulkanMiner.gpuSharedMemory, sizeof(Params), sizeof(GpuConstants), 0, (void ** )&ptr), "vkMapMemory");
	memcpy(ptr, (const void*) &gpuConstants, sizeof(GpuConstants));
	vkUnmapMemory(vulkanMiner.vkDevice, vulkanMiner.gpuSharedMemory);

	initCommandPool(vulkanMiner.vkDevice, computeQueueFamillyIndex, &vulkanMiner.commandPool);
	vulkanMiner.vkCommandBuffer = createCommandBuffer(vulkanMiner.vkDevice, vulkanMiner.commandPool);

	vkGetDeviceQueue(vulkanMiner.vkDevice, computeQueueFamillyIndex, 0, &vulkanMiner.queue);
	vulkanMiner.memoryBarrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
	vulkanMiner.memoryBarrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
	vulkanMiner.memoryBarrier.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
	vulkanMiner.commandBufferFilled = false;

	VkFenceCreateInfo fenceInfo;
	fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
	fenceInfo.pNext = NULL;
	fenceInfo.flags = 0;
	CHECK_RESULT(vkCreateFence(vulkanMiner.vkDevice, &fenceInfo, NULL, &vulkanMiner.drawFence), "vkCreateFence");
}

static const char *getCN1SpirvName(VulkanMiner &vulkanMiner, bool highMemory) {
	const char *cn1_spirvname = NULL;

	switch (vulkanMiner.variant) {
		case 1:
			// aeon only.
			if (highMemory)
				cn1_spirvname = vulkanMiner.local_size_cn1 == 8 ? "spirv/cn1_hmV78.spv" : "spirv/cn1_hmV716.spv";
			else
				cn1_spirvname = vulkanMiner.local_size_cn1 == 8 ? "spirv/cn1_lmV78.spv" : "spirv/cn1_lmV716.spv";
			break;
		case 2:
			if (highMemory)
				cn1_spirvname = vulkanMiner.local_size_cn1 == 8 ? "spirv/cn1_hm8.spv" : "spirv/cn1_hm16.spv";
			else
				cn1_spirvname = vulkanMiner.local_size_cn1 == 8 ? "spirv/cn1_lm8.spv" : "spirv/cn1_lm16.spv";
			break;
		case 4:
			cn1_spirvname = getCryptonightRSpirVName(highMemory,vulkanMiner.local_size_cn1);
			break;
		default:
			exitOnError("Miner algorithm not supported");
			break;
	}
	//puts(cn1_spirvname);
	return cn1_spirvname;
}

static void resetCommandBuffer(VulkanMiner &vulkanMiner) {
	vulkanMiner.commandBufferFilled = false;
	CHECK_RESULT(vkResetCommandBuffer(vulkanMiner.vkCommandBuffer, 0), "vkResetCommandBuffer");
}

static uint64_t now(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}


static void getParams(VulkanMiner &vulkanMiner,Params	&params ) {
	params.target = vulkanMiner.target;
	params.memorySize = vulkanMiner.scratchpadSize[getCurrentIndex()];
	params.global_work_offset = vulkanMiner.nonce;
	params.iterations = 524288 / getIterationFactor(getCryptoType(getCurrentIndex()));
	params.mask = 2097136 / getMemFactor(getCryptoType(getCurrentIndex()));
	params.threads = vulkanMiner.threads[getCurrentIndex()];
	params.scratchpadSplit = vulkanMiner.threads[getCurrentIndex()] / (hasHighMemory(vulkanMiner) ? 2 : 1);
	if (vulkanMiner.cpuMiner.type == TurtleCrypto) {
		params.mask = 0x1FFF0;
	}
}

static void rebuildCryptonightRIfRequired(VulkanMiner &miner, bool reload)  {
	// need to rebuild the SPIR-V file
	if (miner.height != miner.cnrHeight) {
		//std::cout << "Rebuild cryptonightR for height " << miner.height << "\n";
		bool _hasHighMemory = hasHighMemory(miner);
#ifdef __MINGW32__
		if (WaitForSingleObject(mutex, INFINITE) != WAIT_OBJECT_0)
			error("Cannot acquire mutex",NULL);
#else
		sem_wait(&mutex);
#endif
		struct V4_Instruction code[TOTAL_LATENCY * ALU_COUNT + 1];
		v4_random_math_init(code, miner.height,miner.currentCrypto);
		Params params;
		getParams(miner,params);
		buildCryptonightR(code,false,miner.cpuMiner.memFactor==2,miner.local_size_cn1,false,params.iterations,params.mask,miner.currentCrypto);
		if (_hasHighMemory)
			buildCryptonightR(code,true,miner.cpuMiner.memFactor==2,miner.local_size_cn1,false,params.iterations,params.mask,miner.currentCrypto);

		if (reload) {
			vkDestroyPipeline(miner.vkDevice,miner.pipeline_cn1, nullptr);
			miner.pipeline_cn1 = loadShader(miner.vkDevice, miner.pipelineLayout,miner.shader_module, getCryptonightRSpirVName(false,miner.local_size_cn1));
			if (_hasHighMemory) {
				vkDestroyPipeline(miner.vkDevice,miner.pipeline_cn1b, nullptr);
				miner.pipeline_cn1b = loadShader(miner.vkDevice, miner.pipelineLayout,miner.shader_module, getCryptonightRSpirVName(true,miner.local_size_cn1));
			}
		}
#ifdef __MINGW32__
		ReleaseMutex(mutex);
#else
		sem_post(&mutex);
#endif
		miner.cnrHeight = miner.height;
		resetCommandBuffer(miner);
	}
}

// Load the code
void loadSPIRV(VulkanMiner &vulkanMiner) {
	if (getVariant() == 4)
		rebuildCryptonightRIfRequired(vulkanMiner, false);

	vulkanMiner.variant = vulkanMiner.cpuMiner.variant;
	vulkanMiner.pipeline_cn0 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn0.spv");
	vulkanMiner.pipeline_cn1 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,false));
	if (hasHighMemory(vulkanMiner))
		vulkanMiner.pipeline_cn1b= loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,true));
	vulkanMiner.pipeline_cn2 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn2.spv");
	vulkanMiner.pipeline_cn3 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn3.spv");
	vulkanMiner.pipeline_cn4 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn4.spv");
	vulkanMiner.pipeline_cn5 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn5.spv");
	vulkanMiner.pipeline_cn6 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn6.spv");
	vulkanMiner.pipeline_cn7 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, "spirv/cn7.spv");
	//shaderStats(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1); exit(0);
}

static void createCommandBuffer(VulkanMiner &vulkanMiner) {
	int current_index = getCurrentIndex();
	CHECK_RESULT(vkBeginCommandBuffer(vulkanMiner.vkCommandBuffer, &commandBufferBeginInfo), "vkBeginCommandBuffer");

	// reset buffers
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn7);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, 1, 1, 1);
	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vulkanMiner.nonce += vulkanMiner.threads[current_index];			// nonce is incremented during those buffer reset

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	if (hasHighMemory(vulkanMiner)) {
		uint32_t cnt = vulkanMiner.groups[current_index]*(vulkanMiner.local_size_cn1 == 8 ? 2 : 1);
		vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, cnt/2 , 1, 1);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1b);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, cnt/2, 1, 1);
	} else {
		vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index]*(vulkanMiner.local_size_cn1 == 8 ? 2 : 1), 1, 1);
	}

	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn2);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn5);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn6);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn4);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn3);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups[current_index], 1, 1);

	CHECK_RESULT(vkEndCommandBuffer(vulkanMiner.vkCommandBuffer), "vkEndCommandBuffer");

	vulkanMiner.commandBufferFilled = true;
}

void minerIterate(VulkanMiner &vulkanMiner) {
	if (!vulkanMiner.commandBufferFilled)
		createCommandBuffer(vulkanMiner);

	VkSubmitInfo submitInfo = { VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &vulkanMiner.vkCommandBuffer, 0, 0 };

	CHECK_RESULT(vkQueueSubmit(vulkanMiner.queue, 1, &submitInfo, vulkanMiner.drawFence), "vkQueueSubmit");

	// process latest results while GPU is working
	if (vulkanMiner.nrResults > 0) {
		for (int i=0; i< vulkanMiner.nrResults && vulkanMiner.cnrSubmittedHeight == vulkanMiner.height; i++) {
			unsigned char hash[256/8];			// 256 bits
			applyNonce(vulkanMiner.originalInput, vulkanMiner.tmpResults[i]);
			bool candidate = cn_slow_hash(vulkanMiner.originalInput, vulkanMiner.inputLen, hash, vulkanMiner.cpuMiner, vulkanMiner.index,vulkanMiner.height);
			if (candidate)
				notifyResult(vulkanMiner.tmpResults[i], hash, vulkanMiner.originalInput,vulkanMiner.height);
		}
		vulkanMiner.nrResults = 0;
	}

	VkResult res;
	do {
		uint64_t delay = 5UL * 1000UL * 1000UL * 1000UL;
		res = vkWaitForFences(vulkanMiner.vkDevice, 1, &vulkanMiner.drawFence, VK_TRUE, delay );
	} while (res == VK_TIMEOUT);
	vkResetFences(vulkanMiner.vkDevice, 1, &vulkanMiner.drawFence);
	vulkanMiner.nrResults = (int) vulkanMiner.resultPtr[255];
	for (int i = 0; i < vulkanMiner.nrResults; i++) {
		vulkanMiner.tmpResults[i] = (int) vulkanMiner.resultPtr[i];
	}
	vulkanMiner.cnrSubmittedHeight = vulkanMiner.height;
	memcpy(&vulkanMiner.originalInput,&vulkanMiner.input,vulkanMiner.inputLen);
}

void reloadInput(VulkanMiner &vulkanMiner, int nonce) {
	// get current blob to hash from network.
	getCurrentBlob(vulkanMiner.input,&vulkanMiner.inputLen);
	vulkanMiner.nonce = nonce;
	memcpy(vulkanMiner.originalInput,vulkanMiner.input,MAX_BLOB_SIZE/2);

	// transfer blob to GPU
	char *ptr = NULL;
	CHECK_RESULT(vkMapMemory(vulkanMiner.vkDevice, vulkanMiner.gpuSharedMemory, sizeof(Params)+sizeof(GpuConstants), MAX_BLOB_SIZE/2, 0, (void **)&ptr),"vkMapMemory");
	memcpy(ptr,(const void*)vulkanMiner.input,MAX_BLOB_SIZE/2);
	vkUnmapMemory(vulkanMiner.vkDevice,vulkanMiner.gpuSharedMemory);

	// forget results waiting for cpu validation
	vulkanMiner.nrResults = 0;
}


void sendMiningParameters(VulkanMiner &vulkanMiner) {
	Params	params;
	getParams(vulkanMiner,params);
	char *ptr = NULL;
	unmapMiningResults(vulkanMiner);
	CHECK_RESULT(vkMapMemory(vulkanMiner.vkDevice, vulkanMiner.gpuSharedMemory, 0, sizeof(Params), 0, (void **)&ptr),"vkMapMemory");
	memcpy(ptr,(const void*)&params,sizeof(Params));
	vkUnmapMemory(vulkanMiner.vkDevice,vulkanMiner.gpuSharedMemory);
}

void mapMiningResults(VulkanMiner &vulkanMiner) {
	CHECK_RESULT(vkMapMemory(vulkanMiner.vkDevice, vulkanMiner.gpuSharedMemory,sizeof(Params)+sizeof(GpuConstants)+vulkanMiner.inputsSize, vulkanMiner.outputSize*sizeof(int),  0, (void **)&vulkanMiner.resultPtr),"vkMapMemory");
}

void unmapMiningResults(VulkanMiner &vulkanMiner) {
	vkUnmapMemory(vulkanMiner.vkDevice,vulkanMiner.gpuSharedMemory);
}

void shutdownDevice(VulkanMiner &vulkanMiner) {
	vkFreeMemory(vulkanMiner.vkDevice , vulkanMiner.gpuLocalMemory, NULL);
	vkFreeMemory(vulkanMiner.vkDevice , vulkanMiner.gpuSharedMemory, NULL);

	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn0, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn2, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn3, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn4, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn5, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn6, nullptr);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn7, nullptr);

	vkDestroyPipelineLayout(vulkanMiner.vkDevice,vulkanMiner.pipelineLayout,nullptr);

	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_scratchpadsBuffer1,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_scratchpadsBuffer2,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_statesBuffer,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_branchesBuffer,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_params,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_constants,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_inputsBuffer,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_outputBuffer,nullptr);
	vkDestroyBuffer(vulkanMiner.vkDevice,vulkanMiner.gpu_debugBuffer,nullptr);
	vkDestroyCommandPool(vulkanMiner.vkDevice, vulkanMiner.commandPool, nullptr);
	vkDestroyDescriptorPool(vulkanMiner.vkDevice, vulkanMiner.descriptorPool, nullptr);
	vkDestroyShaderModule(vulkanMiner.vkDevice,vulkanMiner.shader_module, nullptr);
	vkDestroyDescriptorSetLayout(vulkanMiner.vkDevice,vulkanMiner.descriptorSetLayout,nullptr);

	//vkFreeCommandBuffers(vulkanMiner.vkDevice,vulkanMiner.commandPool,1,&vulkanMiner.vkCommandBuffer);
}

void findBestSetting(VkDevice vkDevice,int deviceId, int &cu, int &factor, int &localSize, int  memFactor) {
	uint64_t last=0;
	VkCommandPool commandPool;
	VkCommandBuffer vkCommandBuffer;
	VkQueue queue;
	VkBuffer gpu_scratchpadsBuffer1;
	VkDescriptorSet descriptorSet;
	VkDescriptorPool descriptorPool;
	VkShaderModule shader_module;
	VkDescriptorSetLayout descriptorSetLayout;

	uint32_t computeQueueFamillyIndex = getComputeQueueFamillyIndex(deviceId);
	uint64_t local_memory_size= 1048576;
	VkDeviceMemory gpuLocalMemory = allocateGPUMemory(deviceId, vkDevice, local_memory_size, true);
	initCommandPool(vkDevice, computeQueueFamillyIndex, &commandPool);
	vkCommandBuffer = createCommandBuffer(vkDevice, commandPool);
	vkGetDeviceQueue(vkDevice, computeQueueFamillyIndex, 0, &queue);
	gpu_scratchpadsBuffer1 = createBuffer(vkDevice, computeQueueFamillyIndex, gpuLocalMemory, local_memory_size, 0);
	VkPipelineLayout pipelineLayout = bindBuffer(vkDevice, descriptorSet, descriptorPool, descriptorSetLayout, gpu_scratchpadsBuffer1);
	VkPipeline pipeline_cn8_1 = loadShader(vkDevice, pipelineLayout,shader_module, "spirv/cn8.spv");
	VkSubmitInfo submitInfo = { VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &vkCommandBuffer, 0, 0 };

	// Warm up to trigger frequency changes
	for (int i=0; i< 10; i++) {
		CHECK_RESULT(vkBeginCommandBuffer(vkCommandBuffer, &commandBufferBeginInfo), "vkBeginCommandBuffer");
		vkCmdBindPipeline(vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_cn8_1);
		vkCmdBindDescriptorSets(vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &descriptorSet, 0, 0);
		vkCmdDispatch(vkCommandBuffer, i, 1, 1);
		CHECK_RESULT(vkEndCommandBuffer(vkCommandBuffer), "vkEndCommandBuffer");
		CHECK_RESULT(vkQueueSubmit(queue, 1, &submitInfo, VK_NULL_HANDLE), "vkQueueSubmit");
		CHECK_RESULT(vkQueueWaitIdle(queue),"vkQueueWaitIdle");
	}

	// Check with local_size = 8
	int i=0;
	for (i=8; i<= 512; i++) {
		if (i > 8)
			CHECK_RESULT(vkResetCommandBuffer(vkCommandBuffer, 0), "vkResetCommandBuffer");

		CHECK_RESULT(vkBeginCommandBuffer(vkCommandBuffer, &commandBufferBeginInfo), "vkBeginCommandBuffer");

		// reset buffers
		vkCmdBindPipeline(vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_cn8_1);
		vkCmdBindDescriptorSets(vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &descriptorSet, 0, 0);
		vkCmdDispatch(vkCommandBuffer, i, 1, 1);
		CHECK_RESULT(vkEndCommandBuffer(vkCommandBuffer), "vkEndCommandBuffer");

		uint64_t t0 = now();
		VkSubmitInfo submitInfo = { VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, 0, 0, 0, 1, &vkCommandBuffer, 0, 0 };
		CHECK_RESULT(vkQueueSubmit(queue, 1, &submitInfo, VK_NULL_HANDLE), "vkQueueSubmit");
		CHECK_RESULT(vkQueueWaitIdle(queue),"vkQueueWaitIdle");


		uint64_t t1 = now();
		float k = t1-t0;
		if (last ==0) {
			last = k;
		} else if (k*0.8 > last )
			break;
	}
	cu = (i-1)/2;

	localSize = 8;
	int mem = (getMemorySize(deviceId)/1024)*1024 - 128;
	factor = mem/(2.0/memFactor) / cu;
	factor = localSize*(factor/localSize);

	if (factor*cu > SCRATCHPAD_SPLIT) localSize = 16;		// by design
	else if (cu < 16)
		localSize = 16;

	factor = localSize*(factor/localSize);

	// destroy the temps used for the test.
	vkDestroyPipeline(vkDevice,pipeline_cn8_1, nullptr);
	vkDestroyPipelineLayout(vkDevice,pipelineLayout,nullptr);
	vkDestroyBuffer(vkDevice,gpu_scratchpadsBuffer1,nullptr);
	vkFreeMemory(vkDevice , gpuLocalMemory, NULL);
	vkFreeCommandBuffers(vkDevice,commandPool,1,&vkCommandBuffer);
	vkDestroyCommandPool(vkDevice, commandPool, nullptr);
	vkDestroyDescriptorPool(vkDevice, descriptorPool, nullptr);
	vkDestroyShaderModule(vkDevice,shader_module, nullptr);
	vkDestroyDescriptorSetLayout(vkDevice,descriptorSetLayout,nullptr);
}

// not thread safe, but don't care if we loose one
void incGoodHash(int gpuIndex) {
	goodHash[gpuIndex]++;
}

// not thread safe, but don't care if we loose one
void incBadHash(int gpuIndex) {
	badhash[gpuIndex]++;
}


int getGoodHash(int gpuIndex) {
	return goodHash[gpuIndex];
}

int getBadHash(int gpuIndex) {
	return badhash[gpuIndex];
}

static void reloadPipeline(VulkanMiner &vulkanMiner, int variant) {
	vulkanMiner.variant = variant;
	vkDeviceWaitIdle(vulkanMiner.vkDevice);
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1, nullptr);
	bool _hasHighMemory = hasHighMemory(vulkanMiner);

	if (variant == 4) {
		rebuildCryptonightRIfRequired(vulkanMiner,false);
		vulkanMiner.pipeline_cn1 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCryptonightRSpirVName(false,vulkanMiner.local_size_cn1));

		if (_hasHighMemory) {
			vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1b, nullptr);
			vulkanMiner.pipeline_cn1b = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCryptonightRSpirVName(true,vulkanMiner.local_size_cn1));
		}
	} else {
		vulkanMiner.pipeline_cn1 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,false));
		if (_hasHighMemory) {
			vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1b, nullptr);
			vulkanMiner.pipeline_cn1b= loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,true));
		}
	}
	vulkanMiner.cpuMiner.variant = variant;
	memcpy(&vulkanMiner.originalInput,&vulkanMiner.input,vulkanMiner.inputLen);
	resetCommandBuffer(vulkanMiner);
}

#ifdef __MINGW32__
DWORD WINAPI MinerThread(LPVOID args)
#else
void *MinerThread(void *args)
#endif
{
	// force the copy constructor
	VulkanMiner miner = *(VulkanMiner*)args;
	miner.nrResults = 0;
	miner.cnrHeight = 0;
	int inputLen;
	int nonce = getRandomNonce(miner.index);
	getCurrentBlob(miner.input,&inputLen);
	memcpy(&miner.originalInput,&miner.input,miner.inputLen);
	miner.target = getTarget();
	miner.cpuMiner.variant = getVariant();
	reloadInput(miner,nonce);
	sendMiningParameters(miner);

	mapMiningResults(miner);
	uint64_t t0 = now();
	while (!getStopRequested()) {
		miner.height = getHeight();
		if (miner.variant != getVariant() || miner.currentCrypto != getCryptoType(getCurrentIndex())) {
			miner.currentCrypto = getCryptoType(getCurrentIndex());
			miner.cpuMiner.variant = getVariant();
			miner.cpuMiner.memFactor = getMemFactor(miner.currentCrypto);
			destroyCPUScratchPad(miner.cpuMiner);
			miner.cpuMiner.type = miner.currentCrypto;
			reloadPipeline(miner,getVariant());
		}
		if (getVariant() == 4)
			rebuildCryptonightRIfRequired(miner,true);

		if (!checkBlob((unsigned char *)miner.originalInput)) {
			unmapMiningResults(miner);
			nonce=	getRandomNonce(miner.index);
			miner.target = getTarget();
			reloadInput(miner,nonce);
			sendMiningParameters(miner);
			mapMiningResults(miner);
		}
		minerIterate(miner);
		hashRates[miner.index] = 1e9*(float)miner.threads[getCurrentIndex()] / (float)(now() - t0);
		t0 = now();
	}
	unmapMiningResults(miner);

	shutdownDevice(miner);
	std::cout << "Miner[" << miner.index << "] closed\n";
#ifdef __MINGW32__
	return 0;
#else
	return NULL;
#endif
}
