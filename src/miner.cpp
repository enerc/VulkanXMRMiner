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
static sem_t mutex;
uint64_t hashRates[MAX_GPUS];

void initMiners() {
	sem_init(&mutex, 0, 1);
}

void initVulkanMiner(VulkanMiner &vulkanMiner,VkDevice vkDevice, CPUMiner cpuMiner, uint32_t threads, uint32_t local_size_cn1, uint32_t cu, int deviceId, int index) {
	uint32_t computeQueueFamillyIndex = getComputeQueueFamillyIndex(deviceId);
	vulkanMiner.vkDevice = vkDevice;
	vulkanMiner.cpuMiner = cpuMiner;			// copy constructor
	vulkanMiner.deviceId = deviceId;
	vulkanMiner.threads = threads;
	vulkanMiner.cu = cu;
	vulkanMiner.local_size_x = 16;
	vulkanMiner.groups = vulkanMiner.threads / vulkanMiner.local_size_x;
	vulkanMiner.stateSize = 200;
	vulkanMiner.inputsSize = MAX_BLOB_SIZE/2;
	vulkanMiner.outputSize = 256;
	vulkanMiner.index = index;
	vulkanMiner.scratchSplit = SCRATCHPAD_SPLIT * (cpuMiner.isLight ? 2 : 1);
	vulkanMiner.scratchpadSize = 64 + 2 * 1024 * 1024 / (cpuMiner.isLight ? 2 : 1);
	vulkanMiner.scratchpadsSize1 = vulkanMiner.threads  > vulkanMiner.scratchSplit ? vulkanMiner.scratchSplit * vulkanMiner.scratchpadSize : (uint64_t) vulkanMiner.threads * vulkanMiner.scratchpadSize;
	vulkanMiner.scratchpadsSize2 = (uint64_t) vulkanMiner.threads * vulkanMiner.scratchpadSize - vulkanMiner.scratchpadsSize1 + 64;
	vulkanMiner.debugSize = 256 * sizeof(uint64_t);
	vulkanMiner.local_memory_size = vulkanMiner.scratchpadsSize1 + vulkanMiner.scratchpadsSize2 + vulkanMiner.stateSize * vulkanMiner.threads + 4L * sizeof(int) * (vulkanMiner.threads + 2L);
	vulkanMiner.shared_memory_size = sizeof(Params) + sizeof(GpuConstants) + vulkanMiner.inputsSize + vulkanMiner.outputSize * sizeof(int) + vulkanMiner.debugSize;

	vulkanMiner.gpuLocalMemory = allocateGPUMemory(deviceId, vulkanMiner.vkDevice, vulkanMiner.local_memory_size, true);
	vulkanMiner.gpuSharedMemory = allocateGPUMemory(deviceId, vulkanMiner.vkDevice, vulkanMiner.shared_memory_size, false);
	if( vulkanMiner.threads > vulkanMiner.scratchSplit)
		vulkanMiner.highMemory = true;
	else
		vulkanMiner.highMemory = false;
	vulkanMiner.local_size_cn1 = local_size_cn1;

	uint64_t o = 0;
	// create the local buffers
	vulkanMiner.gpu_scratchpadsBuffer1 = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.scratchpadsSize1, o);
	o += vulkanMiner.scratchpadsSize1;
	vulkanMiner.gpu_scratchpadsBuffer2 = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.scratchpadsSize2, o);
	o += vulkanMiner.scratchpadsSize2;
	vulkanMiner.gpu_statesBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, vulkanMiner.stateSize * vulkanMiner.threads, o);
	o += vulkanMiner.stateSize * threads;
	vulkanMiner.gpu_branchesBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuLocalMemory, 4 * sizeof(int) * (vulkanMiner.threads + 2), o);
	o += 4 * sizeof(int) * (threads + 2);

	// create the CPU shared buffers
	o = 0;
	vulkanMiner.gpu_params = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, sizeof(Params), o);
	o += sizeof(Params);
	vulkanMiner.gpu_constants = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, sizeof(GpuConstants), o);
	o += sizeof(GpuConstants);
	vulkanMiner.gpu_inputsBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.inputsSize, o);
	o += vulkanMiner.inputsSize;
	vulkanMiner.gpu_outputBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.outputSize * sizeof(int), o);
	o += vulkanMiner.outputSize * sizeof(int);
	vulkanMiner.gpu_debugBuffer = createBuffer(vulkanMiner.vkDevice, computeQueueFamillyIndex, vulkanMiner.gpuSharedMemory, vulkanMiner.debugSize, o);
	o += vulkanMiner.debugSize;

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
			exitOnError("miner algorithm not supported");
			break;
	}
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

static void rebuildCryptonightRIfRequired(VulkanMiner &miner, bool reload)  {
	uint32_t cryptonightrHeight = getHeight();
	// need to rebuild the SPIR-V file
	if (miner.height != cryptonightrHeight) {
		//std::cout << "Rebuild cryptonightR for height " << cryptonightrHeight << "\n";
		sem_wait(&mutex);
		struct V4_Instruction code[TOTAL_LATENCY * ALU_COUNT + 1];
		v4_random_math_init(code, (uint64_t)cryptonightrHeight);
		buildCryptonightR(code,false,miner.cpuMiner.isLight,miner.local_size_cn1,false);
		if (miner.highMemory)
			buildCryptonightR(code,true,miner.cpuMiner.isLight,miner.local_size_cn1,false);

		if (reload) {
			vkDestroyPipeline(miner.vkDevice,miner.pipeline_cn1, nullptr);
			miner.pipeline_cn1 = loadShader(miner.vkDevice, miner.pipelineLayout,miner.shader_module, getCryptonightRSpirVName(false,miner.local_size_cn1));
			if (miner.highMemory) {
				vkDestroyPipeline(miner.vkDevice,miner.pipeline_cn1b, nullptr);
				miner.pipeline_cn1b = loadShader(miner.vkDevice, miner.pipelineLayout,miner.shader_module, getCryptonightRSpirVName(true,miner.local_size_cn1));
			}
		}
		sem_post(&mutex);
		miner.height = cryptonightrHeight;
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
	if (vulkanMiner.highMemory)
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
	CHECK_RESULT(vkBeginCommandBuffer(vulkanMiner.vkCommandBuffer, &commandBufferBeginInfo), "vkBeginCommandBuffer");

	// reset buffers
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn7);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, 1, 1, 1);
	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vulkanMiner.nonce += vulkanMiner.threads;			// nonce is incremented during those buffer reset

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn0);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

	if (vulkanMiner.highMemory) {
		uint32_t thrs = vulkanMiner.groups*(vulkanMiner.local_size_cn1 == 8 ? 2 : 1);
		uint32_t lowPart = thrs  > vulkanMiner.scratchSplit/vulkanMiner.local_size_cn1 ?  vulkanMiner.scratchSplit/vulkanMiner.local_size_cn1 : thrs ;
		vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1);
		vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, lowPart , 1, 1);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1b);
		vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, thrs - lowPart, 1, 1);
	} else {
		vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
		vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn1);
		vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
		vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups*(vulkanMiner.local_size_cn1 == 8 ? 2 : 1), 1, 1);
	}

	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn2);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

	vkCmdPipelineBarrier(vulkanMiner.vkCommandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1, &vulkanMiner.memoryBarrier, 0, nullptr, 0, nullptr);
	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn5);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn6);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn4);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

	vkCmdBindPipeline(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipeline_cn3);
	vkCmdBindDescriptorSets(vulkanMiner.vkCommandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, vulkanMiner.pipelineLayout, 0, 1, &vulkanMiner.descriptorSet, 0, 0);
	vkCmdDispatch(vulkanMiner.vkCommandBuffer, vulkanMiner.groups, 1, 1);

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
		for (int i=0; i< vulkanMiner.nrResults; i++) {
			unsigned char hash[256/8];			// 256 bits
			applyNonce(vulkanMiner.input, vulkanMiner.tmpResults[i]);
			bool candidate = cn_slow_hash(vulkanMiner.input, vulkanMiner.inputLen, hash, vulkanMiner.cpuMiner, vulkanMiner.index,vulkanMiner.height);
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
	params.target = getTarget();
	params.memorySize = vulkanMiner.scratchpadSize;
	params.global_work_offset = vulkanMiner.nonce;
	params.iterations = 524288 / (vulkanMiner.cpuMiner.isLight ? 2 : 1);
	params.mask = 2097136 / (vulkanMiner.cpuMiner.isLight ? 2 : 1);
	params.threads = vulkanMiner.threads;
	params.scratchpatSplit = vulkanMiner.scratchSplit;
	vulkanMiner.target = params.target;

	char *ptr = NULL;
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

void findBestSetting(VkDevice vkDevice,int deviceId, int &cu, int &factor, int &localSize, bool isLight) {
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
	factor = mem/(2/(isLight ? 2 : 1)) / cu;
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
	vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1, nullptr);
	if (variant == 4) {
		rebuildCryptonightRIfRequired(vulkanMiner,false);
		vulkanMiner.pipeline_cn1 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCryptonightRSpirVName(false,vulkanMiner.local_size_cn1));
		if (vulkanMiner.highMemory) {
			vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1b, nullptr);
			vulkanMiner.pipeline_cn1b = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCryptonightRSpirVName(true,vulkanMiner.local_size_cn1));
		}
	} else {
		vulkanMiner.pipeline_cn1 = loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,false));
		if (vulkanMiner.highMemory) {
			vkDestroyPipeline(vulkanMiner.vkDevice,vulkanMiner.pipeline_cn1b, nullptr);
			vulkanMiner.pipeline_cn1b= loadShader(vulkanMiner.vkDevice, vulkanMiner.pipelineLayout,vulkanMiner.shader_module, getCN1SpirvName(vulkanMiner,true));
		}
	}
	vulkanMiner.cpuMiner.variant = variant;
	resetCommandBuffer(vulkanMiner);
}

void *MinerThread(void *args)
{
	// force the copy constructor
	VulkanMiner miner = *(VulkanMiner*)args;
	miner.nrResults = 0;
	int inputLen;
	int nonce = getRandomNonce(miner.deviceId);
	getCurrentBlob(miner.input,&inputLen);
	reloadInput(miner,nonce);
	sendMiningParameters(miner);

	mapMiningResults(miner);
	uint64_t t0 = now();
	while (!getStopRequested()) {
		if (getVariant() == 4)
			rebuildCryptonightRIfRequired(miner,true);
		else
			miner.height = getHeight();

		if (miner.variant != getVariant()) {
			reloadPipeline(miner,getVariant());
		}
		if (!checkBlob((unsigned char *)miner.originalInput)) {
			unmapMiningResults(miner);
			nonce=	getRandomNonce(miner.deviceId);
			miner.nonce  = nonce;
			miner.target = getTarget();
			getCurrentBlob(miner.input,&inputLen);
			memcpy(&miner.originalInput,&miner.input,inputLen);
			reloadInput(miner,nonce);
			sendMiningParameters(miner);
			mapMiningResults(miner);
		}
		minerIterate(miner);
		hashRates[miner.index] = 1e9*(float)miner.threads / (float)(now() - t0);
		t0 = now();
	}
	unmapMiningResults(miner);

	shutdownDevice(miner);
	std::cout << "Miner[" << miner.index << "] closed\n";
	return NULL;
}
