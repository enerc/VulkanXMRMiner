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
#include <cstdlib>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>


#include "mvulkan.hpp"
#include "log.hpp"
#include "constants.hpp"

static const int forceAMD=0;
static VkInstance instance = NULL;
static VkPhysicalDevice* physicalDevices= NULL;
static uint32_t physicalDeviceCount;
GpuConstants gpuConstants;
Params	params;

using namespace std;

// return the number of devices
int vulkanInit(){
	const VkApplicationInfo applicationInfo = {
	    VK_STRUCTURE_TYPE_APPLICATION_INFO,
	    0,
	    "vulkanMiner",
	    0,
	    "",
	    0,
	    VK_API_VERSION_1_0
	};

	const VkInstanceCreateInfo instanceCreateInfo = {
		VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,								// stype
		0,																	// pNext
		0,																	// flags
		&applicationInfo,													// pApplicationInfo
		0,																	// enabledLayerCount
		nullptr,															// ppEnabledLayerNames
		0,																	// enabledExtensionCount
		nullptr 															// ppEnabledExtensionNames
	};

	CHECK_RESULT(vkCreateInstance(&instanceCreateInfo, 0, &instance),"vkCreateInstance");

	physicalDeviceCount = 0;
	CHECK_RESULT(vkEnumeratePhysicalDevices(instance, &physicalDeviceCount, 0),"vkEnumeratePhysicalDevices");
	if (physicalDeviceCount == 0) {
		exitOnError("No graphic cards were found by Vulkan. Use Adrenalin not Crimson and check your drivers with VulkanInfo.");
	}

	physicalDevices = (VkPhysicalDevice*)malloc(sizeof(VkPhysicalDevice) * physicalDeviceCount);
	memset(physicalDevices,0,sizeof(VkPhysicalDevice) * physicalDeviceCount);

	CHECK_RESULT(vkEnumeratePhysicalDevices(instance, &physicalDeviceCount, physicalDevices),"vkEnumeratePhysicalDevices");

	return physicalDeviceCount;
}

void vulkanEnd() {
}

void getDeviceName(int index, char *name) {
	VkPhysicalDeviceProperties physicalDeviceProperties;
	vkGetPhysicalDeviceProperties(physicalDevices[index],&physicalDeviceProperties);
	int len = strlen(physicalDeviceProperties.deviceName);
	memcpy(name,physicalDeviceProperties.deviceName,len);
	name[len]=0;
}

uint64_t getMemorySize(int index) {
	VkPhysicalDeviceMemoryProperties properties;
	vkGetPhysicalDeviceMemoryProperties(physicalDevices[index], &properties);
	for (uint32_t k = 0; k < properties.memoryTypeCount; k++) {
		VkMemoryType t = properties.memoryTypes[k];
		VkMemoryHeap h = properties.memoryHeaps[k];
		if ((t.propertyFlags&VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)!=0)
			return h.size / 1024 / 1024;
	}
	return 0;
}

int getComputeQueueFamillyIndex(uint32_t index) {
	if (index >= physicalDeviceCount) {
		cout << "Card index " << index << " not found ";
 		exitOnError(". Please review your config.json file");
	}
	uint32_t queueFamilyPropertiesCount = 0;
	vkGetPhysicalDeviceQueueFamilyProperties(physicalDevices[index], &queueFamilyPropertiesCount, 0);
	VkQueueFamilyProperties* const queueFamilyProperties = (VkQueueFamilyProperties*)malloc(  sizeof(VkQueueFamilyProperties) * queueFamilyPropertiesCount);
	vkGetPhysicalDeviceQueueFamilyProperties(physicalDevices[index],  &queueFamilyPropertiesCount, queueFamilyProperties);
	int ret = -1;
	for (unsigned int i=0; i< queueFamilyPropertiesCount; i++) {
		if (queueFamilyProperties[i].queueFlags & VK_QUEUE_COMPUTE_BIT)
			ret = i;
	}
	free(queueFamilyProperties);
	return ret;
}

VkDevice createDevice(int index,uint32_t computeQueueFamillyIndex) {
	const float queuePrioritory = 1.0f;
	const VkDeviceQueueCreateInfo deviceQueueCreateInfo = {
		VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		0,
		0,
		computeQueueFamillyIndex,
		1,
		&queuePrioritory
	};

	static VkPhysicalDeviceFeatures enabledFeatures{};
	enabledFeatures.shaderInt64 = VK_TRUE;
	std::vector<const char*> deviceExtensions;
	if (forceAMD)
		deviceExtensions.push_back("VK_AMD_shader_info");

	const VkDeviceCreateInfo deviceCreateInfo = {
			VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
			0,
			0,
			1,
			&deviceQueueCreateInfo,
			0,
			0,
			static_cast<uint32_t>(deviceExtensions.size()),
			&deviceExtensions[0],
			&enabledFeatures
	   };

	VkDevice vulkanDevice;
	CHECK_RESULT(vkCreateDevice(physicalDevices[index], &deviceCreateInfo, 0, &vulkanDevice),"vkCreateDevice");

	return vulkanDevice;
}

VkDeviceMemory allocateGPUMemory(int index,  VkDevice vkDevice, const VkDeviceSize memorySize, char isLocal) {
	VkPhysicalDeviceMemoryProperties properties;
	vkGetPhysicalDeviceMemoryProperties(physicalDevices[index], &properties);

	// set memoryTypeIndex to an invalid entry in the properties.memoryTypes array
	uint32_t memoryTypeIndex = VK_MAX_MEMORY_TYPES;

	VkMemoryPropertyFlags flag;
	if (isLocal) flag = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
	else flag = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT /*| VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT*/;
	for (uint32_t k = 0; k < properties.memoryTypeCount; k++) {
		if (properties.memoryTypes[k].propertyFlags == flag && memorySize < properties.memoryHeaps[properties.memoryTypes[k].heapIndex].size) {
			memoryTypeIndex = k;
			break;
		}
	}

	VkResult ret = (memoryTypeIndex == VK_MAX_MEMORY_TYPES ? VK_ERROR_OUT_OF_HOST_MEMORY : VK_SUCCESS);
	if (ret != VK_SUCCESS)
		exitOnError("Cannot find GPU memory type... Bye!");

	const VkMemoryAllocateInfo memoryAllocateInfo = {
		VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		0,
		memorySize,
		memoryTypeIndex
	};

	VkDeviceMemory memory;
	CHECK_RESULT(vkAllocateMemory(vkDevice, &memoryAllocateInfo, 0, &memory),"vkAllocateMemory");

	return memory;
}

void initCommandPool(VkDevice vkDevice, uint32_t computeQueueFamillyIndex,VkCommandPool *commandPool) {
	VkCommandPoolCreateInfo commandPoolCreateInfo = {
		VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
		0,
		VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
		computeQueueFamillyIndex
	};

	CHECK_RESULT(vkCreateCommandPool(vkDevice, &commandPoolCreateInfo, 0, commandPool),"vkCreateCommandPool");
}

VkCommandBuffer createCommandBuffer(VkDevice vkDevice,VkCommandPool commandPool) {
	VkCommandBufferAllocateInfo commandBufferAllocateInfo = {
		VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
		0,
		commandPool,
		VK_COMMAND_BUFFER_LEVEL_PRIMARY,
		1
	};

	VkCommandBuffer commandBuffer;
	CHECK_RESULT(vkAllocateCommandBuffers(vkDevice, &commandBufferAllocateInfo, &commandBuffer),"vkAllocateCommandBuffers");

	return commandBuffer;
}

VkBuffer createBuffer(VkDevice vkDevice,uint32_t computeQueueFamillyIndex,VkDeviceMemory memory,VkDeviceSize bufferSize, VkDeviceSize offset) {
	const VkBufferCreateInfo bufferCreateInfo = {
		VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		0,
		0,
		bufferSize,
		VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
		VK_SHARING_MODE_EXCLUSIVE,
		1,
		&computeQueueFamillyIndex
	};

	VkBuffer buffer;
	CHECK_RESULT(vkCreateBuffer(vkDevice, &bufferCreateInfo, 0, &buffer),"vkCreateBuffer");
	CHECK_RESULT(vkBindBufferMemory(vkDevice, buffer, memory, offset),"vkBindBufferMemory");

	return buffer;
}

void prepareGPUConstants() {
	memcpy(gpuConstants.keccakf_rndc,keccakf_rndc,sizeof(keccakf_rndc));
	memcpy(gpuConstants.sbox,sbox,sizeof(sbox));
	memcpy(gpuConstants.keccakf_rotc,keccakf_rotc,sizeof(keccakf_rotc));
	memcpy(gpuConstants.keccakf_piln,keccakf_piln,sizeof(keccakf_piln));
	memcpy(gpuConstants.AES0_C,AES0_C,sizeof(AES0_C));
	memcpy(gpuConstants.RCP_C,RCP_C,sizeof(RCP_C));
	memcpy(gpuConstants.sigma,sigma,sizeof(sigma));
	memcpy(gpuConstants.c_IV256,c_IV256,sizeof(c_IV256));
	memcpy(gpuConstants.c_Padding,c_Padding,sizeof(c_Padding));
	memcpy(gpuConstants.c_u256,c_u256,sizeof(c_u256));
	memcpy(gpuConstants.T0_G,T0_G,sizeof(T0_G));
	memcpy(gpuConstants.T4_G,T4_G,sizeof(T4_G));
	memcpy(gpuConstants.rcon,rcon,sizeof(rcon));
	memcpy(gpuConstants.SKEIN256_IV,SKEIN256_IV,sizeof(SKEIN256_IV));
	memcpy(gpuConstants.SKEIN512_256_IV,SKEIN512_256_IV,sizeof(SKEIN512_256_IV));
	memcpy(gpuConstants.JH_C,JH_C,sizeof(JH_C));
}

VkPipelineLayout bindBuffers(VkDevice vkDevice,VkDescriptorSet &descriptorSet, 	VkDescriptorPool &descriptorPool,VkDescriptorSetLayout &descriptorSetLayout
		,VkBuffer b0, VkBuffer b1,VkBuffer b2, VkBuffer b3, VkBuffer b4, VkBuffer b5, VkBuffer b6, VkBuffer b7, VkBuffer b8) {
	VkPipelineLayout pipelineLayout;
	uint32_t nb_Buffers = 9;
	VkDescriptorSetLayoutBinding descriptorSetLayoutBindings[9] = {
	{	0,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	1,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	2,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	3,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	4,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	5,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	6,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	7,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	{	8,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	};

	VkDescriptorSetLayoutCreateInfo descriptorSetLayoutCreateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		0,
		0,
		nb_Buffers,
		descriptorSetLayoutBindings
	};

	CHECK_RESULT(vkCreateDescriptorSetLayout(vkDevice, &descriptorSetLayoutCreateInfo, 0, &descriptorSetLayout),"vkCreateDescriptorSetLayout");

	VkPipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
		VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		0,
		0,
		1,
		&descriptorSetLayout,
		0,
		0,
	};

	CHECK_RESULT(vkCreatePipelineLayout(vkDevice, &pipelineLayoutCreateInfo, 0, &pipelineLayout),"vkCreatePipelineLayout");

	VkDescriptorPoolSize descriptorPoolSize = {
		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		nb_Buffers
	};

	VkDescriptorPoolCreateInfo descriptorPoolCreateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		0,
		0,
		1,
		1,
		&descriptorPoolSize
	};

	CHECK_RESULT(vkCreateDescriptorPool(vkDevice, &descriptorPoolCreateInfo, 0, &descriptorPool),"vkCreateDescriptorPool");

	VkDescriptorSetAllocateInfo descriptorSetAllocateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		0,
		descriptorPool,
		1,
		&descriptorSetLayout
	};
	CHECK_RESULT(vkAllocateDescriptorSets(vkDevice, &descriptorSetAllocateInfo, &descriptorSet),"vkAllocateDescriptorSets");

	VkDescriptorBufferInfo descriptorBufferInfo0 = { b0, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo1 = { b1, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo2 = { b2, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo3 = { b3, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo4 = { b4, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo5 = { b5, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo6 = { b6, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo7 = { b7, 0, 	VK_WHOLE_SIZE };
	VkDescriptorBufferInfo descriptorBufferInfo8 = { b8, 0, 	VK_WHOLE_SIZE };


	VkWriteDescriptorSet writeDescriptorSet[9] = {
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	0,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo0,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	1,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo1,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	2,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo2,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	3,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo3,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	4,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo4,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	5,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo5,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	6,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo6,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	7,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo7,	0	},
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	8,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo8,	0	}
	};

	vkUpdateDescriptorSets(vkDevice, nb_Buffers, writeDescriptorSet, 0, 0);

	return pipelineLayout;
}

VkPipelineLayout bindBuffer(VkDevice vkDevice,VkDescriptorSet &descriptorSet, 	VkDescriptorPool &descriptorPool, VkDescriptorSetLayout &descriptorSetLayout, VkBuffer b0) {
	VkPipelineLayout pipelineLayout;
	uint32_t nb_Buffers = 1;
	VkDescriptorSetLayoutBinding descriptorSetLayoutBindings[1] = {
	{	0,		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,		1,		VK_SHADER_STAGE_COMPUTE_BIT,		0	},
	};

	VkDescriptorSetLayoutCreateInfo descriptorSetLayoutCreateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		0,
		0,
		nb_Buffers,
		descriptorSetLayoutBindings
	};

	CHECK_RESULT(vkCreateDescriptorSetLayout(vkDevice, &descriptorSetLayoutCreateInfo, 0, &descriptorSetLayout),"vkCreateDescriptorSetLayout");

	VkPipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
		VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		0,
		0,
		1,
		&descriptorSetLayout,
		0,
		0
	};

	CHECK_RESULT(vkCreatePipelineLayout(vkDevice, &pipelineLayoutCreateInfo, 0, &pipelineLayout),"vkCreatePipelineLayout");

	VkDescriptorPoolSize descriptorPoolSize = {
		VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		nb_Buffers
	};

	VkDescriptorPoolCreateInfo descriptorPoolCreateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		0,
		0,
		1,
		1,
		&descriptorPoolSize
	};

	CHECK_RESULT(vkCreateDescriptorPool(vkDevice, &descriptorPoolCreateInfo, 0, &descriptorPool),"vkCreateDescriptorPool");

	VkDescriptorSetAllocateInfo descriptorSetAllocateInfo = {
		VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		0,
		descriptorPool,
		1,
		&descriptorSetLayout
	};
	CHECK_RESULT(vkAllocateDescriptorSets(vkDevice, &descriptorSetAllocateInfo, &descriptorSet),"vkAllocateDescriptorSets");

	VkDescriptorBufferInfo descriptorBufferInfo0 = { b0, 0, 	VK_WHOLE_SIZE };


	VkWriteDescriptorSet writeDescriptorSet[9] = {
		{	VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,	0,	descriptorSet,	0,	0,	1,	VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,	0,	&descriptorBufferInfo0,	0	},
	};

	vkUpdateDescriptorSets(vkDevice, nb_Buffers, writeDescriptorSet, 0, 0);

	return pipelineLayout;
}

VkPipeline loadShader(VkDevice vkDevice, VkPipelineLayout pipelineLayout,VkShaderModule &shader_module, const char * file_name) {
	uint32_t *shader;
	size_t shader_size;

	FILE *fp = fopen(file_name, "rb");
	if (fp == NULL) {
		char msg[2048];
		sprintf(msg,"SPIR-V program %s not found\n",file_name);
		error(msg,NULL);
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	shader_size = (size_t) (ftell(fp) * sizeof(char));
	fseek(fp, 0, SEEK_SET);

	shader = (uint32_t*) malloc(shader_size+1);
	memset(shader,0,shader_size+1);
	size_t read_size = fread(shader,sizeof(char),shader_size,fp);
	if(read_size != shader_size) {
		free(shader);
		char msg[2048];
		sprintf(msg,"Failed to read shader %s!\n",file_name);
		exitOnError(msg);
	}

	VkShaderModuleCreateInfo shaderModuleCreateInfo = {
		VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		0,
		0,
		shader_size,
		shader
	};

	CHECK_RESULT(vkCreateShaderModule(vkDevice, &shaderModuleCreateInfo, 0, &shader_module),"vkCreateShaderModule");

	VkComputePipelineCreateInfo computePipelineCreateInfo = {
		VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
		0,
		0,
		{
			VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
			0,
			0,
			VK_SHADER_STAGE_COMPUTE_BIT,
			shader_module,
			"main",
			0
		},
		pipelineLayout,
		0,
		0
	};

	VkPipeline pipeline;
	CHECK_RESULT(vkCreateComputePipelines(vkDevice, 0, 1, &computePipelineCreateInfo, 0, &pipeline),"vkCreateComputePipelines");

	free(shader);
	fclose(fp);
	return pipeline;
}

// For AMD shader debugging.
void shaderStats(VkDevice vkDevice,VkPipeline shader) {
	if (forceAMD) {
		size_t pInfoSize;
		PFN_vkGetShaderInfoAMD vkGetShaderInfoAMD = (PFN_vkGetShaderInfoAMD)vkGetDeviceProcAddr(vkDevice, "vkGetShaderInfoAMD");

		CHECK_RESULT(vkGetShaderInfoAMD(vkDevice,shader,VK_SHADER_STAGE_COMPUTE_BIT,VK_SHADER_INFO_TYPE_STATISTICS_AMD,&pInfoSize,NULL),"vkGetShaderInfoAMD");
		void *pinfo = (void*)malloc(pInfoSize);
		CHECK_RESULT(vkGetShaderInfoAMD(vkDevice,shader,VK_SHADER_STAGE_COMPUTE_BIT,VK_SHADER_INFO_TYPE_STATISTICS_AMD,&pInfoSize,pinfo),"vkGetShaderInfoAMD");

		VkShaderStatisticsInfoAMD *info = (VkShaderStatisticsInfoAMD*)pinfo;
		printf("---------------------------------------\n");
		printf("shaderStageMask= %x\n",info->shaderStageMask);
		printf("resourceUsage->numUsedVgprs= %u\n",info->resourceUsage.numUsedVgprs);
		printf("resourceUsage->numUsedSgprs= %u\n",info->resourceUsage.numUsedSgprs);
		printf("resourceUsage->ldsSizePerLocalWorkGroup= %u\n",info->resourceUsage.ldsSizePerLocalWorkGroup);
#if __MINGW32__
		printf("resourceUsage->ldsUsageSizeInBytes= %I64d\n",info->resourceUsage.ldsUsageSizeInBytes);
		printf("resourceUsage->scratchMemUsageInBytes= %I64d\n",info->resourceUsage.scratchMemUsageInBytes);
#else
		printf("resourceUsage->ldsUsageSizeInBytes= %lu\n",info->resourceUsage.ldsUsageSizeInBytes);
		printf("resourceUsage->scratchMemUsageInBytes= %lu\n",info->resourceUsage.scratchMemUsageInBytes);
#endif
		printf("numPhysicalVgprs= %u\n",info->numPhysicalVgprs);
		printf("numPhysicalSgprs= %u\n",info->numPhysicalSgprs);
		printf("numAvailableVgprs= %u\n",info->numAvailableVgprs);
		printf("numAvailableSgprs= %u\n",info->numAvailableSgprs);
		printf("computeWorkGroupSize[0]= %u\n",info->computeWorkGroupSize[0]);
		printf("Groups = %.1lf (max=2)\n",65536.0/(info->resourceUsage.numUsedVgprs*info->computeWorkGroupSize[0]));
		printf("\n");
		free(pinfo);

		CHECK_RESULT(vkGetShaderInfoAMD(vkDevice,shader,VK_SHADER_STAGE_COMPUTE_BIT,VK_SHADER_INFO_TYPE_DISASSEMBLY_AMD,&pInfoSize,NULL),"vkGetShaderInfoAMD");
		pinfo = (void*)malloc(pInfoSize);
		CHECK_RESULT(vkGetShaderInfoAMD(vkDevice,shader,VK_SHADER_STAGE_COMPUTE_BIT,VK_SHADER_INFO_TYPE_DISASSEMBLY_AMD,&pInfoSize,pinfo),"vkGetShaderInfoAMD");
		printf("%s\n",(const char*)pinfo);
		free(pinfo);
	}
}

// VK_API_VERSION_1_1 only.
int32_t getSubGroupSize(int index) {
	VkPhysicalDeviceSubgroupProperties subgroupProperties;
	subgroupProperties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_PROPERTIES;
	subgroupProperties.pNext = NULL;

	VkPhysicalDeviceProperties2 physicalDeviceProperties;
	physicalDeviceProperties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
	physicalDeviceProperties.pNext = &subgroupProperties;

	vkGetPhysicalDeviceProperties2(physicalDevices[index], &physicalDeviceProperties);

	return subgroupProperties.subgroupSize;
}

uint32_t getBufferMemoryRequirements(VkDevice vkDevice,VkBuffer b) {
	VkMemoryRequirements req;
	vkGetBufferMemoryRequirements(vkDevice,b,&req);
	return req.alignment;
}
