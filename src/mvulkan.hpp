#ifndef MVULKAN_HPP_
#define MVULKAN_HPP_
#include <vulkan/vulkan.h>

#define CHECK_RESULT(result,msg) \
  if (VK_SUCCESS != (result)) {\
	char txt[2048];\
	sprintf(txt, "Failure in %s at %u %s  ErrCode=%d\n", msg,__LINE__, __FILE__,result);\
	exitOnError(txt);\
  }

int vulkanInit();
void vulkanEnd();
void getDeviceName(int index, char* name);
uint64_t getMemorySize(int index);
int getComputeQueueFamillyIndex(uint32_t index);
VkDevice createDevice(int index,uint32_t computeQueueFamillyIndex);
VkDeviceMemory allocateGPUMemory(int index,  VkDevice vkDevice, const VkDeviceSize memorySize, char isLocal);
void initCommandPool(VkDevice vkDevice, uint32_t computeQueueFamillyIndex,VkCommandPool *commandPool);
VkCommandBuffer createCommandBuffer(VkDevice vkDevice,VkCommandPool commandPool);
VkBuffer createBuffer(VkDevice vkDevice,uint32_t computeQueueFamillyIndex,VkDeviceMemory memory,VkDeviceSize bufferSize, VkDeviceSize offset);
VkPipelineLayout bindBuffers(VkDevice vkDevice,VkDescriptorSet &descriptorSet, VkDescriptorPool &descriptorPool, VkDescriptorSetLayout &descriptorSetLayout, VkBuffer b0, VkBuffer b1,VkBuffer b2, VkBuffer b3, VkBuffer b4, VkBuffer b5, VkBuffer b6,VkBuffer b7,VkBuffer b8);
VkPipelineLayout bindBuffer(VkDevice vkDevice,VkDescriptorSet &descriptorSet, VkDescriptorPool &descriptorPool, VkDescriptorSetLayout &descriptorSetLayout, VkBuffer b);
VkPipeline loadShader(VkDevice vkDevice, VkPipelineLayout pipelineLayout,VkShaderModule &shader_module, const char * file_name);
void prepareGPUConstants();
void shaderStats(VkDevice vkDevice,VkPipeline shader);
int32_t getSubGroupSize(int index);

#endif /* MVULKAN_HPP_ */
