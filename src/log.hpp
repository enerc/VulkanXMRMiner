#ifndef LOG_HPP_
#define LOG_HPP_
#include <vulkan/vulkan.h>

enum LogLevel {
	LEVEL_DEBUG,
	LEVEL_WARN,
	LEVEL_ERROR
};

void exitOnError(const char *s);
void debug(const char *title,const char *msg);
void debugnc(const char *title,const char *msg);
void error(const char *title,const char *msg);
void errornc(const char *title,const char *msg);
void printDate();

VKAPI_ATTR VkBool32 VKAPI_CALL myDebugReportCallback(
    VkDebugReportFlagsEXT       flags,
    VkDebugReportObjectTypeEXT  objectType,
    uint64_t                    object,
    size_t                      location,
    int32_t                     messageCode,
    const char*                 pLayerPrefix,
    const char*                 pMessage,
    void*                       pUserData);

#endif /* LOG_HPP_ */
