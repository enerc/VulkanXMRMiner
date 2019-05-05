#
# Cryptonight Vulkan Mining Software
#
cmake_minimum_required(VERSION 3.5.0)

project(VulkanXMRMiner)

# enforce C++11
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)

# change the processor target here if needed
set(ARCH "native")

# change gcc for Windows 64 build
if(WIN32)
	SET(CMAKE_SYSTEM_NAME Windows)
	SET(CMAKE_C_COMPILER x86_64-w64-mingw32-g++-win32)
	SET(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++-win32)
	SET(CMAKE_FIND_ROOT_PATH /usr/bin/)
endif()

# set AVX for debug,release,unspecified
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_CXX_FLAGS_DEBUG "-g3 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	set(CMAKE_C_FLAGS_DEBUG  "-g3 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
else()
	set(CMAKE_CXX_FLAGS_RELEASE "-O1 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	set(CMAKE_C_FLAGS_RELEASE "-O1 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	# if not build specified
	set(CMAKE_CXX_FLAGS "-O1 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	set(CMAKE_C_FLAGS "-O1 -mavx -march=${ARCH}" CACHE STRING "compile flags" FORCE)
endif()

# Look for vulkan SDK
# For a Windows build on Linux, install the Vulkan SDK with wine, and set VULKAN_SDK to ..../.wine/drive_c/VulkanSDK/1.x.y
# For Linux, install libvulkan-dev
find_path(VulkanIncludes vulkan/vulkan.h PATHS ENV VULKAN_SDK ENV /usr )
if(NOT VulkanIncludes)
  message(FATAL_ERROR "Can't find folder containing vulkan.h")
endif()

if (SOFT_AES)
	message("Build without aesi-ni and without avx")
	SET(ARCH core2)
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(CMAKE_CXX_FLAGS_RELEASE "-g3 -DSOFT_AES -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS_RELEASE "-g3 -DSOFT_AES  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	else()
		set(CMAKE_CXX_FLAGS_RELEASE "-O1 -DSOFT_AES -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS_RELEASE "-O1 -DSOFT_AES  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		# if not build specified
		set(CMAKE_CXX_FLAGS "-O1 -DSOFT_AES  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS "-O1 -DSOFT_AES  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	endif()
endif()

if (CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
	message("Build for ARM V8 (Cortex A53 +)")
	SET(ARCH native)
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(CMAKE_CXX_FLAGS_RELEASE "-g3 -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS_RELEASE "-g3 -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	else()
		set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS_RELEASE "-O3  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		# if not build specified
		set(CMAKE_CXX_FLAGS "-O3  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
		set(CMAKE_C_FLAGS "-O3  -march=${ARCH}" CACHE STRING "compile flags" FORCE)
	endif()
endif()
	
# Add Include/Lib (Windows) and include/lib (Linux)
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(ADDITIONAL_LIBRARIES vulkan-1 pthread ws2_32)
	include_directories("$ENV{VULKAN_SDK}/Include")
	link_directories("$ENV{VULKAN_SDK}/Lib")
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(ADDITIONAL_LIBRARIES vulkan pthread)
	include_directories("$ENV{VULKAN_SDK}/include")
	link_directories("$ENV{VULKAN_SDK}/lib")
endif()
                      
file(GLOB SRCFILES_CPP "src/*.cpp")
set_source_files_properties(${SRCFILES_CPP} PROPERTIES LANGUAGE CXX)

file(GLOB SRCFILES_S "src/*.S")
set_source_files_properties(${SRCFILES_S} PROPERTIES LANGUAGE C)

add_executable(miner ${SRCFILES_CPP} ${SRCFILES_S})
target_link_libraries(miner ${ADDITIONAL_LIBRARIES})

# copy SPIR-V programs, GLSL compiler (cryptonightR), and Windows DLLs
add_custom_command(TARGET miner PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/spirv spirv)
add_custom_command(TARGET miner PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/redist .)

# make the download file for Linux
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux" AND NOT (CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64))
	add_custom_target(zip ALL DEPENDS miner COMMAND
    ${CMAKE_COMMAND} -E tar "zcvf" "vulkanXMRMiner.tgz"
    "miner"
    "spirv"
    "glslangValidator"
    )
endif()

# same as Linux, but add mingw runtime DLLs.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	add_custom_target(zip ALL DEPENDS miner COMMAND
    ${CMAKE_COMMAND} -E tar "cvf" "vulkanXMRMiner.zip" --format=zip
    "miner.exe"
    "spirv"
    "glslangValidator.exe"
    "libgcc_s_seh-1.dll"
    "libstdc++-6.dll"
    "libwinpthread-1.dll"
    )
endif()
