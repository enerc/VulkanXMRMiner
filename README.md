# VulkanXMRMiner

This program is a Vulkan SPIR-V based miner for Cryptonight:<br/>
<img src="https://monero.org/wp-content/uploads/2015/03/logo-big.jpg" height="67" width="250" >     <img src="http://wownero.org/images/wow.png" height="40" width="200" >     <img src="https://www.aeon.cash/branding/aeon_logo_32x32.png" height="67" width="80" >

This miner is based on Vulkan technology (not OpenCL):
<img src="https://www.khronos.org/assets/uploads/apis/vulkan2.svg" height="67" width="250" ><img src="https://www.khronos.org/assets/uploads/ceimg/made/assets/uploads/apis/SPIR_100px_June16_150_75.png" height="67" width="250" >

What's Vulkan:<br/>
>Vulkan is a new generation graphics and compute API that provides high-efficiency, cross-platform access to modern GPUs used in a wide variety of devices from PCs and consoles to mobile phones and embedded platforms.

This program should work on any Vulkan 1.0 compatible device: AMD, Intel, Nvidia.

# Download and run
You can get Windows binaries here:  <a href="https://github.com/enerc">Download</a> <br />
You can get Linux binaries here:  <a href="https://github.com/enerc">Download</a> <br />

Extract the zip file, and run Miner.exe / Miner.<br/>

The binary glslangValidator.exe/glslangValidator is from the Vulkan SDK and is for CryptonightR to a compile new SPIR-V kernel at each new block.

# Performance
## on CN V2 (Variant 2)
<span style="font-family: monospace;">
Vega56 1500/1075&nbsp;: 1800 H/s on Windows 10 (200 W)<br />
Vega56 1500/945&nbsp;&nbsp;: 1635 H/s on Windows 10<br />
Vega56 PowerSave&nbsp;: 1595 H/s on Windows 10<br />
Vega56 1500/945&nbsp;&nbsp;: 1625 H/s on Linux Rocm 2.0 (200 W)<br />
Vega56 1200/800&nbsp;&nbsp;: 1460 H/s on Linux Rocm 2.0 (100 W)<br />
R9 Fury 1050/500&nbsp;: 835 H/s on Windows 10<br />
R9 Fury 1050/500&nbsp;: 835 H/s on Linux ROCM 2.0 (185 W)<br />
R9 Fury 874/500&nbsp;&nbsp;: 700 H/s on Linux ROCM 2.0 (100 >)<br/>
RX560 1000/1850&nbsp;&nbsp;: 410 H/s on Linux amdgpu-pro (25 W)<br />
RX550 1000/1800&nbsp;&nbsp;: 330 H/s on Linux amdgpu-pro (16 W)<br />
</span>

## on CN/R (CryptonightR - Variant 4)
<span style="font-family: monospace;">
Vega56 1500/1075&nbsp;: 1805 H/s on Windows 10 (200 W)<br />
R9 Fury 1050/500&nbsp;: 833 H/s on Windows 10<br />
R9 Fury 874/500&nbsp;&nbsp;: 700 H/s on Linux ROCM 2.0 (100 >)<br/>
</span>

## on CN Light V7 (Aeon)
<span style="font-family: monospace;">
Vega56 1500/1075&nbsp;: 3900 H/s on Windows 10 (200 W)<br />
Vega56 PowerSave&nbsp;: 3526 H/s on Windows 10<br />
</span>

# Drivers installation
On Windows, Vulkan should be provided with recent drivers for AMD and NVIDIA.<br/>
If unsure chech https://www.amd.com/en/technologies/vulkan or https://developer.nvidia.com/vulkan-driver.<br/>
If you run intro trouble, please download the Vulkan SDK at https://www.lunarg.com/vulkan-sdk/ and run the vulkaninfo.exe tool to check your drivers are properly installed.
<br/><br/>
On Linux, install amdgpu/amdgpu-pro as usual or ROCM and either install the vulkan driver (<i>apt-get install libvulkan1</i>) or install the SDK https://www.lunarg.com/vulkan-sdk/.<br />
It is recommended to check your configuration with vulkaninfo that you can get with <i>apt-get install vulkan-utils</i>.
<br/>
As for Windows, check the installation with vulkaninfo.<br/>
If it does not work, check that the ICD is properly configured.
In /etc/vulkan/icd.d/ there should be a file with sothing like:
>{<br/>
    "file_format_version" : "1.0.0",<br/>
    "ICD" : {<br/>
        "library_path" : "path_to/amdvlk64.so",<br/>
        "api_version" : "1.1.something"<br/>
    }<br/>
}<br/>

# Configuration
When entering the miner, a setup menu will be shown if there are no config.json file there.<br />
- on wallet_address you can add a worker/farm id by adding .your_farm after the address
- The cu parameter is the number of compute units (AMD terminology) / Stream Multiprocessors(Nvidia).<br />
- The factor is how many threads are sent to each cu. <br/>
- The worksize is the number of threads per cu at a given time.<br/>
- Used memory is given by: <br/>
Number of CU x Factor x 2 Mb (1Mb for Cryptonight light)<br/>
- So for example a 56 CU with a factor 64 on Monero will use:<br/>
56 * 64 * 2 = 7168 Mb of Video RAM. <br/>

# Build
For Windows,use Eclipse CDT, Mingw and the Vulkan SDK. Import the project from Githib and build it.<br/>
For Linux users TBD. 
