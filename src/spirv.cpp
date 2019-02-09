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
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <iostream>
#include <sstream>

#include "spirv.hpp"
#include "log.hpp"

using namespace std;

// From the Monero project - Variant 4
static string writeV4Code(const V4_Instruction* code, bool randomMath64) {
	ostringstream s;
	for (int i = 0; i < TOTAL_LATENCY * ALU_COUNT + 1; ++i) {
		const V4_Instruction inst = code[i];

		const uint32_t a = inst.dst_index;
		const uint32_t b = inst.src_index;

		switch (inst.opcode) {
		case MUL:
			s << 'r' << a << "*=r" << b << ';';
			break;

		case ADD:
			s << 'r' << a << "+=r" << b << '+' << inst.C << "U;";
			break;

		case SUB:
			s << 'r' << a << "-=r" << b << ';';
			break;

		case ROR:
			s << "r" << a << " = rotate" << (randomMath64 ? 64 : 32) << "(r" << a << "," << (randomMath64 ? 64 : 32) << "-r" << b << ");";
			break;
		case ROL:
			s << "r" << a << " = rotate" << (randomMath64 ? 64 : 32) << "(r" << a << ", r" << b << ");";
			break;

		case XOR:
			s << 'r' << a << "^=r" << b << ';';
			break;

		case RET:
			return s.str();
			break;
		}
	}
	return s.str();
}

const char *getCryptonightRSpirVName(bool hi, int localSize) {
#ifdef __MINGW32__
	if (hi) {
		if (localSize == 8) return "spirv\\cnrm8.spv";
		else return "spirv\\cnrm16.spv";
	} else {
		if (localSize == 8) return "spirv\\cnrl8.spv";
		else return "spirv\\cnrl16.spv";
	}
#else
	if (hi) {
		if (localSize == 8)
			return "spirv/cnrm8.spv";
		else
			return "spirv/cnrm16.spv";
	} else {
		if (localSize == 8)
			return "spirv/cnrl8.spv";
		else
			return "spirv/cnrl16.spv";
	}
#endif
}

void buildCryptonightR(const struct V4_Instruction* code, bool hi, bool light, int localSize, bool randomMath64) {
	ostringstream s;
	s << "#version 460\n";
	s << "#extension GL_ARB_gpu_shader_int64 : require\n";
	s << "layout(binding = 0) buffer scratchpadsBuffer1 { uvec4 scratchpad1[]; };layout(binding = 1) buffer scratchpadsBuffer2 { uvec4 scratchpad2[]; };layout(binding = 2) buffer statesBuffer { uint64_t states[]; };layout(binding = 4) buffer Params { uint64_t target;uint memorySize;uint global_work_offset;uint iterations;uint mask;uint threads;uint scratchpatSplit;};layout(binding = 5) buffer constants{uint AES0_C[256];};layout(binding = 6) buffer inputsBuffer {uint64_t inputs[];};\n";
	s << "layout (local_size_x = " << localSize << ", local_size_y = 1) in;\n";
	s << "shared uint AES0[256], AES1[256], AES2[256], AES3[256];\n";
	s << "#define INDEX0  (scratchpadOffset + ((idx0 >> 4)))\n";
	s << "#define INDEX1  (scratchpadOffset + ((idx0 >> 4) ^ 1))\n";
	s << "#define INDEX2  (scratchpadOffset + ((idx0 >> 4) ^ 2))\n";
	s << "#define INDEX3  (scratchpadOffset + ((idx0 >> 4) ^ 3))\n";
	s << "#define BYTE(x,b)  ((x) >> (8*(b)))&0xff\n";
	if (light)
		s << "#define SCRATCHPAD_SPLIT 3584\n";
	else
		s << "#define SCRATCHPAD_SPLIT 1792\n";
	s << "uint mul_hi(uint a, uint b) { uint64_t a0 = a;uint64_t b0 = b;return uint((a0*b0)>>32);}\n";
	s << "uint rotate32(uint x, uint c) {return (x << c) | (x >> (32-c));}\n";
	s << "uint64_t mul_hi64(uint64_t x, uint64_t y) {uint64_t x0 = x & 0xffffffffUL;uint64_t x1 = x >> 32;uint64_t y0 = y & 0xffffffffUL;uint64_t y1 = y >> 32;uint64_t z0 = x0*y0;uint64_t t = x1*y0 + (z0 >> 32);uint64_t z1 = t & 0xffffffffUL;uint64_t z2 = t >> 32;z1 = x0*y1 + z1;return x1*y1 + z2 + (z1 >> 32);}\n";
	s << "void main() {\n";
	s << "uint64_t a[2];uint64_t b[4];uvec4 b_x[2];uvec4 chunk0,chunk1,chunk2,chunk3,_chunk0,_chunk1,_chunk2,_chunk3;\n";
	if (randomMath64)
		s << "uint64_t r0,r1,r2,r3,r4,r5,r6,r7;\n";
	else
		s << "uint r0,r1,r2,r3,r4,r5,r6,r7;\n";
	s << "const uint lIdx = gl_LocalInvocationID.x;\n";
	s << "const uint gIdx = gl_GlobalInvocationID.x ";
	if (hi) s << " + SCRATCHPAD_SPLIT";
	s << ";\n";
	s << "for(uint i = lIdx ; i < 256; i += gl_WorkGroupSize.x){const uint tmp = AES0_C[i];AES0[i] = tmp;AES1[i] = rotate32(tmp, 8U);AES2[i] = rotate32(tmp, 16U);AES3[i] = rotate32(tmp, 24U);}\n";
	s << "memoryBarrierShared();\n";
	s << "const uint stateOffset = 25 * gIdx;\n";
	s << "const uint scratchpadOffset = gl_GlobalInvocationID.x * (memorySize >> 4);\n";
	s << "a[0] = states[stateOffset+0] ^ states[stateOffset+4];b[0] = states[stateOffset+2] ^ states[stateOffset+6];a[1] = states[stateOffset+1] ^ states[stateOffset+5];\n";
	s << "b[1] = states[stateOffset+3] ^ states[stateOffset+7];b[2] = states[stateOffset+8] ^ states[stateOffset+10];b[3] = states[stateOffset+9] ^ states[stateOffset+11];\n";
	s << "b_x[0] = uvec4(unpackUint2x32(b[0]).x,unpackUint2x32(b[0]).y,unpackUint2x32(b[1]).x,unpackUint2x32(b[1]).y);\n";
	s << "b_x[1] = uvec4(unpackUint2x32(b[2]).x,unpackUint2x32(b[2]).y,unpackUint2x32(b[3]).x,unpackUint2x32(b[3]).y);\n";
	if (randomMath64)
		s << "r0 = states[stateOffset+12];r1 = states[stateOffset+13];r2 = states[stateOffset+14];r3 = states[stateOffset+15];\n";
	else
		s << "r0 = unpackUint2x32(states[stateOffset+12]).x;r1 = unpackUint2x32(states[stateOffset+12]).y;r2 = unpackUint2x32(states[stateOffset+13]).x;r3 = unpackUint2x32(states[stateOffset+13]).y;\n";
	s << "uint idx0 = uint(a[0]) & mask;\n";
	s << "uint64_t c[2],m0,m1;uint64_t result_mul[2];uvec4 tmp;\n";
	s << "for(uint i = 0; i < iterations; ++i)\n";
	s << "{\n";
	const int o = hi ? 2 : 1;
	s << "chunk0 = scratchpad" << o << "[INDEX0];chunk1 = scratchpad" << o << "[INDEX1];chunk2 = scratchpad" << o << "[INDEX2];chunk3 = scratchpad" << o << "[INDEX3];\n";
	s << "_chunk0 = uvec4(unpackUint2x32(a[0]),unpackUint2x32(a[1]));\n";
	s << "_chunk0.x ^= AES0[BYTE(chunk0.x, 0)];_chunk0.y ^= AES0[BYTE(chunk0.y, 0)];_chunk0.z ^= AES0[BYTE(chunk0.z, 0)];_chunk0.w ^= AES0[BYTE(chunk0.w, 0)];\n";
	s << "_chunk0.x ^= AES2[BYTE(chunk0.z, 2)];_chunk0.y ^= AES2[BYTE(chunk0.w, 2)];_chunk0.z ^= AES2[BYTE(chunk0.x, 2)];_chunk0.w ^= AES2[BYTE(chunk0.y, 2)];\n";
	s << "_chunk0.x ^= AES1[BYTE(chunk0.y, 1)];_chunk0.y ^= AES1[BYTE(chunk0.z, 1)];_chunk0.z ^= AES1[BYTE(chunk0.w, 1)];_chunk0.w ^= AES1[BYTE(chunk0.x, 1)];\n";
	s << "_chunk0.x ^= AES3[BYTE(chunk0.w, 3)];_chunk0.y ^= AES3[BYTE(chunk0.x, 3)];_chunk0.z ^= AES3[BYTE(chunk0.y, 3)];_chunk0.w ^= AES3[BYTE(chunk0.z, 3)];\n";
	s << "c[0] = packUint2x32(_chunk0.xy);\n";
	s << "c[1] = packUint2x32(_chunk0.zw);\n";
	s << "_chunk0 ^= b_x[0];m0 = packUint2x32(chunk3.xy) + packUint2x32(b_x[1].xy);m1 = packUint2x32(chunk3.zw) + packUint2x32(b_x[1].zw);\n";
	s << "_chunk1 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));m0 = packUint2x32(chunk1.xy) + packUint2x32(b_x[0].xy);m1 = packUint2x32(chunk1.zw) + packUint2x32(b_x[0].zw);\n";
	s << "_chunk2 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));m0 = packUint2x32(chunk2.xy) + a[0];m1 = packUint2x32(chunk2.zw) + a[1];\n";
	s << "_chunk3 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));\n";
	s << "scratchpad" << o << "[INDEX0] = _chunk0;scratchpad" << o << "[INDEX1] = _chunk1;scratchpad" << o << "[INDEX2] = _chunk2;scratchpad" << o << "[INDEX3] = _chunk3;\n";
	s << "idx0 = uint(c[0]) & mask;\n";
	s << "_chunk0 = scratchpad" << o << "[INDEX0];_chunk1 = scratchpad" << o << "[INDEX1];_chunk2 = scratchpad" << o << "[INDEX2];_chunk3 = scratchpad" << o << "[INDEX3];\n";
	s << "tmp = _chunk0;\n";
	if (randomMath64) {
		s << "const uint64_t random_math_result = (r0 + r1) ^ (r2 + r3);\n";
		s << "tmp.x ^= unpackUint2x32(random_math_result).x;tmp.y ^= unpackUint2x32(random_math_result).y;\n";
		s << "r4 = a[0];r5 = a[1];r6 = packUint2x32(b_x[0].xy);r7 = packUint2x32(b_x[1].xy);\n";
	} else {
		s << "tmp.x ^= r0 + r1;tmp.y ^= r2 + r3;r4 = unpackUint2x32(a[0]).x;r5 = unpackUint2x32(a[1]).x;r6 = b_x[0].x;r7 = b_x[1].x;\n";
	}
	s << writeV4Code(code, randomMath64);
	s << "result_mul[0] = mul_hi64(c[0], packUint2x32(tmp.xy));result_mul[1] = c[0] * packUint2x32(tmp.xy);\n";
	s << "_chunk1 ^= uvec4(unpackUint2x32(result_mul[0]),unpackUint2x32(result_mul[1]));\n";
	s << "result_mul[0] ^= packUint2x32(_chunk2.xy);result_mul[1] ^= packUint2x32(_chunk2.zw);\n";
	s << "m0 = packUint2x32(_chunk3.xy) + packUint2x32(b_x[1].xy);m1 = packUint2x32(_chunk3.zw) + packUint2x32(b_x[1].zw);chunk1 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));\n";
	s << "m0 = packUint2x32(_chunk1.xy) + packUint2x32(b_x[0].xy);m1 = packUint2x32(_chunk1.zw) + packUint2x32(b_x[0].zw);chunk2 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));\n";
	s << "m0 = packUint2x32(_chunk2.xy) + a[0];m1 = packUint2x32(_chunk2.zw) + a[1];chunk3 = uvec4(unpackUint2x32(m0),unpackUint2x32(m1));\n";
	s << "a[1] += result_mul[1];a[0] += result_mul[0];chunk0 = uvec4(unpackUint2x32(a[0]),unpackUint2x32(a[1]));\n";
	s << "scratchpad" << o << "[INDEX0] = chunk0;scratchpad" << o << "[INDEX1] = chunk1;scratchpad" << o << "[INDEX2] = chunk2;scratchpad" << o << "[INDEX3] = chunk3;\n";
	s << "a[0] ^= packUint2x32(tmp.xy);a[1] ^= packUint2x32(tmp.zw);b_x[1] = b_x[0];b_x[0] = uvec4(unpackUint2x32(c[0]),unpackUint2x32(c[1]));idx0 = uint(a[0]) & mask;}}\n";


	FILE *f = fopen("src.comp", "w");
	if (f == NULL) {
		error("Failed to create Vulkan file", "src.comp");
		return;
	}
	fwrite(s.str().c_str(), s.str().size(), 1, f);
	fclose(f);

	char cmd[1024];
#ifdef __MINGW32__
	sprintf(cmd,"glslangValidator.exe -s -o %s -V src.comp",getCryptonightRSpirVName(hi,localSize));
#else
	sprintf(cmd,"./glslangValidator -s -o %s -V src.comp; rm src.comp;",getCryptonightRSpirVName(hi,localSize));
#endif
	system(cmd);
#ifdef __MINGW32__
	system("del src.comp");
#endif
}

