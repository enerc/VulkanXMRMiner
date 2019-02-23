#ifndef SPIRV_H_
#define SPIRV_H_

// ****** V4 Variant

// Register size can be configured to either 32 bit (uint32_t) or 64 bit (uint64_t)
typedef uint32_t v4_reg;

enum V4_Settings {
	// Generate code with minimal theoretical latency = 45 cycles, which is equivalent to 15 multiplications
	TOTAL_LATENCY = 15 * 3,

	// Always generate at least 60 instructions
	NUM_INSTRUCTIONS_MIN = 60,

	// Never generate more than 70 instructions (final RET instruction doesn't count here)
	NUM_INSTRUCTIONS_MAX = 70,

	// Available ALUs for MUL
	// Modern CPUs typically have only 1 ALU which can do multiplications
	ALU_COUNT_MUL = 1,

	// Total available ALUs
	// Modern CPUs have 4 ALUs, but we use only 3 because random math executes together with other main loop code
	ALU_COUNT = 3
};

enum V4_InstructionList {
	MUL,	// a*b
	ADD,	// a+b + C, -128 <= C <= 127
	SUB,	// a-b
	ROR,	// rotate right "a" by "b & 31" bits
	ROL,	// rotate left "a" by "b & 31" bits
	XOR,	// a^b
	RET,	// finish execution
	V4_INSTRUCTION_COUNT = RET,};

enum V4_InstructionDefinition {
	V4_OPCODE_BITS = 3,
	V4_DST_INDEX_BITS = 2,
	V4_SRC_INDEX_BITS = 3,
};

// V4_InstructionCompact is used to generate code from random data
// Every random sequence of bytes is a valid code
//
// Instruction encoding is 1 byte for all instructions except ADD
// ADD instruction uses second byte for constant "C" in "a+b+C"
//
// There are 8 registers in total:
// - 4 variable registers
// - 4 constant registers initialized from loop variables
//
// This is why dst_index is 2 bits
struct V4_Instruction {
	uint8_t opcode;
	uint8_t dst_index;
	uint8_t src_index;
	uint32_t C;
};

void buildCryptonightR(const struct V4_Instruction* code, bool hi, bool light, int localSize, bool randomMath64, uint32_t iterations, uint32_t mask, CryptoType cryptoType );
const char *getCryptonightRSpirVName(bool hilo, int localSize);
#endif /* SÎRV_H_ */
