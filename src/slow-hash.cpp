// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
#include <stdio.h>
#include <stdlib.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#ifdef __MINGW32__
#include <windows.h>
#include <intrin.h>
#else
#include <sys/mman.h>
#endif

#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/timeb.h>

#include <cstdint>

#include "config.hpp"
#include "slow_hash.hpp"
#include "log.hpp"
#include "network.hpp"
#include "miner.hpp"
#include "spirv.hpp"

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#define KECCAK_ROUNDS 24
#define U64(x) ((uint64_t *) (x))
#define R128(x) ((__m128i *) (x))
#define NONCE_POINTER (((const uint8_t*)data)+35)
#define TOTALBLOCKS (MEMORY / AES_BLOCK_SIZE)
#define state_index(x,div) (((*((uint64_t *)x) >> 4) & (TOTALBLOCKS /(div*isLight) - 1)) << 4)

#define VARIANT1_CHECK() \
		if (length < 43) \
		{ \
			exitOnError("Cryptonight variant 1 needs at least 43 bytes of data"); \
		};


#define VARIANT1_INIT64() \
		if (cpuMiner.variant == 1) \
		{ \
			VARIANT1_CHECK(); \
		} \
		const uint64_t tweak1_2 = (cpuMiner.variant == 1) ? (cpuMiner.shs.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER))) : 0

#define VARIANT2_INIT64() \
		uint64_t division_result = 0; \
		uint64_t sqrt_result = 0; \
		if (cpuMiner.variant >= 2) \
		{ \
			U64(b)[2] = cpuMiner.shs.hs.w[8] ^ cpuMiner.shs.hs.w[10]; \
			U64(b)[3] = cpuMiner.shs.hs.w[9] ^ cpuMiner.shs.hs.w[11]; \
			division_result = cpuMiner.shs.hs.w[12]; \
			sqrt_result = cpuMiner.shs.hs.w[13]; \
		};

#define VARIANT1_1(p) \
		if (cpuMiner.variant == 1) \
		{ \
			const uint8_t tmp = ((const uint8_t*)(p))[11]; \
			static const uint32_t table = 0x75310; \
			const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
			((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
		} ;

static void xor64(uint64_t *a, const uint64_t b) {
	*a ^= b;
}

#define VARIANT1_2(p) \
		do if (cpuMiner.variant == 1) \
		{ \
			xor64(p, tweak1_2); \
		} while(0)

#define pre_aes() \
		j = state_index(a,cpuMiner.memFactor); \
		_c = _mm_load_si128(R128(&php_state[j])); \
		_a = _mm_load_si128(R128(a)); \

#define VARIANT2_SHUFFLE_ADD_SSE2(base_ptr, offset) \
		if (cpuMiner.variant  >= 2 && cpuMiner.type != MoneroCrypto) \
		{ \
			const __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))); \
			const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
			const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
			_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
			_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
			_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
		} \
		if (cpuMiner.variant  >= 2 && cpuMiner.type == MoneroCrypto) { \
			 __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))); \
			 const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
			 const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
			 _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
			 _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
			 _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
			 if (cpuMiner.variant >= 4) \
			 { \
			      chunk1 = _mm_xor_si128(chunk1, chunk2); \
			      _c = _mm_xor_si128(_c, chunk3); \
			      _c = _mm_xor_si128(_c, chunk1); \
			} \
		}

#define VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr) \
		((uint64_t*)(b))[0] ^= division_result ^ (sqrt_result << 32); \
		{ \
			const uint64_t dividend = ((uint64_t*)(ptr))[1]; \
			const uint32_t divisor = (((uint64_t*)(ptr))[0] + (uint32_t)(sqrt_result << 1)) | 0x80000001UL; \
			division_result = ((uint32_t)(dividend / divisor)) + \
			(((uint64_t)(dividend % divisor)) << 32); \
		} \
		const uint64_t sqrt_input = ((uint64_t*)(ptr))[0] + division_result

#define VARIANT2_INTEGER_MATH_SQRT_STEP_SSE2() \
		{ \
			const __m128i exp_double_bias = _mm_set_epi64x(0, 1023ULL << 52); \
			__m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(sqrt_input >> 12), exp_double_bias)); \
			x = _mm_sqrt_sd(_mm_setzero_pd(), x); \
			sqrt_result = (uint64_t)(_mm_cvtsi128_si64(_mm_sub_epi64(_mm_castpd_si128(x), exp_double_bias))) >> 19; \
		}

#define VARIANT2_INTEGER_MATH_SQRT_FIXUP(r) \
		{ \
	const uint64_t s = r >> 1; \
	const uint64_t b = r & 1; \
	const uint64_t r2 = (uint64_t)(s) * (s + b) + (r << 32); \
	r += ((r2 + b > sqrt_input) ? -1 : 0) + ((r2 + (1ULL << 32) < sqrt_input - s) ? 1 : 0); \
		}

#define VARIANT2_INTEGER_MATH_SSE2(b, ptr) \
		if ((cpuMiner.variant == 2) || (cpuMiner.variant == 3)) \
		{ \
			VARIANT2_INTEGER_MATH_DIVISION_STEP(b, ptr); \
			VARIANT2_INTEGER_MATH_SQRT_STEP_SSE2(); \
			VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result); \
		};

#define VARIANT2_2() \
		if (cpuMiner.variant == 4 && cpuMiner.type == MoneroCrypto) {\
		} else if (cpuMiner.variant >= 2) \
		{ \
			*U64(php_state + (j ^ 0x10)) ^= hi; \
			*(U64(php_state + (j ^ 0x10)) + 1) ^= lo; \
			hi ^= *U64(php_state + (j ^ 0x20)); \
			lo ^= *(U64(php_state + (j ^ 0x20)) + 1); \
		};



// Random math interpreter's loop is fully unrolled and inlined to achieve 100% branch prediction on CPU:
// every switch-case will point to the same destination on every iteration of Cryptonight main loop
//
// This is about as fast as it can get without using low-level machine code generation
void v4_random_math(const struct V4_Instruction* code, v4_reg* r)
{
	enum
	{
		REG_BITS = sizeof(v4_reg) * 8,
	};

#define V4_EXEC(i) \
		{ \
	const struct V4_Instruction* op = code + i; \
	const v4_reg src = r[op->src_index]; \
	v4_reg* dst = r + op->dst_index; \
	switch (op->opcode) \
	{ \
	case MUL: \
	*dst *= src; \
	break; \
	case ADD: \
	*dst += src + op->C; \
	break; \
	case SUB: \
	*dst -= src; \
	break; \
	case ROR: \
	{ \
		const uint32_t shift = src % REG_BITS; \
		*dst = (*dst >> shift) | (*dst << (REG_BITS - shift)); \
	} \
	break; \
	case ROL: \
	{ \
		const uint32_t shift = src % REG_BITS; \
		*dst = (*dst << shift) | (*dst >> (REG_BITS - shift)); \
	} \
	break; \
	case XOR: \
	*dst ^= src; \
	break; \
	case RET: \
	return; \
	default: \
	__builtin_unreachable();\
	break; \
	} \
		}

#define V4_EXEC_10(j) \
		V4_EXEC(j + 0) \
		V4_EXEC(j + 1) \
		V4_EXEC(j + 2) \
		V4_EXEC(j + 3) \
		V4_EXEC(j + 4) \
		V4_EXEC(j + 5) \
		V4_EXEC(j + 6) \
		V4_EXEC(j + 7) \
		V4_EXEC(j + 8) \
		V4_EXEC(j + 9)

	// Generated program can have up to 109 instructions (54*2+1: 54 clock cycles with 2 ALUs running + one final RET instruction)
	V4_EXEC_10(0);		// instructions 0-9
	V4_EXEC_10(10);		// instructions 10-19
	V4_EXEC_10(20);		// instructions 20-29
	V4_EXEC_10(30);		// instructions 30-39
	V4_EXEC_10(40);		// instructions 40-49
	V4_EXEC_10(50);		// instructions 50-59
	V4_EXEC_10(60); // instructions 60-69
#undef V4_EXEC_10
#undef V4_EXEC
}


#if defined(__x86_64__)
#define __mul() __asm("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" (c[0]), "rm" (b[0]) : "cc");
#else
#define __mul() lo = mul128(c[0], b[0], &hi);
#endif

/*
 * An SSE-optimized implementation of the second half of CryptoNight step 3.
 * After using AES to mix a scratchpad value into _c (done by the caller),
 * this macro xors it with _b and stores the result back to the same index (j) that it
 * loaded the scratchpad value from.  It then performs a second random memory
 * read/write from the scratchpad, but this time mixes the values using a 64
 * bit multiply.
 * This code is based upon an optimized implementation by dga.
 */
#define post_aes() \
		VARIANT2_SHUFFLE_ADD_SSE2(php_state, j); \
		_mm_store_si128(R128(c), _c); \
		_mm_store_si128(R128(&php_state[j]), _mm_xor_si128(_b, _c)); \
		VARIANT1_1(&php_state[j]); \
		j = state_index(c,(cpuMiner.memFactor)); \
		p = U64(&php_state[j]); \
		b[0] = p[0]; b[1] = p[1]; \
		VARIANT2_INTEGER_MATH_SSE2(b, c); \
		VARIANT4_RANDOM_MATH(a, b, r, &_b, &_b1); \
		__mul(); \
		VARIANT2_2(); \
		VARIANT2_SHUFFLE_ADD_SSE2(php_state, j); \
		a[0] += hi; a[1] += lo; \
		p = U64(&php_state[j]); \
		p[0] = a[0];  p[1] = a[1]; \
		a[0] ^= b[0]; a[1] ^= b[1]; \
		VARIANT1_2(p + 1); \
		_b1 = _b; \
		_b = _c;

#define U8TO32(p) \
		(((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |    \
				((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))
#define U32TO8(p, v) \
		(p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
		(p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define ROWS 8
#define LENGTHFIELDLEN ROWS
#define COLS512 8
#define SIZE512 (ROWS*COLS512)
#define ROUNDS512 10
#define HASH_BIT_LEN 256
#define ROTL32(v, n) ((((v)<<(n))|((v)>>(32-(n))))&li_32(ffffffff))

#define li_32(h) 0x##h##u
#define EXT_BYTE(var,n) ((uint8_t)((uint32_t)(var) >> (8*n)))

#define u32BIG(a)				\
		((ROTL32(a,8) & li_32(00FF00FF)) |		\
				(ROTL32(a,24) & li_32(FF00FF00)))

#define  SKEIN_MODIFIER_WORDS  ( 2)          /* number of modifier (tweak) words */

#define  SKEIN_256_STATE_WORDS ( 4)
#define  SKEIN_512_STATE_WORDS ( 8)
#define  SKEIN1024_STATE_WORDS (16)
#define  SKEIN_MAX_STATE_WORDS (16)

#define  SKEIN_256_STATE_BYTES ( 8*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_STATE_BYTES ( 8*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_STATE_BYTES ( 8*SKEIN1024_STATE_WORDS)

#define  SKEIN_256_STATE_BITS  (64*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_STATE_BITS  (64*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_STATE_BITS  (64*SKEIN1024_STATE_WORDS)

#define  SKEIN_256_BLOCK_BYTES ( 8*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_BLOCK_BYTES ( 8*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_BLOCK_BYTES ( 8*SKEIN1024_STATE_WORDS)

#define SKEIN_RND_SPECIAL       (1000u)
#define SKEIN_RND_KEY_INITIAL   (SKEIN_RND_SPECIAL+0u)
#define SKEIN_RND_KEY_INJECT    (SKEIN_RND_SPECIAL+1u)
#define SKEIN_RND_FEED_FWD      (SKEIN_RND_SPECIAL+2u)
#ifndef SKEIN_256_NIST_MAX_HASHBITS
#define SKEIN_256_NIST_MAX_HASHBITS (0)
#endif

#ifndef SKEIN_512_NIST_MAX_HASHBITS
#define SKEIN_512_NIST_MAX_HASHBITS (512)
#endif

/*****************************************************************
 ** "Internal" Skein definitions
 **    -- not needed for sequential hashing API, but will be
 **           helpful for other uses of Skein (e.g., tree hash mode).
 **    -- included here so that they can be shared between
 **           reference and optimized code.
 ******************************************************************/

/* tweak word T[1]: bit field starting positions */
#define SKEIN_T1_BIT(BIT)       ((BIT) - 64)            /* offset 64 because it's the second word  */

#define SKEIN_T1_POS_TREE_LVL   SKEIN_T1_BIT(112)       /* bits 112..118: level in hash tree       */
#define SKEIN_T1_POS_BIT_PAD    SKEIN_T1_BIT(119)       /* bit  119     : partial final input byte */
#define SKEIN_T1_POS_BLK_TYPE   SKEIN_T1_BIT(120)       /* bits 120..125: type field               */
#define SKEIN_T1_POS_FIRST      SKEIN_T1_BIT(126)       /* bits 126     : first block flag         */
#define SKEIN_T1_POS_FINAL      SKEIN_T1_BIT(127)       /* bit  127     : final block flag         */

/* tweak word T[1]: flag bit definition(s) */
#define SKEIN_T1_FLAG_FIRST     (((uint64_t)  1 ) << SKEIN_T1_POS_FIRST)
#define SKEIN_T1_FLAG_FINAL     (((uint64_t)  1 ) << SKEIN_T1_POS_FINAL)
#define SKEIN_T1_FLAG_BIT_PAD   (((uint64_t)  1 ) << SKEIN_T1_POS_BIT_PAD)

/* tweak word T[1]: tree level bit field mask */
#define SKEIN_T1_TREE_LVL_MASK  (((u64b_t)0x7F) << SKEIN_T1_POS_TREE_LVL)
#define SKEIN_T1_TREE_LEVEL(n)  (((u64b_t) (n)) << SKEIN_T1_POS_TREE_LVL)

/* tweak word T[1]: block type field */
#define SKEIN_BLK_TYPE_KEY      ( 0)                    /* key, for MAC and KDF */
#define SKEIN_BLK_TYPE_CFG      ( 4)                    /* configuration block */
#define SKEIN_BLK_TYPE_PERS     ( 8)                    /* personalization string */
#define SKEIN_BLK_TYPE_PK       (12)                    /* public key (for digital signature hashing) */
#define SKEIN_BLK_TYPE_KDF      (16)                    /* key identifier for KDF */
#define SKEIN_BLK_TYPE_NONCE    (20)                    /* nonce for PRNG */
#define SKEIN_BLK_TYPE_MSG      (48)                    /* message processing */
#define SKEIN_BLK_TYPE_OUT      (63)                    /* output stage */
#define SKEIN_BLK_TYPE_MASK     (63)                    /* bit field mask */

#define SKEIN_T1_BLK_TYPE(T)   (((uint64_t) (SKEIN_BLK_TYPE_##T)) << SKEIN_T1_POS_BLK_TYPE)
#define SKEIN_T1_BLK_TYPE_KEY   SKEIN_T1_BLK_TYPE(KEY)  /* key, for MAC and KDF */
#define SKEIN_T1_BLK_TYPE_CFG   SKEIN_T1_BLK_TYPE(CFG)  /* configuration block */
#define SKEIN_T1_BLK_TYPE_PERS  SKEIN_T1_BLK_TYPE(PERS) /* personalization string */
#define SKEIN_T1_BLK_TYPE_PK    SKEIN_T1_BLK_TYPE(PK)   /* public key (for digital signature hashing) */
#define SKEIN_T1_BLK_TYPE_KDF   SKEIN_T1_BLK_TYPE(KDF)  /* key identifier for KDF */
#define SKEIN_T1_BLK_TYPE_NONCE SKEIN_T1_BLK_TYPE(NONCE)/* nonce for PRNG */
#define SKEIN_T1_BLK_TYPE_MSG   SKEIN_T1_BLK_TYPE(MSG)  /* message processing */
#define SKEIN_T1_BLK_TYPE_OUT   SKEIN_T1_BLK_TYPE(OUT)  /* output stage */
#define SKEIN_T1_BLK_TYPE_MASK  SKEIN_T1_BLK_TYPE(MASK) /* field bit mask */

#define SKEIN_T1_BLK_TYPE_CFG_FINAL       (SKEIN_T1_BLK_TYPE_CFG | SKEIN_T1_FLAG_FINAL)
#define SKEIN_T1_BLK_TYPE_OUT_FINAL       (SKEIN_T1_BLK_TYPE_OUT | SKEIN_T1_FLAG_FINAL)

#define SKEIN_VERSION           (1)

#ifndef SKEIN_ID_STRING_LE      /* allow compile-time personalization */
#define SKEIN_ID_STRING_LE      (0x33414853)            /* "SHA3" (little-endian)*/
#endif

#define SKEIN_MK_64(hi32,lo32)  ((lo32) + (((uint64_t) (hi32)) << 32))
#define SKEIN_SCHEMA_VER        SKEIN_MK_64(SKEIN_VERSION,SKEIN_ID_STRING_LE)
#define SKEIN_KS_PARITY         SKEIN_MK_64(0x1BD11BDA,0xA9FC1A22)

#define SKEIN_CFG_STR_LEN       (4*8)

/* bit field definitions in config block treeInfo word */
#define SKEIN_CFG_TREE_LEAF_SIZE_POS  ( 0)
#define SKEIN_CFG_TREE_NODE_SIZE_POS  ( 8)
#define SKEIN_CFG_TREE_MAX_LEVEL_POS  (16)

#define SKEIN_CFG_TREE_LEAF_SIZE_MSK  (((uint64_t) 0xFF) << SKEIN_CFG_TREE_LEAF_SIZE_POS)
#define SKEIN_CFG_TREE_NODE_SIZE_MSK  (((uint64_t) 0xFF) << SKEIN_CFG_TREE_NODE_SIZE_POS)
#define SKEIN_CFG_TREE_MAX_LEVEL_MSK  (((uint64_t) 0xFF) << SKEIN_CFG_TREE_MAX_LEVEL_POS)

#define SKEIN_CFG_TREE_INFO(leaf,node,maxLvl)                   \
		( (((uint64_t)(leaf  )) << SKEIN_CFG_TREE_LEAF_SIZE_POS) |    \
				(((uint64_t)(node  )) << SKEIN_CFG_TREE_NODE_SIZE_POS) |    \
				(((uint64_t)(maxLvl)) << SKEIN_CFG_TREE_MAX_LEVEL_POS) )

#define SKEIN_CFG_TREE_INFO_SEQUENTIAL SKEIN_CFG_TREE_INFO(0,0,0) /* use as treeInfo in InitExt() call for sequential processing */
#define Skein_Assert(x,retCode) assert(x)

typedef struct {
	uint32_t h[8], s[4], t[2];
	int buflen, nullt;
	uint8_t buf[64];
} blake_state;

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef struct {
	uint32_t chaining[SIZE512 / sizeof(uint32_t)];            // actual state
	uint32_t block_counter1, block_counter2;         // message block counter(s)
	BitSequence buffer[SIZE512];      						// data buffer
	int buf_ptr;              							// data buffer pointer
	int bits_in_last_byte;    // no. of message bits in last byte of data buffer
} groestl_hashState;

typedef struct {
	int hashbitlen;	   	              				//the message digest size
	unsigned long long databitlen;    				//the message size in bits
	unsigned long long datasize_in_buffer; // the size of the message remained in buffer; assumed to be multiple of 8bits except for the last partial block at the end of the message
	RDATA_ALIGN16 uint64_t x[8][2]; // the 1024-bit state, ( x[i][0] || x[i][1] ) is the ith row of the state in the pseudocode
	unsigned char buffer[64];         // the 512-bit message block to be hashed;
} jh_hashState;

typedef struct {
	size_t hashBitLen; /* size of hash result, in bits */
	size_t bCnt; /* current byte count in buffer b[] */
	uint64_t T[SKEIN_MODIFIER_WORDS]; /* tweak words: T[0]=byte cnt, T[1]=flags */
} Skein_Ctxt_Hdr_t;

typedef struct /*  256-bit Skein hash context structure */
{
	Skein_Ctxt_Hdr_t h; /* common header context variables */
	uint64_t X[SKEIN_256_STATE_WORDS]; /* chaining variables */
	unsigned char b[SKEIN_256_BLOCK_BYTES]; /* partial block buffer (8-byte aligned) */
} Skein_256_Ctxt_t;

typedef struct /*  512-bit Skein hash context structure */
{
	Skein_Ctxt_Hdr_t h; /* common header context variables */
	uint64_t X[SKEIN_512_STATE_WORDS]; /* chaining variables */
	unsigned char b[SKEIN_512_BLOCK_BYTES]; /* partial block buffer (8-byte aligned) */
} Skein_512_Ctxt_t;

typedef struct /* 1024-bit Skein hash context structure */
{
	Skein_Ctxt_Hdr_t h; /* common header context variables */
	uint64_t X[SKEIN1024_STATE_WORDS]; /* chaining variables */
	unsigned char b[SKEIN1024_BLOCK_BYTES]; /* partial block buffer (8-byte aligned) */
} Skein1024_Ctxt_t;

typedef struct {
	uint32_t statebits;                      				// 256, 512, or 1024
	union {
		Skein_Ctxt_Hdr_t h;                			// common header "overlay"
		Skein_256_Ctxt_t ctx_256;
		Skein_512_Ctxt_t ctx_512;
		Skein1024_Ctxt_t ctx1024;
	} u;
} skein_hashState;

typedef uint64_t state_t[25];

static const uint64_t keccakf_rndc[24] = { 0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001, 0x8000000080008081,
		0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 };

static const int keccakf_rotc[24] = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };

static const int keccakf_piln[24] = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

enum {
	HASH_SIZE = 32, HASH_DATA_AREA = 136
};

static const uint8_t sigma[][16] = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }, { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7,
		1, 9, 4 }, { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 }, { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }, { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }, { 12,
				5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }, { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 }, { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }, { 10, 2, 8, 4, 7, 6, 1,
						5, 15, 11, 9, 14, 3, 12, 13, 0 }, { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }, { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3,
								6, 7, 1, 9, 4 }, { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 } };

static const uint32_t cst[16] = { 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7,
		0xC97C50DD, 0x3F84D5B5, 0xB5470917 };

static const uint8_t padding[] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

const uint32_t T[512] = { 0xa5f432c6, 0xc6a597f4, 0x84976ff8, 0xf884eb97, 0x99b05eee, 0xee99c7b0, 0x8d8c7af6, 0xf68df78c, 0xd17e8ff, 0xff0de517, 0xbddc0ad6, 0xd6bdb7dc, 0xb1c816de, 0xdeb1a7c8,
		0x54fc6d91, 0x915439fc, 0x50f09060, 0x6050c0f0, 0x3050702, 0x2030405, 0xa9e02ece, 0xcea987e0, 0x7d87d156, 0x567dac87, 0x192bcce7, 0xe719d52b, 0x62a613b5, 0xb56271a6, 0xe6317c4d, 0x4de69a31,
		0x9ab559ec, 0xec9ac3b5, 0x45cf408f, 0x8f4505cf, 0x9dbca31f, 0x1f9d3ebc, 0x40c04989, 0x894009c0, 0x879268fa, 0xfa87ef92, 0x153fd0ef, 0xef15c53f, 0xeb2694b2, 0xb2eb7f26, 0xc940ce8e, 0x8ec90740,
		0xb1de6fb, 0xfb0bed1d, 0xec2f6e41, 0x41ec822f, 0x67a91ab3, 0xb3677da9, 0xfd1c435f, 0x5ffdbe1c, 0xea256045, 0x45ea8a25, 0xbfdaf923, 0x23bf46da, 0xf7025153, 0x53f7a602, 0x96a145e4, 0xe496d3a1,
		0x5bed769b, 0x9b5b2ded, 0xc25d2875, 0x75c2ea5d, 0x1c24c5e1, 0xe11cd924, 0xaee9d43d, 0x3dae7ae9, 0x6abef24c, 0x4c6a98be, 0x5aee826c, 0x6c5ad8ee, 0x41c3bd7e, 0x7e41fcc3, 0x206f3f5, 0xf502f106,
		0x4fd15283, 0x834f1dd1, 0x5ce48c68, 0x685cd0e4, 0xf4075651, 0x51f4a207, 0x345c8dd1, 0xd134b95c, 0x818e1f9, 0xf908e918, 0x93ae4ce2, 0xe293dfae, 0x73953eab, 0xab734d95, 0x53f59762, 0x6253c4f5,
		0x3f416b2a, 0x2a3f5441, 0xc141c08, 0x80c1014, 0x52f66395, 0x955231f6, 0x65afe946, 0x46658caf, 0x5ee27f9d, 0x9d5e21e2, 0x28784830, 0x30286078, 0xa1f8cf37, 0x37a16ef8, 0xf111b0a, 0xa0f1411,
		0xb5c4eb2f, 0x2fb55ec4, 0x91b150e, 0xe091c1b, 0x365a7e24, 0x2436485a, 0x9bb6ad1b, 0x1b9b36b6, 0x3d4798df, 0xdf3da547, 0x266aa7cd, 0xcd26816a, 0x69bbf54e, 0x4e699cbb, 0xcd4c337f, 0x7fcdfe4c,
		0x9fba50ea, 0xea9fcfba, 0x1b2d3f12, 0x121b242d, 0x9eb9a41d, 0x1d9e3ab9, 0x749cc458, 0x5874b09c, 0x2e724634, 0x342e6872, 0x2d774136, 0x362d6c77, 0xb2cd11dc, 0xdcb2a3cd, 0xee299db4, 0xb4ee7329,
		0xfb164d5b, 0x5bfbb616, 0xf601a5a4, 0xa4f65301, 0x4dd7a176, 0x764decd7, 0x61a314b7, 0xb76175a3, 0xce49347d, 0x7dcefa49, 0x7b8ddf52, 0x527ba48d, 0x3e429fdd, 0xdd3ea142, 0x7193cd5e, 0x5e71bc93,
		0x97a2b113, 0x139726a2, 0xf504a2a6, 0xa6f55704, 0x68b801b9, 0xb96869b8, 0x0, 0x0, 0x2c74b5c1, 0xc12c9974, 0x60a0e040, 0x406080a0, 0x1f21c2e3, 0xe31fdd21, 0xc8433a79, 0x79c8f243, 0xed2c9ab6,
		0xb6ed772c, 0xbed90dd4, 0xd4beb3d9, 0x46ca478d, 0x8d4601ca, 0xd9701767, 0x67d9ce70, 0x4bddaf72, 0x724be4dd, 0xde79ed94, 0x94de3379, 0xd467ff98, 0x98d42b67, 0xe82393b0, 0xb0e87b23, 0x4ade5b85,
		0x854a11de, 0x6bbd06bb, 0xbb6b6dbd, 0x2a7ebbc5, 0xc52a917e, 0xe5347b4f, 0x4fe59e34, 0x163ad7ed, 0xed16c13a, 0xc554d286, 0x86c51754, 0xd762f89a, 0x9ad72f62, 0x55ff9966, 0x6655ccff, 0x94a7b611,
		0x119422a7, 0xcf4ac08a, 0x8acf0f4a, 0x1030d9e9, 0xe910c930, 0x60a0e04, 0x406080a, 0x819866fe, 0xfe81e798, 0xf00baba0, 0xa0f05b0b, 0x44ccb478, 0x7844f0cc, 0xbad5f025, 0x25ba4ad5, 0xe33e754b,
		0x4be3963e, 0xf30eaca2, 0xa2f35f0e, 0xfe19445d, 0x5dfeba19, 0xc05bdb80, 0x80c01b5b, 0x8a858005, 0x58a0a85, 0xadecd33f, 0x3fad7eec, 0xbcdffe21, 0x21bc42df, 0x48d8a870, 0x7048e0d8, 0x40cfdf1,
		0xf104f90c, 0xdf7a1963, 0x63dfc67a, 0xc1582f77, 0x77c1ee58, 0x759f30af, 0xaf75459f, 0x63a5e742, 0x426384a5, 0x30507020, 0x20304050, 0x1a2ecbe5, 0xe51ad12e, 0xe12effd, 0xfd0ee112, 0x6db708bf,
		0xbf6d65b7, 0x4cd45581, 0x814c19d4, 0x143c2418, 0x1814303c, 0x355f7926, 0x26354c5f, 0x2f71b2c3, 0xc32f9d71, 0xe13886be, 0xbee16738, 0xa2fdc835, 0x35a26afd, 0xcc4fc788, 0x88cc0b4f, 0x394b652e,
		0x2e395c4b, 0x57f96a93, 0x93573df9, 0xf20d5855, 0x55f2aa0d, 0x829d61fc, 0xfc82e39d, 0x47c9b37a, 0x7a47f4c9, 0xacef27c8, 0xc8ac8bef, 0xe73288ba, 0xbae76f32, 0x2b7d4f32, 0x322b647d, 0x95a442e6,
		0xe695d7a4, 0xa0fb3bc0, 0xc0a09bfb, 0x98b3aa19, 0x199832b3, 0xd168f69e, 0x9ed12768, 0x7f8122a3, 0xa37f5d81, 0x66aaee44, 0x446688aa, 0x7e82d654, 0x547ea882, 0xabe6dd3b, 0x3bab76e6, 0x839e950b,
		0xb83169e, 0xca45c98c, 0x8cca0345, 0x297bbcc7, 0xc729957b, 0xd36e056b, 0x6bd3d66e, 0x3c446c28, 0x283c5044, 0x798b2ca7, 0xa779558b, 0xe23d81bc, 0xbce2633d, 0x1d273116, 0x161d2c27, 0x769a37ad,
		0xad76419a, 0x3b4d96db, 0xdb3bad4d, 0x56fa9e64, 0x6456c8fa, 0x4ed2a674, 0x744ee8d2, 0x1e223614, 0x141e2822, 0xdb76e492, 0x92db3f76, 0xa1e120c, 0xc0a181e, 0x6cb4fc48, 0x486c90b4, 0xe4378fb8,
		0xb8e46b37, 0x5de7789f, 0x9f5d25e7, 0x6eb20fbd, 0xbd6e61b2, 0xef2a6943, 0x43ef862a, 0xa6f135c4, 0xc4a693f1, 0xa8e3da39, 0x39a872e3, 0xa4f7c631, 0x31a462f7, 0x37598ad3, 0xd337bd59, 0x8b8674f2,
		0xf28bff86, 0x325683d5, 0xd532b156, 0x43c54e8b, 0x8b430dc5, 0x59eb856e, 0x6e59dceb, 0xb7c218da, 0xdab7afc2, 0x8c8f8e01, 0x18c028f, 0x64ac1db1, 0xb16479ac, 0xd26df19c, 0x9cd2236d, 0xe03b7249,
		0x49e0923b, 0xb4c71fd8, 0xd8b4abc7, 0xfa15b9ac, 0xacfa4315, 0x709faf3, 0xf307fd09, 0x256fa0cf, 0xcf25856f, 0xafea20ca, 0xcaaf8fea, 0x8e897df4, 0xf48ef389, 0xe9206747, 0x47e98e20, 0x18283810,
		0x10182028, 0xd5640b6f, 0x6fd5de64, 0x888373f0, 0xf088fb83, 0x6fb1fb4a, 0x4a6f94b1, 0x7296ca5c, 0x5c72b896, 0x246c5438, 0x3824706c, 0xf1085f57, 0x57f1ae08, 0xc7522173, 0x73c7e652, 0x51f36497,
		0x975135f3, 0x2365aecb, 0xcb238d65, 0x7c8425a1, 0xa17c5984, 0x9cbf57e8, 0xe89ccbbf, 0x21635d3e, 0x3e217c63, 0xdd7cea96, 0x96dd377c, 0xdc7f1e61, 0x61dcc27f, 0x86919c0d, 0xd861a91, 0x85949b0f,
		0xf851e94, 0x90ab4be0, 0xe090dbab, 0x42c6ba7c, 0x7c42f8c6, 0xc4572671, 0x71c4e257, 0xaae529cc, 0xccaa83e5, 0xd873e390, 0x90d83b73, 0x50f0906, 0x6050c0f, 0x103f4f7, 0xf701f503, 0x12362a1c,
		0x1c123836, 0xa3fe3cc2, 0xc2a39ffe, 0x5fe18b6a, 0x6a5fd4e1, 0xf910beae, 0xaef94710, 0xd06b0269, 0x69d0d26b, 0x91a8bf17, 0x17912ea8, 0x58e87199, 0x995829e8, 0x2769533a, 0x3a277469, 0xb9d0f727,
		0x27b94ed0, 0x384891d9, 0xd938a948, 0x1335deeb, 0xeb13cd35, 0xb3cee52b, 0x2bb356ce, 0x33557722, 0x22334455, 0xbbd604d2, 0xd2bbbfd6, 0x709039a9, 0xa9704990, 0x89808707, 0x7890e80, 0xa7f2c133,
		0x33a766f2, 0xb6c1ec2d, 0x2db65ac1, 0x22665a3c, 0x3c227866, 0x92adb815, 0x15922aad, 0x2060a9c9, 0xc9208960, 0x49db5c87, 0x874915db, 0xff1ab0aa, 0xaaff4f1a, 0x7888d850, 0x5078a088, 0x7a8e2ba5,
		0xa57a518e, 0x8f8a8903, 0x38f068a, 0xf8134a59, 0x59f8b213, 0x809b9209, 0x980129b, 0x1739231a, 0x1a173439, 0xda751065, 0x65daca75, 0x315384d7, 0xd731b553, 0xc651d584, 0x84c61351, 0xb8d303d0,
		0xd0b8bbd3, 0xc35edc82, 0x82c31f5e, 0xb0cbe229, 0x29b052cb, 0x7799c35a, 0x5a77b499, 0x11332d1e, 0x1e113c33, 0xcb463d7b, 0x7bcbf646, 0xfc1fb7a8, 0xa8fc4b1f, 0xd6610c6d, 0x6dd6da61, 0x3a4e622c,
		0x2c3a584e };

/*The initial hash value H(0)*/
const unsigned char JH224_H0[128] = { 0x2d, 0xfe, 0xdd, 0x62, 0xf9, 0x9a, 0x98, 0xac, 0xae, 0x7c, 0xac, 0xd6, 0x19, 0xd6, 0x34, 0xe7, 0xa4, 0x83, 0x10, 0x5, 0xbc, 0x30, 0x12, 0x16, 0xb8, 0x60, 0x38,
		0xc6, 0xc9, 0x66, 0x14, 0x94, 0x66, 0xd9, 0x89, 0x9f, 0x25, 0x80, 0x70, 0x6f, 0xce, 0x9e, 0xa3, 0x1b, 0x1d, 0x9b, 0x1a, 0xdc, 0x11, 0xe8, 0x32, 0x5f, 0x7b, 0x36, 0x6e, 0x10, 0xf9, 0x94, 0x85,
		0x7f, 0x2, 0xfa, 0x6, 0xc1, 0x1b, 0x4f, 0x1b, 0x5c, 0xd8, 0xc8, 0x40, 0xb3, 0x97, 0xf6, 0xa1, 0x7f, 0x6e, 0x73, 0x80, 0x99, 0xdc, 0xdf, 0x93, 0xa5, 0xad, 0xea, 0xa3, 0xd3, 0xa4, 0x31, 0xe8,
		0xde, 0xc9, 0x53, 0x9a, 0x68, 0x22, 0xb4, 0xa9, 0x8a, 0xec, 0x86, 0xa1, 0xe4, 0xd5, 0x74, 0xac, 0x95, 0x9c, 0xe5, 0x6c, 0xf0, 0x15, 0x96, 0xd, 0xea, 0xb5, 0xab, 0x2b, 0xbf, 0x96, 0x11, 0xdc,
		0xf0, 0xdd, 0x64, 0xea, 0x6e };
const unsigned char JH256_H0[128] = { 0xeb, 0x98, 0xa3, 0x41, 0x2c, 0x20, 0xd3, 0xeb, 0x92, 0xcd, 0xbe, 0x7b, 0x9c, 0xb2, 0x45, 0xc1, 0x1c, 0x93, 0x51, 0x91, 0x60, 0xd4, 0xc7, 0xfa, 0x26, 0x0, 0x82,
		0xd6, 0x7e, 0x50, 0x8a, 0x3, 0xa4, 0x23, 0x9e, 0x26, 0x77, 0x26, 0xb9, 0x45, 0xe0, 0xfb, 0x1a, 0x48, 0xd4, 0x1a, 0x94, 0x77, 0xcd, 0xb5, 0xab, 0x26, 0x2, 0x6b, 0x17, 0x7a, 0x56, 0xf0, 0x24,
		0x42, 0xf, 0xff, 0x2f, 0xa8, 0x71, 0xa3, 0x96, 0x89, 0x7f, 0x2e, 0x4d, 0x75, 0x1d, 0x14, 0x49, 0x8, 0xf7, 0x7d, 0xe2, 0x62, 0x27, 0x76, 0x95, 0xf7, 0x76, 0x24, 0x8f, 0x94, 0x87, 0xd5, 0xb6,
		0x57, 0x47, 0x80, 0x29, 0x6c, 0x5c, 0x5e, 0x27, 0x2d, 0xac, 0x8e, 0xd, 0x6c, 0x51, 0x84, 0x50, 0xc6, 0x57, 0x5, 0x7a, 0xf, 0x7b, 0xe4, 0xd3, 0x67, 0x70, 0x24, 0x12, 0xea, 0x89, 0xe3, 0xab,
		0x13, 0xd3, 0x1c, 0xd7, 0x69 };
const unsigned char JH384_H0[128] = { 0x48, 0x1e, 0x3b, 0xc6, 0xd8, 0x13, 0x39, 0x8a, 0x6d, 0x3b, 0x5e, 0x89, 0x4a, 0xde, 0x87, 0x9b, 0x63, 0xfa, 0xea, 0x68, 0xd4, 0x80, 0xad, 0x2e, 0x33, 0x2c, 0xcb,
		0x21, 0x48, 0xf, 0x82, 0x67, 0x98, 0xae, 0xc8, 0x4d, 0x90, 0x82, 0xb9, 0x28, 0xd4, 0x55, 0xea, 0x30, 0x41, 0x11, 0x42, 0x49, 0x36, 0xf5, 0x55, 0xb2, 0x92, 0x48, 0x47, 0xec, 0xc7, 0x25, 0xa,
		0x93, 0xba, 0xf4, 0x3c, 0xe1, 0x56, 0x9b, 0x7f, 0x8a, 0x27, 0xdb, 0x45, 0x4c, 0x9e, 0xfc, 0xbd, 0x49, 0x63, 0x97, 0xaf, 0xe, 0x58, 0x9f, 0xc2, 0x7d, 0x26, 0xaa, 0x80, 0xcd, 0x80, 0xc0, 0x8b,
		0x8c, 0x9d, 0xeb, 0x2e, 0xda, 0x8a, 0x79, 0x81, 0xe8, 0xf8, 0xd5, 0x37, 0x3a, 0xf4, 0x39, 0x67, 0xad, 0xdd, 0xd1, 0x7a, 0x71, 0xa9, 0xb4, 0xd3, 0xbd, 0xa4, 0x75, 0xd3, 0x94, 0x97, 0x6c, 0x3f,
		0xba, 0x98, 0x42, 0x73, 0x7f };
const unsigned char JH512_H0[128] = { 0x6f, 0xd1, 0x4b, 0x96, 0x3e, 0x0, 0xaa, 0x17, 0x63, 0x6a, 0x2e, 0x5, 0x7a, 0x15, 0xd5, 0x43, 0x8a, 0x22, 0x5e, 0x8d, 0xc, 0x97, 0xef, 0xb, 0xe9, 0x34, 0x12,
		0x59, 0xf2, 0xb3, 0xc3, 0x61, 0x89, 0x1d, 0xa0, 0xc1, 0x53, 0x6f, 0x80, 0x1e, 0x2a, 0xa9, 0x5, 0x6b, 0xea, 0x2b, 0x6d, 0x80, 0x58, 0x8e, 0xcc, 0xdb, 0x20, 0x75, 0xba, 0xa6, 0xa9, 0xf, 0x3a,
		0x76, 0xba, 0xf8, 0x3b, 0xf7, 0x1, 0x69, 0xe6, 0x5, 0x41, 0xe3, 0x4a, 0x69, 0x46, 0xb5, 0x8a, 0x8e, 0x2e, 0x6f, 0xe6, 0x5a, 0x10, 0x47, 0xa7, 0xd0, 0xc1, 0x84, 0x3c, 0x24, 0x3b, 0x6e, 0x71,
		0xb1, 0x2d, 0x5a, 0xc1, 0x99, 0xcf, 0x57, 0xf6, 0xec, 0x9d, 0xb1, 0xf8, 0x56, 0xa7, 0x6, 0x88, 0x7c, 0x57, 0x16, 0xb1, 0x56, 0xe3, 0xc2, 0xfc, 0xdf, 0xe6, 0x85, 0x17, 0xfb, 0x54, 0x5a, 0x46,
		0x78, 0xcc, 0x8c, 0xdd, 0x4b };

/*42 round constants, each round constant is 32-byte (256-bit)*/
const unsigned char E8_bitslice_roundconstant[42][32] =
		{ { 0x72, 0xd5, 0xde, 0xa2, 0xdf, 0x15, 0xf8, 0x67, 0x7b, 0x84, 0x15, 0xa, 0xb7, 0x23, 0x15, 0x57, 0x81, 0xab, 0xd6, 0x90, 0x4d, 0x5a, 0x87, 0xf6, 0x4e, 0x9f, 0x4f, 0xc5, 0xc3, 0xd1, 0x2b,
				0x40 }, { 0xea, 0x98, 0x3a, 0xe0, 0x5c, 0x45, 0xfa, 0x9c, 0x3, 0xc5, 0xd2, 0x99, 0x66, 0xb2, 0x99, 0x9a, 0x66, 0x2, 0x96, 0xb4, 0xf2, 0xbb, 0x53, 0x8a, 0xb5, 0x56, 0x14, 0x1a, 0x88,
				0xdb, 0xa2, 0x31 }, { 0x3, 0xa3, 0x5a, 0x5c, 0x9a, 0x19, 0xe, 0xdb, 0x40, 0x3f, 0xb2, 0xa, 0x87, 0xc1, 0x44, 0x10, 0x1c, 0x5, 0x19, 0x80, 0x84, 0x9e, 0x95, 0x1d, 0x6f, 0x33, 0xeb,
				0xad, 0x5e, 0xe7, 0xcd, 0xdc }, { 0x10, 0xba, 0x13, 0x92, 0x2, 0xbf, 0x6b, 0x41, 0xdc, 0x78, 0x65, 0x15, 0xf7, 0xbb, 0x27, 0xd0, 0xa, 0x2c, 0x81, 0x39, 0x37, 0xaa, 0x78, 0x50, 0x3f,
				0x1a, 0xbf, 0xd2, 0x41, 0x0, 0x91, 0xd3 }, { 0x42, 0x2d, 0x5a, 0xd, 0xf6, 0xcc, 0x7e, 0x90, 0xdd, 0x62, 0x9f, 0x9c, 0x92, 0xc0, 0x97, 0xce, 0x18, 0x5c, 0xa7, 0xb, 0xc7, 0x2b, 0x44,
				0xac, 0xd1, 0xdf, 0x65, 0xd6, 0x63, 0xc6, 0xfc, 0x23 }, { 0x97, 0x6e, 0x6c, 0x3, 0x9e, 0xe0, 0xb8, 0x1a, 0x21, 0x5, 0x45, 0x7e, 0x44, 0x6c, 0xec, 0xa8, 0xee, 0xf1, 0x3, 0xbb, 0x5d,
				0x8e, 0x61, 0xfa, 0xfd, 0x96, 0x97, 0xb2, 0x94, 0x83, 0x81, 0x97 }, { 0x4a, 0x8e, 0x85, 0x37, 0xdb, 0x3, 0x30, 0x2f, 0x2a, 0x67, 0x8d, 0x2d, 0xfb, 0x9f, 0x6a, 0x95, 0x8a, 0xfe, 0x73,
				0x81, 0xf8, 0xb8, 0x69, 0x6c, 0x8a, 0xc7, 0x72, 0x46, 0xc0, 0x7f, 0x42, 0x14 }, { 0xc5, 0xf4, 0x15, 0x8f, 0xbd, 0xc7, 0x5e, 0xc4, 0x75, 0x44, 0x6f, 0xa7, 0x8f, 0x11, 0xbb, 0x80, 0x52,
				0xde, 0x75, 0xb7, 0xae, 0xe4, 0x88, 0xbc, 0x82, 0xb8, 0x0, 0x1e, 0x98, 0xa6, 0xa3, 0xf4 }, { 0x8e, 0xf4, 0x8f, 0x33, 0xa9, 0xa3, 0x63, 0x15, 0xaa, 0x5f, 0x56, 0x24, 0xd5, 0xb7, 0xf9,
				0x89, 0xb6, 0xf1, 0xed, 0x20, 0x7c, 0x5a, 0xe0, 0xfd, 0x36, 0xca, 0xe9, 0x5a, 0x6, 0x42, 0x2c, 0x36 }, { 0xce, 0x29, 0x35, 0x43, 0x4e, 0xfe, 0x98, 0x3d, 0x53, 0x3a, 0xf9, 0x74, 0x73,
				0x9a, 0x4b, 0xa7, 0xd0, 0xf5, 0x1f, 0x59, 0x6f, 0x4e, 0x81, 0x86, 0xe, 0x9d, 0xad, 0x81, 0xaf, 0xd8, 0x5a, 0x9f }, { 0xa7, 0x5, 0x6, 0x67, 0xee, 0x34, 0x62, 0x6a, 0x8b, 0xb, 0x28,
				0xbe, 0x6e, 0xb9, 0x17, 0x27, 0x47, 0x74, 0x7, 0x26, 0xc6, 0x80, 0x10, 0x3f, 0xe0, 0xa0, 0x7e, 0x6f, 0xc6, 0x7e, 0x48, 0x7b }, { 0xd, 0x55, 0xa, 0xa5, 0x4a, 0xf8, 0xa4, 0xc0, 0x91,
				0xe3, 0xe7, 0x9f, 0x97, 0x8e, 0xf1, 0x9e, 0x86, 0x76, 0x72, 0x81, 0x50, 0x60, 0x8d, 0xd4, 0x7e, 0x9e, 0x5a, 0x41, 0xf3, 0xe5, 0xb0, 0x62 }, { 0xfc, 0x9f, 0x1f, 0xec, 0x40, 0x54, 0x20,
				0x7a, 0xe3, 0xe4, 0x1a, 0x0, 0xce, 0xf4, 0xc9, 0x84, 0x4f, 0xd7, 0x94, 0xf5, 0x9d, 0xfa, 0x95, 0xd8, 0x55, 0x2e, 0x7e, 0x11, 0x24, 0xc3, 0x54, 0xa5 }, { 0x5b, 0xdf, 0x72, 0x28, 0xbd,
				0xfe, 0x6e, 0x28, 0x78, 0xf5, 0x7f, 0xe2, 0xf, 0xa5, 0xc4, 0xb2, 0x5, 0x89, 0x7c, 0xef, 0xee, 0x49, 0xd3, 0x2e, 0x44, 0x7e, 0x93, 0x85, 0xeb, 0x28, 0x59, 0x7f }, { 0x70, 0x5f, 0x69,
				0x37, 0xb3, 0x24, 0x31, 0x4a, 0x5e, 0x86, 0x28, 0xf1, 0x1d, 0xd6, 0xe4, 0x65, 0xc7, 0x1b, 0x77, 0x4, 0x51, 0xb9, 0x20, 0xe7, 0x74, 0xfe, 0x43, 0xe8, 0x23, 0xd4, 0x87, 0x8a },
				{ 0x7d, 0x29, 0xe8, 0xa3, 0x92, 0x76, 0x94, 0xf2, 0xdd, 0xcb, 0x7a, 0x9, 0x9b, 0x30, 0xd9, 0xc1, 0x1d, 0x1b, 0x30, 0xfb, 0x5b, 0xdc, 0x1b, 0xe0, 0xda, 0x24, 0x49, 0x4f, 0xf2, 0x9c,
						0x82, 0xbf }, { 0xa4, 0xe7, 0xba, 0x31, 0xb4, 0x70, 0xbf, 0xff, 0xd, 0x32, 0x44, 0x5, 0xde, 0xf8, 0xbc, 0x48, 0x3b, 0xae, 0xfc, 0x32, 0x53, 0xbb, 0xd3, 0x39, 0x45, 0x9f, 0xc3,
						0xc1, 0xe0, 0x29, 0x8b, 0xa0 }, { 0xe5, 0xc9, 0x5, 0xfd, 0xf7, 0xae, 0x9, 0xf, 0x94, 0x70, 0x34, 0x12, 0x42, 0x90, 0xf1, 0x34, 0xa2, 0x71, 0xb7, 0x1, 0xe3, 0x44, 0xed, 0x95,
						0xe9, 0x3b, 0x8e, 0x36, 0x4f, 0x2f, 0x98, 0x4a }, { 0x88, 0x40, 0x1d, 0x63, 0xa0, 0x6c, 0xf6, 0x15, 0x47, 0xc1, 0x44, 0x4b, 0x87, 0x52, 0xaf, 0xff, 0x7e, 0xbb, 0x4a, 0xf1,
						0xe2, 0xa, 0xc6, 0x30, 0x46, 0x70, 0xb6, 0xc5, 0xcc, 0x6e, 0x8c, 0xe6 }, { 0xa4, 0xd5, 0xa4, 0x56, 0xbd, 0x4f, 0xca, 0x0, 0xda, 0x9d, 0x84, 0x4b, 0xc8, 0x3e, 0x18, 0xae, 0x73,
						0x57, 0xce, 0x45, 0x30, 0x64, 0xd1, 0xad, 0xe8, 0xa6, 0xce, 0x68, 0x14, 0x5c, 0x25, 0x67 }, { 0xa3, 0xda, 0x8c, 0xf2, 0xcb, 0xe, 0xe1, 0x16, 0x33, 0xe9, 0x6, 0x58, 0x9a, 0x94,
						0x99, 0x9a, 0x1f, 0x60, 0xb2, 0x20, 0xc2, 0x6f, 0x84, 0x7b, 0xd1, 0xce, 0xac, 0x7f, 0xa0, 0xd1, 0x85, 0x18 }, { 0x32, 0x59, 0x5b, 0xa1, 0x8d, 0xdd, 0x19, 0xd3, 0x50, 0x9a,
						0x1c, 0xc0, 0xaa, 0xa5, 0xb4, 0x46, 0x9f, 0x3d, 0x63, 0x67, 0xe4, 0x4, 0x6b, 0xba, 0xf6, 0xca, 0x19, 0xab, 0xb, 0x56, 0xee, 0x7e }, { 0x1f, 0xb1, 0x79, 0xea, 0xa9, 0x28, 0x21,
						0x74, 0xe9, 0xbd, 0xf7, 0x35, 0x3b, 0x36, 0x51, 0xee, 0x1d, 0x57, 0xac, 0x5a, 0x75, 0x50, 0xd3, 0x76, 0x3a, 0x46, 0xc2, 0xfe, 0xa3, 0x7d, 0x70, 0x1 }, { 0xf7, 0x35, 0xc1, 0xaf,
						0x98, 0xa4, 0xd8, 0x42, 0x78, 0xed, 0xec, 0x20, 0x9e, 0x6b, 0x67, 0x79, 0x41, 0x83, 0x63, 0x15, 0xea, 0x3a, 0xdb, 0xa8, 0xfa, 0xc3, 0x3b, 0x4d, 0x32, 0x83, 0x2c, 0x83 }, {
						0xa7, 0x40, 0x3b, 0x1f, 0x1c, 0x27, 0x47, 0xf3, 0x59, 0x40, 0xf0, 0x34, 0xb7, 0x2d, 0x76, 0x9a, 0xe7, 0x3e, 0x4e, 0x6c, 0xd2, 0x21, 0x4f, 0xfd, 0xb8, 0xfd, 0x8d, 0x39, 0xdc,
						0x57, 0x59, 0xef }, { 0x8d, 0x9b, 0xc, 0x49, 0x2b, 0x49, 0xeb, 0xda, 0x5b, 0xa2, 0xd7, 0x49, 0x68, 0xf3, 0x70, 0xd, 0x7d, 0x3b, 0xae, 0xd0, 0x7a, 0x8d, 0x55, 0x84, 0xf5, 0xa5,
						0xe9, 0xf0, 0xe4, 0xf8, 0x8e, 0x65 }, { 0xa0, 0xb8, 0xa2, 0xf4, 0x36, 0x10, 0x3b, 0x53, 0xc, 0xa8, 0x7, 0x9e, 0x75, 0x3e, 0xec, 0x5a, 0x91, 0x68, 0x94, 0x92, 0x56, 0xe8, 0x88,
						0x4f, 0x5b, 0xb0, 0x5c, 0x55, 0xf8, 0xba, 0xbc, 0x4c }, { 0xe3, 0xbb, 0x3b, 0x99, 0xf3, 0x87, 0x94, 0x7b, 0x75, 0xda, 0xf4, 0xd6, 0x72, 0x6b, 0x1c, 0x5d, 0x64, 0xae, 0xac,
						0x28, 0xdc, 0x34, 0xb3, 0x6d, 0x6c, 0x34, 0xa5, 0x50, 0xb8, 0x28, 0xdb, 0x71 }, { 0xf8, 0x61, 0xe2, 0xf2, 0x10, 0x8d, 0x51, 0x2a, 0xe3, 0xdb, 0x64, 0x33, 0x59, 0xdd, 0x75,
						0xfc, 0x1c, 0xac, 0xbc, 0xf1, 0x43, 0xce, 0x3f, 0xa2, 0x67, 0xbb, 0xd1, 0x3c, 0x2, 0xe8, 0x43, 0xb0 }, { 0x33, 0xa, 0x5b, 0xca, 0x88, 0x29, 0xa1, 0x75, 0x7f, 0x34, 0x19, 0x4d,
						0xb4, 0x16, 0x53, 0x5c, 0x92, 0x3b, 0x94, 0xc3, 0xe, 0x79, 0x4d, 0x1e, 0x79, 0x74, 0x75, 0xd7, 0xb6, 0xee, 0xaf, 0x3f }, { 0xea, 0xa8, 0xd4, 0xf7, 0xbe, 0x1a, 0x39, 0x21, 0x5c,
						0xf4, 0x7e, 0x9, 0x4c, 0x23, 0x27, 0x51, 0x26, 0xa3, 0x24, 0x53, 0xba, 0x32, 0x3c, 0xd2, 0x44, 0xa3, 0x17, 0x4a, 0x6d, 0xa6, 0xd5, 0xad }, { 0xb5, 0x1d, 0x3e, 0xa6, 0xaf, 0xf2,
						0xc9, 0x8, 0x83, 0x59, 0x3d, 0x98, 0x91, 0x6b, 0x3c, 0x56, 0x4c, 0xf8, 0x7c, 0xa1, 0x72, 0x86, 0x60, 0x4d, 0x46, 0xe2, 0x3e, 0xcc, 0x8, 0x6e, 0xc7, 0xf6 }, { 0x2f, 0x98, 0x33,
						0xb3, 0xb1, 0xbc, 0x76, 0x5e, 0x2b, 0xd6, 0x66, 0xa5, 0xef, 0xc4, 0xe6, 0x2a, 0x6, 0xf4, 0xb6, 0xe8, 0xbe, 0xc1, 0xd4, 0x36, 0x74, 0xee, 0x82, 0x15, 0xbc, 0xef, 0x21, 0x63 }, {
						0xfd, 0xc1, 0x4e, 0xd, 0xf4, 0x53, 0xc9, 0x69, 0xa7, 0x7d, 0x5a, 0xc4, 0x6, 0x58, 0x58, 0x26, 0x7e, 0xc1, 0x14, 0x16, 0x6, 0xe0, 0xfa, 0x16, 0x7e, 0x90, 0xaf, 0x3d, 0x28, 0x63,
						0x9d, 0x3f }, { 0xd2, 0xc9, 0xf2, 0xe3, 0x0, 0x9b, 0xd2, 0xc, 0x5f, 0xaa, 0xce, 0x30, 0xb7, 0xd4, 0xc, 0x30, 0x74, 0x2a, 0x51, 0x16, 0xf2, 0xe0, 0x32, 0x98, 0xd, 0xeb, 0x30,
						0xd8, 0xe3, 0xce, 0xf8, 0x9a }, { 0x4b, 0xc5, 0x9e, 0x7b, 0xb5, 0xf1, 0x79, 0x92, 0xff, 0x51, 0xe6, 0x6e, 0x4, 0x86, 0x68, 0xd3, 0x9b, 0x23, 0x4d, 0x57, 0xe6, 0x96, 0x67, 0x31,
						0xcc, 0xe6, 0xa6, 0xf3, 0x17, 0xa, 0x75, 0x5 }, { 0xb1, 0x76, 0x81, 0xd9, 0x13, 0x32, 0x6c, 0xce, 0x3c, 0x17, 0x52, 0x84, 0xf8, 0x5, 0xa2, 0x62, 0xf4, 0x2b, 0xcb, 0xb3, 0x78,
						0x47, 0x15, 0x47, 0xff, 0x46, 0x54, 0x82, 0x23, 0x93, 0x6a, 0x48 }, { 0x38, 0xdf, 0x58, 0x7, 0x4e, 0x5e, 0x65, 0x65, 0xf2, 0xfc, 0x7c, 0x89, 0xfc, 0x86, 0x50, 0x8e, 0x31, 0x70,
						0x2e, 0x44, 0xd0, 0xb, 0xca, 0x86, 0xf0, 0x40, 0x9, 0xa2, 0x30, 0x78, 0x47, 0x4e }, { 0x65, 0xa0, 0xee, 0x39, 0xd1, 0xf7, 0x38, 0x83, 0xf7, 0x5e, 0xe9, 0x37, 0xe4, 0x2c, 0x3a,
						0xbd, 0x21, 0x97, 0xb2, 0x26, 0x1, 0x13, 0xf8, 0x6f, 0xa3, 0x44, 0xed, 0xd1, 0xef, 0x9f, 0xde, 0xe7 }, { 0x8b, 0xa0, 0xdf, 0x15, 0x76, 0x25, 0x92, 0xd9, 0x3c, 0x85, 0xf7, 0xf6,
						0x12, 0xdc, 0x42, 0xbe, 0xd8, 0xa7, 0xec, 0x7c, 0xab, 0x27, 0xb0, 0x7e, 0x53, 0x8d, 0x7d, 0xda, 0xaa, 0x3e, 0xa8, 0xde }, { 0xaa, 0x25, 0xce, 0x93, 0xbd, 0x2, 0x69, 0xd8, 0x5a,
						0xf6, 0x43, 0xfd, 0x1a, 0x73, 0x8, 0xf9, 0xc0, 0x5f, 0xef, 0xda, 0x17, 0x4a, 0x19, 0xa5, 0x97, 0x4d, 0x66, 0x33, 0x4c, 0xfd, 0x21, 0x6a }, { 0x35, 0xb4, 0x98, 0x31, 0xdb, 0x41,
																																																																																				0x15, 0x70, 0xea, 0x1e, 0xf, 0xbb, 0xed, 0xcd, 0x54, 0x9b, 0x9a, 0xd0, 0x63, 0xa1, 0x51, 0x97, 0x40, 0x72, 0xf6, 0x75, 0x9d, 0xbf, 0x91, 0x47, 0x6f, 0xe2 } };

/*
 ***************** Pre-computed Skein IVs *******************
 **
 ** NOTE: these values are not "magic" constants, but
 ** are generated using the Threefish block function.
 ** They are pre-computed here only for speed; i.e., to
 ** avoid the need for a Threefish call during Init().
 **
 ** The IV for any fixed hash length may be pre-computed.
 ** Only the most common values are included here.
 **
 ************************************************************
 **/

#define MK_64 SKEIN_MK_64

/* blkSize =  512 bits. hashSize =  224 bits */
static const uint64_t SKEIN_512_IV_224[] = {
		MK_64(0xCCD06162,0x48677224),
		MK_64(0xCBA65CF3,0xA92339EF),
		MK_64(0x8CCD69D6,0x52FF4B64),
		MK_64(0x398AED7B,0x3AB890B4),
		MK_64(0x0F59D1B1,0x457D2BD0),
		MK_64(0x6776FE65,0x75D4EB3D),
		MK_64(0x99FBC70E,0x997413E9),
		MK_64(0x9E2CFCCF,0xE1C41EF7) };

/* blkSize =  512 bits. hashSize =  256 bits */
static const uint64_t SKEIN_512_IV_256[] = {
		MK_64(0xCCD044A1,0x2FDB3E13),
		MK_64(0xE8359030,0x1A79A9EB),
		MK_64(0x55AEA061,0x4F816E6F),
		MK_64(0x2A2767A4,0xAE9B94DB),
		MK_64(0xEC06025E,0x74DD7683),
		MK_64(0xE7A436CD,0xC4746251),
		MK_64(0xC36FBAF9,0x393AD185),
		MK_64(0x3EEDBA18,0x33EDFC13) };

/* blkSize =  512 bits. hashSize =  384 bits */
static const uint64_t SKEIN_512_IV_384[] = {
		MK_64(0xA3F6C6BF,0x3A75EF5F),
		MK_64(0xB0FEF9CC,0xFD84FAA4),
		MK_64(0x9D77DD66,0x3D770CFE),
		MK_64(0xD798CBF3,0xB468FDDA),
		MK_64(0x1BC4A666,0x8A0E4465),
		MK_64(0x7ED7D434,0xE5807407),
		MK_64(0x548FC1AC,0xD4EC44D6),
		MK_64(0x266E1754,0x6AA18FF8) };

/* blkSize =  512 bits. hashSize =  512 bits */
static const uint64_t SKEIN_512_IV_512[] = {
		MK_64(0x4903ADFF,0x749C51CE),
		MK_64(0x0D95DE39,0x9746DF03),
		MK_64(0x8FD19341,0x27C79BCE),
		MK_64(0x9A255629,0xFF352CB1),
		MK_64(0x5DB62599,0xDF6CA7B0),
		MK_64(0xEABE394C,0xA9D5C3F4),
		MK_64(0x991112C7,0x1A75B523),
		MK_64(0xAE18A40B,0x660FCC33) };

/* blkSize = 1024 bits. hashSize =  384 bits */
static const uint64_t SKEIN1024_IV_384[] = {
		MK_64(0x5102B6B8,0xC1894A35),
		MK_64(0xFEEBC9E3,0xFE8AF11A),
		MK_64(0x0C807F06,0xE32BED71),
		MK_64(0x60C13A52,0xB41A91F6),
		MK_64(0x9716D35D,0xD4917C38),
		MK_64(0xE780DF12,0x6FD31D3A),
		MK_64(0x797846B6,0xC898303A),
		MK_64(0xB172C2A8,0xB3572A3B),
		MK_64(0xC9BC8203,0xA6104A6C),
		MK_64(0x65909338,0xD75624F4),
		MK_64(0x94BCC568,0x4B3F81A0),
		MK_64(0x3EBBF51E,0x10ECFD46),
		MK_64(0x2DF50F0B,0xEEB08542),
		MK_64(0x3B5A6530,0x0DBC6516),
		MK_64(0x484B9CD2,0x167BBCE1),
		MK_64(0x2D136947,0xD4CBAFEA) };

/* blkSize = 1024 bits. hashSize =  512 bits */
static const uint64_t SKEIN1024_IV_512[] = {
		MK_64(0xCAEC0E5D,0x7C1B1B18),
		MK_64(0xA01B0E04,0x5F03E802),
		MK_64(0x33840451,0xED912885),
		MK_64(0x374AFB04,0xEAEC2E1C),
		MK_64(0xDF25A0E2,0x813581F7),
		MK_64(0xE4004093,0x8B12F9D2),
		MK_64(0xA662D539,0xC2ED39B6),
		MK_64(0xFA8B85CF,0x45D8C75A),
		MK_64(0x8316ED8E,0x29EDE796),
		MK_64(0x053289C0,0x2E9F91B8),
		MK_64(0xC3F8EF1D,0x6D518B73),
		MK_64(0xBDCEC3C4,0xD5EF332E),
		MK_64(0x549A7E52,0x22974487),
		MK_64(0x67070872,0x5B749816),
		MK_64(0xB9CD28FB,0xF0581BD1),
		MK_64(0x0E2940B8,0x15804974) };

/* blkSize = 1024 bits. hashSize = 1024 bits */
static const uint64_t SKEIN1024_IV_1024[] = {
		MK_64(0xD593DA07,0x41E72355),
		MK_64(0x15B5E511,0xAC73E00C),
		MK_64(0x5180E5AE,0xBAF2C4F0),
		MK_64(0x03BD41D3,0xFCBCAFAF),
		MK_64(0x1CAEC6FD,0x1983A898),
		MK_64(0x6E510B8B,0xCDD0589F),
		MK_64(0x77E2BDFD,0xC6394ADA),
		MK_64(0xC11E1DB5,0x24DCB0A3),
		MK_64(0xD6D14AF9,0xC6329AB5),
		MK_64(0x6A9B0BFC,0x6EB67E0D),
		MK_64(0x9243C60D,0xCCFF1332),
		MK_64(0x1A1F1DDE,0x743F02D4),
		MK_64(0x0996753C,0x10ED0BB8),
		MK_64(0x6572DD22,0xF2B4969A),
		MK_64(0x61FD3062,0xD00A579A),
		MK_64(0x1DE0536E,0x8682E539) };

#if defined(__MINGW32__)
BOOL SetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable)
{
	struct
	{
		DWORD count;
		LUID_AND_ATTRIBUTES privilege[1];
	} info;

	HANDLE token;
	if(!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &token))
		return FALSE;

	info.count = 1;
	info.privilege[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if(!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(info.privilege[0].Luid)))
		return FALSE;

	if(!AdjustTokenPrivileges(token, FALSE, (PTOKEN_PRIVILEGES) &info, 0, NULL, NULL))
		return FALSE;

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	CloseHandle(token);

	return TRUE;

}
#endif

/**
 * @brief allocate the 2MB scratch buffer using OS support for huge pages, if available
 *
 * This function tries to allocate the 2MB scratch buffer using a single
 * 2MB "huge page" (instead of the usual 4KB page sizes) to reduce TLB misses
 * during the random accesses to the scratch buffer.  This is one of the
 * important speed optimizations needed to make CryptoNight faster.
 *
 * No parameters.  Updates a thread-local pointer, hp_state, to point to
 * the allocated buffer.
 */

static void slow_hash_allocate_state(CPUMiner &cpuMiner) {
	if (cpuMiner.hp_state != NULL)
		return;

	cpuMiner.hp_state = (uint8_t *) malloc(MEMORY/(cpuMiner.memFactor));
}

void destroyCPUScratchPad(CPUMiner &cpuMiner) {
	if (cpuMiner.hp_state == nullptr)
		return;

	free(cpuMiner.hp_state);
	cpuMiner.hp_state = nullptr;
}

// update the state with given number of rounds
static void keccakf(uint64_t st[25], int rounds) {
	int i, j, round;
	uint64_t t, bc[5];

	for (round = 0; round < rounds; round++) {

		// Theta
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		// Rho Pi
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		//  Chi
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		//  Iota
		st[0] ^= keccakf_rndc[round];
	}
}

// compute a keccak hash (md) of given byte length from "in"
static void keccak(const uint8_t *in, size_t inlen, uint8_t *md, int mdlen) {
	state_t st;
	uint8_t temp[144];
	size_t i, rsiz, rsizw;

	static_assert(HASH_DATA_AREA <= sizeof(temp), "Bad keccak preconditions");
	if (mdlen <= 0 || (mdlen > 100 && sizeof(st) != (size_t) mdlen)) {
		exitOnError("Bad keccak use");
	}

	rsiz = sizeof(state_t) == mdlen ? HASH_DATA_AREA : 200 - 2 * mdlen;
	rsizw = rsiz / 8;

	memset(st, 0, sizeof(st));

	for (; inlen >= rsiz; inlen -= rsiz, in += rsiz) {
		for (i = 0; i < rsizw; i++)
			st[i] ^= ((uint64_t *) in)[i];
		keccakf(st, KECCAK_ROUNDS);
	}

	// last block and padding
	if (inlen + 1 >= sizeof(temp) || inlen > rsiz || rsiz - inlen + inlen + 1 >= sizeof(temp) || rsiz == 0 || rsiz - 1 >= sizeof(temp) || rsizw * 8 > sizeof(temp)) {
		exitOnError("Bad keccak use");
	}

	memcpy(temp, in, inlen);
	temp[inlen++] = 1;
	memset(temp + inlen, 0, rsiz - inlen);
	temp[rsiz - 1] |= 0x80;

	for (i = 0; i < rsizw; i++)
		st[i] ^= ((uint64_t *) temp)[i];

	keccakf(st, KECCAK_ROUNDS);

	memcpy(md, st, mdlen);
}

void hash_permutation(union hash_state *state) {
	keccakf((uint64_t*) state, 24);
}

static void keccak1600(const uint8_t *in, size_t inlen, uint8_t *md) {
	keccak(in, inlen, md, sizeof(state_t));
}

static void hash_process(union hash_state *state, const uint8_t *buf, size_t count) {
	keccak1600(buf, count, (uint8_t*) state);
}

static void aes_256_assist1(__m128i* t1, __m128i * t2)
{
	__m128i t4;
	*t2 = _mm_shuffle_epi32(*t2, 0xff);
	t4 = _mm_slli_si128(*t1, 0x04);
	*t1 = _mm_xor_si128(*t1, t4);
	t4 = _mm_slli_si128(t4, 0x04);
	*t1 = _mm_xor_si128(*t1, t4);
	t4 = _mm_slli_si128(t4, 0x04);
	*t1 = _mm_xor_si128(*t1, t4);
	*t1 = _mm_xor_si128(*t1, *t2);
}

static void aes_256_assist2(__m128i* t1, __m128i * t3)
{
	__m128i t2, t4;
	t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
	t2 = _mm_shuffle_epi32(t4, 0xaa);
	t4 = _mm_slli_si128(*t3, 0x04);
	*t3 = _mm_xor_si128(*t3, t4);
	t4 = _mm_slli_si128(t4, 0x04);
	*t3 = _mm_xor_si128(*t3, t4);
	t4 = _mm_slli_si128(t4, 0x04);
	*t3 = _mm_xor_si128(*t3, t4);
	*t3 = _mm_xor_si128(*t3, t2);
}

/**
 * @brief expands 'key' into a form it can be used for AES encryption.
 *
 * This is an SSE-optimized implementation of AES key schedule generation.  It
 * expands the key into multiple round keys, each of which is used in one round
 * of the AES encryption used to fill (and later, extract randomness from)
 * the large 2MB buffer.  Note that CryptoNight does not use a completely
 * standard AES encryption for its buffer expansion, so do not copy this
 * function outside of Monero without caution!  This version uses the hardware
 * AESKEYGENASSIST instruction to speed key generation, and thus requires
 * CPU AES support.
 * For more information about these functions, see page 19 of Intel's AES instructions
 * white paper:
 * http://www.intel.com/content/dam/www/public/us/en/documents/white-papers/aes-instructions-set-white-paper.pdf
 *
 * @param key the input 128 bit key
 * @param expandedKey An output buffer to hold the generated key schedule
 */

static void aes_expand_key(const uint8_t *key, uint8_t *expandedKey) {
	__m128i *ek = R128(expandedKey);
	__m128i t1, t2, t3;

	t1 = _mm_loadu_si128(R128(key));
	t3 = _mm_loadu_si128(R128(key + 16));

	ek[0] = t1;
	ek[1] = t3;

	t2 = _mm_aeskeygenassist_si128(t3, 0x01);
	aes_256_assist1(&t1, &t2);
	ek[2] = t1;
	aes_256_assist2(&t1, &t3);
	ek[3] = t3;

	t2 = _mm_aeskeygenassist_si128(t3, 0x02);
	aes_256_assist1(&t1, &t2);
	ek[4] = t1;
	aes_256_assist2(&t1, &t3);
	ek[5] = t3;

	t2 = _mm_aeskeygenassist_si128(t3, 0x04);
	aes_256_assist1(&t1, &t2);
	ek[6] = t1;
	aes_256_assist2(&t1, &t3);
	ek[7] = t3;

	t2 = _mm_aeskeygenassist_si128(t3, 0x08);
	aes_256_assist1(&t1, &t2);
	ek[8] = t1;
	aes_256_assist2(&t1, &t3);
	ek[9] = t3;

	t2 = _mm_aeskeygenassist_si128(t3, 0x10);
	aes_256_assist1(&t1, &t2);
	ek[10] = t1;
}

/**
 * @brief a "pseudo" round of AES (similar to but slightly different from normal AES encryption)
 *
 * To fill its 2MB scratch buffer, CryptoNight uses a nonstandard implementation
 * of AES encryption:  It applies 10 rounds of the basic AES encryption operation
 * to an input 128 bit chunk of data <in>.  Unlike normal AES, however, this is
 * all it does;  it does not perform the initial AddRoundKey step (this is done
 * in subsequent steps by aesenc_si128), and it does not use the simpler final round.
 * Hence, this is a "pseudo" round - though the function actually implements 10 rounds together.
 *
 * Note that unlike aesb_pseudo_round, this function works on multiple data chunks.
 *
 * @param in a pointer to nblocks * 128 bits of data to be encrypted
 * @param out a pointer to an nblocks * 128 bit buffer where the output will be stored
 * @param expandedKey the expanded AES key
 * @param nblocks the number of 128 blocks of data to be encrypted
 */

static void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks) {
	__m128i *k = R128(expandedKey);
	__m128i d;
	int i;

	for (i = 0; i < nblocks; i++) {
		d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
		d = _mm_aesenc_si128(d, *R128(&k[0]));
		d = _mm_aesenc_si128(d, *R128(&k[1]));
		d = _mm_aesenc_si128(d, *R128(&k[2]));
		d = _mm_aesenc_si128(d, *R128(&k[3]));
		d = _mm_aesenc_si128(d, *R128(&k[4]));
		d = _mm_aesenc_si128(d, *R128(&k[5]));
		d = _mm_aesenc_si128(d, *R128(&k[6]));
		d = _mm_aesenc_si128(d, *R128(&k[7]));
		d = _mm_aesenc_si128(d, *R128(&k[8]));
		d = _mm_aesenc_si128(d, *R128(&k[9]));
		_mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
	}
}

/**
 * @brief aes_pseudo_round that loads data from *in and xors it with *xor first
 *
 * This function performs the same operations as aes_pseudo_round, but before
 * performing the encryption of each 128 bit block from <in>, it xors
 * it with the corresponding block from <xor>.
 *
 * @param in a pointer to nblocks * 128 bits of data to be encrypted
 * @param out a pointer to an nblocks * 128 bit buffer where the output will be stored
 * @param expandedKey the expanded AES key
 * @param xor a pointer to an nblocks * 128 bit buffer that is xored into in before encryption (in is left unmodified)
 * @param nblocks the number of 128 blocks of data to be encrypted
 */

static void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *_xor, int nblocks) {
	__m128i *k = R128(expandedKey);
	__m128i *x = R128(_xor);
	__m128i d;

	for (int i = 0; i < nblocks; i++) {
		d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
		d = _mm_xor_si128(d, *R128(x++));
		d = _mm_aesenc_si128(d, *R128(&k[0]));
		d = _mm_aesenc_si128(d, *R128(&k[1]));
		d = _mm_aesenc_si128(d, *R128(&k[2]));
		d = _mm_aesenc_si128(d, *R128(&k[3]));
		d = _mm_aesenc_si128(d, *R128(&k[4]));
		d = _mm_aesenc_si128(d, *R128(&k[5]));
		d = _mm_aesenc_si128(d, *R128(&k[6]));
		d = _mm_aesenc_si128(d, *R128(&k[7]));
		d = _mm_aesenc_si128(d, *R128(&k[8]));
		d = _mm_aesenc_si128(d, *R128(&k[9]));
		_mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
	}
}

void blake256_init(blake_state *S) {
	S->h[0] = 0x6A09E667;
	S->h[1] = 0xBB67AE85;
	S->h[2] = 0x3C6EF372;
	S->h[3] = 0xA54FF53A;
	S->h[4] = 0x510E527F;
	S->h[5] = 0x9B05688C;
	S->h[6] = 0x1F83D9AB;
	S->h[7] = 0x5BE0CD19;
	S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
	S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}

void blake256_compress(blake_state *S, const uint8_t *block) {
	uint32_t v[16], m[16], i;

#define ROT(x,n) (((x)<<(32-n))|((x)>>(n)))
#define G(a,b,c,d,e)                                      \
		v[a] += (m[sigma[i][e]] ^ cst[sigma[i][e+1]]) + v[b]; \
		v[d] = ROT(v[d] ^ v[a],16);                           \
		v[c] += v[d];                                         \
		v[b] = ROT(v[b] ^ v[c],12);                           \
		v[a] += (m[sigma[i][e+1]] ^ cst[sigma[i][e]])+v[b];   \
		v[d] = ROT(v[d] ^ v[a], 8);                           \
		v[c] += v[d];                                         \
		v[b] = ROT(v[b] ^ v[c], 7);

	for (i = 0; i < 16; ++i)
		m[i] = U8TO32(block + i * 4);
	for (i = 0; i < 8; ++i)
		v[i] = S->h[i];
	v[8] = S->s[0] ^ 0x243F6A88;
	v[9] = S->s[1] ^ 0x85A308D3;
	v[10] = S->s[2] ^ 0x13198A2E;
	v[11] = S->s[3] ^ 0x03707344;
	v[12] = 0xA4093822;
	v[13] = 0x299F31D0;
	v[14] = 0x082EFA98;
	v[15] = 0xEC4E6C89;

	if (S->nullt == 0) {
		v[12] ^= S->t[0];
		v[13] ^= S->t[0];
		v[14] ^= S->t[1];
		v[15] ^= S->t[1];
	}

	for (i = 0; i < 14; ++i) {
		G(0, 4, 8, 12, 0);
		G(1, 5, 9, 13, 2);
		G(2, 6, 10, 14, 4);
		G(3, 7, 11, 15, 6);
		G(3, 4, 9, 14, 14);
		G(2, 7, 8, 13, 12);
		G(0, 5, 10, 15, 8);
		G(1, 6, 11, 12, 10);
	}

	for (i = 0; i < 16; ++i)
		S->h[i % 8] ^= v[i];
	for (i = 0; i < 8; ++i)
		S->h[i] ^= S->s[i % 4];
}

// datalen = number of bits
static void blake256_update(blake_state *S, const uint8_t *data, uint64_t datalen) {
	int left = S->buflen >> 3;
	int fill = 64 - left;

	if (left && (((datalen >> 3)) >= (unsigned) fill)) {
		memcpy((void *) (S->buf + left), (void *) data, fill);
		S->t[0] += 512;
		if (S->t[0] == 0)
			S->t[1]++;
		blake256_compress(S, S->buf);
		data += fill;
		datalen -= (fill << 3);
		left = 0;
	}

	while (datalen >= 512) {
		S->t[0] += 512;
		if (S->t[0] == 0)
			S->t[1]++;
		blake256_compress(S, data);
		data += 64;
		datalen -= 512;
	}

	if (datalen > 0) {
		memcpy((void *) (S->buf + left), (void *) data, datalen >> 3);
		S->buflen = (left << 3) + datalen;
	} else {
		S->buflen = 0;
	}
}

static void blake256_final_h(blake_state *S, uint8_t *digest, uint8_t pa, uint8_t pb) {
	uint8_t msglen[8];
	uint32_t lo = S->t[0] + S->buflen, hi = S->t[1];
	if (lo < (unsigned) S->buflen)
		hi++;
	U32TO8(msglen + 0, hi);
	U32TO8(msglen + 4, lo);

	if (S->buflen == 440) { /* one padding byte */
		S->t[0] -= 8;
		blake256_update(S, &pa, 8);
	} else {
		if (S->buflen < 440) { /* enough space to fill the block  */
			if (S->buflen == 0)
				S->nullt = 1;
			S->t[0] -= 440 - S->buflen;
			blake256_update(S, padding, 440 - S->buflen);
		} else { /* need 2 compressions */
			S->t[0] -= 512 - S->buflen;
			blake256_update(S, padding, 512 - S->buflen);
			S->t[0] -= 440;
			blake256_update(S, padding + 1, 440);
			S->nullt = 1;
		}
		blake256_update(S, &pb, 8);
		S->t[0] -= 8;
	}
	S->t[0] -= 64;
	blake256_update(S, msglen, 64);

	U32TO8(digest + 0, S->h[0]);
	U32TO8(digest + 4, S->h[1]);
	U32TO8(digest + 8, S->h[2]);
	U32TO8(digest + 12, S->h[3]);
	U32TO8(digest + 16, S->h[4]);
	U32TO8(digest + 20, S->h[5]);
	U32TO8(digest + 24, S->h[6]);
	U32TO8(digest + 28, S->h[7]);
}

static void blake256_final(blake_state *S, uint8_t *digest) {
	blake256_final_h(S, digest, 0x81, 0x01);
}

// inlen = number of bytes
static void blake256_hash(uint8_t *out, const uint8_t *in, uint64_t inlen) {
	blake_state S;
	blake256_init(&S);
	blake256_update(&S, in, inlen * 8);
	blake256_final(&S, out);
}

static void hash_extra_blake(const void *data, size_t length, char *hash) {
	blake256_hash((uint8_t*) hash, (const uint8_t *) data, length);
}

// initialise context
static void Init(groestl_hashState* ctx) {
	// allocate memory for state and data buffer

	for (size_t i = 0; i < (SIZE512 / sizeof(uint32_t)); i++) {
		ctx->chaining[i] = 0;
	}

	// set initial value
	ctx->chaining[2 * COLS512 - 1] = u32BIG((uint32_t)HASH_BIT_LEN);

	// set other variables
	ctx->buf_ptr = 0;
	ctx->block_counter1 = 0;
	ctx->block_counter2 = 0;
	ctx->bits_in_last_byte = 0;
}

#define ROTATE_COLUMN_DOWN(v1, v2, amount_bytes, temp_var) {temp_var = (v1<<(8*amount_bytes))|(v2>>(8*(4-amount_bytes))); \
		v2 = (v2<<(8*amount_bytes))|(v1>>(8*(4-amount_bytes))); \
		v1 = temp_var;}

#define COLUMN(x,y,i,c0,c1,c2,c3,c4,c5,c6,c7,tv1,tv2,tu,tl,t)				\
		tu = T[2*(uint32_t)x[4*c0+0]];			    \
		tl = T[2*(uint32_t)x[4*c0+0]+1];		    \
		tv1 = T[2*(uint32_t)x[4*c1+1]];			\
		tv2 = T[2*(uint32_t)x[4*c1+1]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,1,t)	\
		tu ^= tv1;						\
		tl ^= tv2;						\
		tv1 = T[2*(uint32_t)x[4*c2+2]];			\
		tv2 = T[2*(uint32_t)x[4*c2+2]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,2,t)	\
		tu ^= tv1;						\
		tl ^= tv2;   					\
		tv1 = T[2*(uint32_t)x[4*c3+3]];			\
		tv2 = T[2*(uint32_t)x[4*c3+3]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,3,t)	\
		tu ^= tv1;						\
		tl ^= tv2;						\
		tl ^= T[2*(uint32_t)x[4*c4+0]];			\
		tu ^= T[2*(uint32_t)x[4*c4+0]+1];			\
		tv1 = T[2*(uint32_t)x[4*c5+1]];			\
		tv2 = T[2*(uint32_t)x[4*c5+1]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,1,t)	\
		tl ^= tv1;						\
		tu ^= tv2;						\
		tv1 = T[2*(uint32_t)x[4*c6+2]];			\
		tv2 = T[2*(uint32_t)x[4*c6+2]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,2,t)	\
		tl ^= tv1;						\
		tu ^= tv2;   					\
		tv1 = T[2*(uint32_t)x[4*c7+3]];			\
		tv2 = T[2*(uint32_t)x[4*c7+3]+1];			\
		ROTATE_COLUMN_DOWN(tv1,tv2,3,t)	\
		tl ^= tv1;						\
		tu ^= tv2;						\
		y[i] = tu;						\
		y[i+1] = tl;

/* compute one round of P (short variants) */
static void RND512P(uint8_t *x, uint32_t *y, uint32_t r) {
	uint32_t temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp;
	uint32_t* x32 = (uint32_t*) x;
	x32[0] ^= 0x00000000 ^ r;
	x32[2] ^= 0x00000010 ^ r;
	x32[4] ^= 0x00000020 ^ r;
	x32[6] ^= 0x00000030 ^ r;
	x32[8] ^= 0x00000040 ^ r;
	x32[10] ^= 0x00000050 ^ r;
	x32[12] ^= 0x00000060 ^ r;
	x32[14] ^= 0x00000070 ^ r;
	COLUMN(x, y, 0, 0, 2, 4, 6, 9, 11, 13, 15, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 2, 2, 4, 6, 8, 11, 13, 15, 1, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 4, 4, 6, 8, 10, 13, 15, 1, 3, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 6, 6, 8, 10, 12, 15, 1, 3, 5, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 8, 8, 10, 12, 14, 1, 3, 5, 7, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 10, 10, 12, 14, 0, 3, 5, 7, 9, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 12, 12, 14, 0, 2, 5, 7, 9, 11, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 14, 14, 0, 2, 4, 7, 9, 11, 13, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
}

// compute one round of Q (short variants)
static void RND512Q(uint8_t *x, uint32_t *y, uint32_t r) {
	uint32_t temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp;
	uint32_t* x32 = (uint32_t*) x;
	x32[0] = ~x32[0];
	x32[1] ^= 0xffffffff ^ r;
	x32[2] = ~x32[2];
	x32[3] ^= 0xefffffff ^ r;
	x32[4] = ~x32[4];
	x32[5] ^= 0xdfffffff ^ r;
	x32[6] = ~x32[6];
	x32[7] ^= 0xcfffffff ^ r;
	x32[8] = ~x32[8];
	x32[9] ^= 0xbfffffff ^ r;
	x32[10] = ~x32[10];
	x32[11] ^= 0xafffffff ^ r;
	x32[12] = ~x32[12];
	x32[13] ^= 0x9fffffff ^ r;
	x32[14] = ~x32[14];
	x32[15] ^= 0x8fffffff ^ r;
	COLUMN(x, y, 0, 2, 6, 10, 14, 1, 5, 9, 13, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 2, 4, 8, 12, 0, 3, 7, 11, 15, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 4, 6, 10, 14, 2, 5, 9, 13, 1, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 6, 8, 12, 0, 4, 7, 11, 15, 3, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 8, 10, 14, 2, 6, 9, 13, 1, 5, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 10, 12, 0, 4, 8, 11, 15, 3, 7, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 12, 14, 2, 6, 10, 13, 1, 5, 9, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
	COLUMN(x, y, 14, 0, 4, 8, 12, 15, 3, 7, 11, temp_v1, temp_v2, temp_upper_value, temp_lower_value, temp);
}
// compute compression function (short variants)
static void F512(uint32_t *h, const uint32_t *m) {
	int i;
	uint32_t Ptmp[2 * COLS512];
	uint32_t Qtmp[2 * COLS512];
	uint32_t y[2 * COLS512];
	uint32_t z[2 * COLS512];

	for (i = 0; i < 2 * COLS512; i++) {
		z[i] = m[i];
		Ptmp[i] = h[i] ^ m[i];
	}

	/* compute Q(m) */
	RND512Q((uint8_t*) z, y, 0x00000000);
	RND512Q((uint8_t*) y, z, 0x01000000);
	RND512Q((uint8_t*) z, y, 0x02000000);
	RND512Q((uint8_t*) y, z, 0x03000000);
	RND512Q((uint8_t*) z, y, 0x04000000);
	RND512Q((uint8_t*) y, z, 0x05000000);
	RND512Q((uint8_t*) z, y, 0x06000000);
	RND512Q((uint8_t*) y, z, 0x07000000);
	RND512Q((uint8_t*) z, y, 0x08000000);
	RND512Q((uint8_t*) y, Qtmp, 0x09000000);

	/* compute P(h+m) */
	RND512P((uint8_t*) Ptmp, y, 0x00000000);
	RND512P((uint8_t*) y, z, 0x00000001);
	RND512P((uint8_t*) z, y, 0x00000002);
	RND512P((uint8_t*) y, z, 0x00000003);
	RND512P((uint8_t*) z, y, 0x00000004);
	RND512P((uint8_t*) y, z, 0x00000005);
	RND512P((uint8_t*) z, y, 0x00000006);
	RND512P((uint8_t*) y, z, 0x00000007);
	RND512P((uint8_t*) z, y, 0x00000008);
	RND512P((uint8_t*) y, Ptmp, 0x00000009);

	/* compute P(h+m) + Q(m) + h */
	for (i = 0; i < 2 * COLS512; i++) {
		h[i] ^= Ptmp[i] ^ Qtmp[i];
	}
}
// digest up to msglen bytes of input (full blocks only)
static void Transform(groestl_hashState *ctx, const uint8_t *input, int msglen) {

	/* digest message, one block at a time */
	for (; msglen >= SIZE512; msglen -= SIZE512, input += SIZE512) {
		F512(ctx->chaining, (uint32_t*) input);

		/* increment block counter */
		ctx->block_counter1++;
		if (ctx->block_counter1 == 0)
			ctx->block_counter2++;
	}
}

// update state with databitlen bits of input
static void Update(groestl_hashState* ctx, const BitSequence* input, DataLength databitlen) {
	int index = 0;
	int msglen = (int) (databitlen / 8);
	int rem = (int) (databitlen % 8);

	/* if the buffer contains data that has not yet been digested, first
	 add data to buffer until full */
	if (ctx->buf_ptr) {
		while (ctx->buf_ptr < SIZE512 && index < msglen) {
			ctx->buffer[(int) ctx->buf_ptr++] = input[index++];
		}
		if (ctx->buf_ptr < SIZE512) {
			/* buffer still not full, return */
			if (rem) {
				ctx->bits_in_last_byte = rem;
				ctx->buffer[(int) ctx->buf_ptr++] = input[index];
			}
			return;
		}

		/* digest buffer */
		ctx->buf_ptr = 0;
		Transform(ctx, ctx->buffer, SIZE512);
	}

	// digest bulk of message
	Transform(ctx, input + index, msglen - index);
	index += ((msglen - index) / SIZE512) * SIZE512;

	// store remaining data in buffer
	while (index < msglen) {
		ctx->buffer[(int) ctx->buf_ptr++] = input[index++];
	}

	/* if non-integral number of bytes have been supplied, store
	 remaining bits in last byte, together with information about
	 number of bits */
	if (rem) {
		ctx->bits_in_last_byte = rem;
		ctx->buffer[(int) ctx->buf_ptr++] = input[index];
	}
}

/* given state h, do h <- P(h)+h */
static void OutputTransformation(groestl_hashState *ctx) {
	int j;
	uint32_t temp[2 * COLS512];
	uint32_t y[2 * COLS512];
	uint32_t z[2 * COLS512];

	for (j = 0; j < 2 * COLS512; j++) {
		temp[j] = ctx->chaining[j];
	}
	RND512P((uint8_t*) temp, y, 0x00000000);
	RND512P((uint8_t*) y, z, 0x00000001);
	RND512P((uint8_t*) z, y, 0x00000002);
	RND512P((uint8_t*) y, z, 0x00000003);
	RND512P((uint8_t*) z, y, 0x00000004);
	RND512P((uint8_t*) y, z, 0x00000005);
	RND512P((uint8_t*) z, y, 0x00000006);
	RND512P((uint8_t*) y, z, 0x00000007);
	RND512P((uint8_t*) z, y, 0x00000008);
	RND512P((uint8_t*) y, temp, 0x00000009);
	for (j = 0; j < 2 * COLS512; j++) {
		ctx->chaining[j] ^= temp[j];
	}
}

#define BILB ctx->bits_in_last_byte

/* finalise: process remaining data (including padding), perform
 output transformation, and write hash result to 'output' */
static void Final(groestl_hashState* ctx, BitSequence* output) {
	int i, j = 0, hashbytelen = HASH_BIT_LEN / 8;
	uint8_t *s = (BitSequence*) ctx->chaining;

	/* pad with '1'-bit and first few '0'-bits */
	if (BILB) {
		ctx->buffer[(int) ctx->buf_ptr - 1] &= ((1 << BILB) - 1) << (8 - BILB);
		ctx->buffer[(int) ctx->buf_ptr - 1] ^= 0x1 << (7 - BILB);
		BILB = 0;
	} else
		ctx->buffer[(int) ctx->buf_ptr++] = 0x80;

	/* pad with '0'-bits */
	if (ctx->buf_ptr > SIZE512 - LENGTHFIELDLEN) {
		/* padding requires two blocks */
		while (ctx->buf_ptr < SIZE512) {
			ctx->buffer[(int) ctx->buf_ptr++] = 0;
		}
		/* digest first padding block */
		Transform(ctx, ctx->buffer, SIZE512);
		ctx->buf_ptr = 0;
	}
	while (ctx->buf_ptr < SIZE512 - LENGTHFIELDLEN) {
		ctx->buffer[(int) ctx->buf_ptr++] = 0;
	}

	/* length padding */
	ctx->block_counter1++;
	if (ctx->block_counter1 == 0)
		ctx->block_counter2++;
	ctx->buf_ptr = SIZE512;

	while (ctx->buf_ptr > SIZE512 - (int) sizeof(uint32_t)) {
		ctx->buffer[(int) --ctx->buf_ptr] = (uint8_t) ctx->block_counter1;
		ctx->block_counter1 >>= 8;
	}
	while (ctx->buf_ptr > SIZE512 - LENGTHFIELDLEN) {
		ctx->buffer[(int) --ctx->buf_ptr] = (uint8_t) ctx->block_counter2;
		ctx->block_counter2 >>= 8;
	}
	/* digest final padding block */
	Transform(ctx, ctx->buffer, SIZE512);
	/* perform output transformation */
	OutputTransformation(ctx);

	/* store hash result in output */
	for (i = SIZE512 - hashbytelen; i < SIZE512; i++, j++) {
		output[j] = s[i];
	}

	/* zeroise relevant variables and deallocate memory */
	for (i = 0; i < COLS512; i++) {
		ctx->chaining[i] = 0;
	}
	for (i = 0; i < SIZE512; i++) {
		ctx->buffer[i] = 0;
	}
}

// hash bit sequence
void groestl(const BitSequence* data, DataLength databitlen, BitSequence* hashval) {
	groestl_hashState context;

	/* initialise */
	Init(&context);

	/* process message */
	Update(&context, data, databitlen);

	/* finalise */
	Final(&context, hashval);
}

void hash_extra_groestl(const void *data, size_t length, char *hash) {
	groestl((const BitSequence*) data, length * 8, (uint8_t*) hash);
}

/*swapping bit 2i with bit 2i+1 of 64-bit x*/
#define SWAP1(x)   (x) = ((((x) & 0x5555555555555555ULL) << 1) | (((x) & 0xaaaaaaaaaaaaaaaaULL) >> 1));
/*swapping bits 4i||4i+1 with bits 4i+2||4i+3 of 64-bit x*/
#define SWAP2(x)   (x) = ((((x) & 0x3333333333333333ULL) << 2) | (((x) & 0xccccccccccccccccULL) >> 2));
/*swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of 64-bit x*/
#define SWAP4(x)   (x) = ((((x) & 0x0f0f0f0f0f0f0f0fULL) << 4) | (((x) & 0xf0f0f0f0f0f0f0f0ULL) >> 4));
/*swapping bits 16i||16i+1||......||16i+7  with bits 16i+8||16i+9||......||16i+15 of 64-bit x*/
#define SWAP8(x)   (x) = ((((x) & 0x00ff00ff00ff00ffULL) << 8) | (((x) & 0xff00ff00ff00ff00ULL) >> 8));
/*swapping bits 32i||32i+1||......||32i+15 with bits 32i+16||32i+17||......||32i+31 of 64-bit x*/
#define SWAP16(x)  (x) = ((((x) & 0x0000ffff0000ffffULL) << 16) | (((x) & 0xffff0000ffff0000ULL) >> 16));
/*swapping bits 64i||64i+1||......||64i+31 with bits 64i+32||64i+33||......||64i+63 of 64-bit x*/
#define SWAP32(x)  (x) = (((x) << 32) | ((x) >> 32));

/*The MDS transform*/
#define L(m0,m1,m2,m3,m4,m5,m6,m7) \
		(m4) ^= (m1);                \
		(m5) ^= (m2);                \
		(m6) ^= (m0) ^ (m3);         \
		(m7) ^= (m0);                \
		(m0) ^= (m5);                \
		(m1) ^= (m6);                \
		(m2) ^= (m4) ^ (m7);         \
		(m3) ^= (m4);

/*Two Sboxes are computed in parallel, each Sbox implements S0 and S1, selected by a constant bit*/
/*The reason to compute two Sboxes in parallel is to try to fully utilize the parallel processing power*/
#define SS(m0,m1,m2,m3,m4,m5,m6,m7,cc0,cc1)   \
		m3  = ~(m3);                  \
		m7  = ~(m7);                  \
		m0 ^= ((~(m2)) & (cc0));      \
		m4 ^= ((~(m6)) & (cc1));      \
		temp0 = (cc0) ^ ((m0) & (m1));\
		temp1 = (cc1) ^ ((m4) & (m5));\
		m0 ^= ((m2) & (m3));          \
		m4 ^= ((m6) & (m7));          \
		m3 ^= ((~(m1)) & (m2));       \
		m7 ^= ((~(m5)) & (m6));       \
		m1 ^= ((m0) & (m2));          \
		m5 ^= ((m4) & (m6));          \
		m2 ^= ((m0) & (~(m3)));       \
		m6 ^= ((m4) & (~(m7)));       \
		m0 ^= ((m1) | (m3));          \
		m4 ^= ((m5) | (m7));          \
		m3 ^= ((m1) & (m2));          \
		m7 ^= ((m5) & (m6));          \
		m1 ^= (temp0 & (m0));         \
		m5 ^= (temp1 & (m4));         \
		m2 ^= temp0;                  \
		m6 ^= temp1;

/*The bijective function E8, in bitslice form*/
static void E8(jh_hashState *state) {
	uint64_t i, roundnumber, temp0, temp1;

	for (roundnumber = 0; roundnumber < 42; roundnumber = roundnumber + 7) {
		/*round 7*roundnumber+0: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 0])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 0])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP1(state->x[1][i]);
			SWAP1(state->x[3][i]);
			SWAP1(state->x[5][i]);
			SWAP1(state->x[7][i]);
		}

		/*round 7*roundnumber+1: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 1])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 1])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP2(state->x[1][i]);
			SWAP2(state->x[3][i]);
			SWAP2(state->x[5][i]);
			SWAP2(state->x[7][i]);
		}

		/*round 7*roundnumber+2: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 2])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 2])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP4(state->x[1][i]);
			SWAP4(state->x[3][i]);
			SWAP4(state->x[5][i]);
			SWAP4(state->x[7][i]);
		}

		/*round 7*roundnumber+3: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 3])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 3])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP8(state->x[1][i]);
			SWAP8(state->x[3][i]);
			SWAP8(state->x[5][i]);
			SWAP8(state->x[7][i]);
		}

		/*round 7*roundnumber+4: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 4])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 4])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP16(state->x[1][i]);
			SWAP16(state->x[3][i]);
			SWAP16(state->x[5][i]);
			SWAP16(state->x[7][i]);
		}

		/*round 7*roundnumber+5: Sbox, MDS and Swapping layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 5])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 5])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
			SWAP32(state->x[1][i]);
			SWAP32(state->x[3][i]);
			SWAP32(state->x[5][i]);
			SWAP32(state->x[7][i]);
		}

		/*round 7*roundnumber+6: Sbox and MDS layers*/
		for (i = 0; i < 2; i++) {
			SS(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i],
					((uint64_t* )E8_bitslice_roundconstant[roundnumber + 6])[i], ((uint64_t* )E8_bitslice_roundconstant[roundnumber + 6])[i + 2]);
			L(state->x[0][i], state->x[2][i], state->x[4][i], state->x[6][i], state->x[1][i], state->x[3][i], state->x[5][i], state->x[7][i]);
		}
		/*round 7*roundnumber+6: swapping layer*/
		for (i = 1; i < 8; i = i + 2) {
			temp0 = state->x[i][0];
			state->x[i][0] = state->x[i][1];
			state->x[i][1] = temp0;
		}
	}

}

/*The compression function F8 */
static void F8(jh_hashState *state) {
	uint64_t i;

	/*xor the 512-bit message with the fist half of the 1024-bit hash state*/
	for (i = 0; i < 8; i++)
		state->x[i >> 1][i & 1] ^= ((uint64_t*) state->buffer)[i];

	/*the bijective function E8 */
	E8(state);

	/*xor the 512-bit message with the second half of the 1024-bit hash state*/
	for (i = 0; i < 8; i++)
		state->x[(8 + i) >> 1][(8 + i) & 1] ^= ((uint64_t*) state->buffer)[i];
}

/*before hashing a message, initialize the hash state as H0 */
static bool Init(jh_hashState *state, int hashbitlen) {
	state->databitlen = 0;
	state->datasize_in_buffer = 0;

	/*initialize the initial hash value of JH*/
	state->hashbitlen = hashbitlen;

	/*load the intital hash value into state*/
	switch (hashbitlen) {
	case 224:
		memcpy(state->x, JH224_H0, 128);
		break;
	case 256:
		memcpy(state->x, JH256_H0, 128);
		break;
	case 384:
		memcpy(state->x, JH384_H0, 128);
		break;
	case 512:
		memcpy(state->x, JH512_H0, 128);
		break;
	}

	return true;
}

/*hash each 512-bit message block, except the last partial block*/
static bool Update(jh_hashState *state, const BitSequence *data, DataLength databitlen) {
	DataLength index; /*the starting address of the data to be compressed*/

	state->databitlen += databitlen;
	index = 0;

	/*if there is remaining data in the buffer, fill it to a full message block first*/
	/*we assume that the size of the data in the buffer is the multiple of 8 bits if it is not at the end of a message*/

	/*There is data in the buffer, but the incoming data is insufficient for a full block*/
	if ((state->datasize_in_buffer > 0) && ((state->datasize_in_buffer + databitlen) < 512)) {
		if ((databitlen & 7) == 0) {
			memcpy(state->buffer + (state->datasize_in_buffer >> 3), data, 64 - (state->datasize_in_buffer >> 3));
		} else
			memcpy(state->buffer + (state->datasize_in_buffer >> 3), data, 64 - (state->datasize_in_buffer >> 3) + 1);
		state->datasize_in_buffer += databitlen;
		databitlen = 0;
	}

	/*There is data in the buffer, and the incoming data is sufficient for a full block*/
	if ((state->datasize_in_buffer > 0) && ((state->datasize_in_buffer + databitlen) >= 512)) {
		memcpy(state->buffer + (state->datasize_in_buffer >> 3), data, 64 - (state->datasize_in_buffer >> 3));
		index = 64 - (state->datasize_in_buffer >> 3);
		databitlen = databitlen - (512 - state->datasize_in_buffer);
		F8(state);
		state->datasize_in_buffer = 0;
	}

	/*hash the remaining full message blocks*/
	for (; databitlen >= 512; index = index + 64, databitlen = databitlen - 512) {
		memcpy(state->buffer, data + index, 64);
		F8(state);
	}

	/*store the partial block into buffer, assume that -- if part of the last byte is not part of the message, then that part consists of 0 bits*/
	if (databitlen > 0) {
		if ((databitlen & 7) == 0)
			memcpy(state->buffer, data + index, (databitlen & 0x1ff) >> 3);
		else
			memcpy(state->buffer, data + index, ((databitlen & 0x1ff) >> 3) + 1);
		state->datasize_in_buffer = databitlen;
	}

	return true;
}

/*pad the message, process the padded block(s), truncate the hash value H to obtain the message digest*/
static bool Final(jh_hashState *state, BitSequence *hashval) {
	unsigned int i;

	if ((state->databitlen & 0x1ff) == 0) {
		/*pad the message when databitlen is multiple of 512 bits, then process the padded block*/
		memset(state->buffer, 0, 64);
		state->buffer[0] = 0x80;
		state->buffer[63] = state->databitlen & 0xff;
		state->buffer[62] = (state->databitlen >> 8) & 0xff;
		state->buffer[61] = (state->databitlen >> 16) & 0xff;
		state->buffer[60] = (state->databitlen >> 24) & 0xff;
		state->buffer[59] = (state->databitlen >> 32) & 0xff;
		state->buffer[58] = (state->databitlen >> 40) & 0xff;
		state->buffer[57] = (state->databitlen >> 48) & 0xff;
		state->buffer[56] = (state->databitlen >> 56) & 0xff;
		F8(state);
	} else {
		/*set the rest of the bytes in the buffer to 0*/
		if ((state->datasize_in_buffer & 7) == 0)
			for (i = (state->databitlen & 0x1ff) >> 3; i < 64; i++)
				state->buffer[i] = 0;
		else
			for (i = ((state->databitlen & 0x1ff) >> 3) + 1; i < 64; i++)
				state->buffer[i] = 0;

		/*pad and process the partial block when databitlen is not multiple of 512 bits, then hash the padded blocks*/
		state->buffer[((state->databitlen & 0x1ff) >> 3)] |= 1 << (7 - (state->databitlen & 7));

		F8(state);
		memset(state->buffer, 0, 64);
		state->buffer[63] = state->databitlen & 0xff;
		state->buffer[62] = (state->databitlen >> 8) & 0xff;
		state->buffer[61] = (state->databitlen >> 16) & 0xff;
		state->buffer[60] = (state->databitlen >> 24) & 0xff;
		state->buffer[59] = (state->databitlen >> 32) & 0xff;
		state->buffer[58] = (state->databitlen >> 40) & 0xff;
		state->buffer[57] = (state->databitlen >> 48) & 0xff;
		state->buffer[56] = (state->databitlen >> 56) & 0xff;
		F8(state);
	}

	/*truncating the final hash value to generate the message digest*/
	switch (state->hashbitlen) {
	case 224:
		memcpy(hashval, (unsigned char*) state->x + 64 + 36, 28);
		break;
	case 256:
		memcpy(hashval, (unsigned char*) state->x + 64 + 32, 32);
		break;
	case 384:
		memcpy(hashval, (unsigned char*) state->x + 64 + 16, 48);
		break;
	case 512:
		memcpy(hashval, (unsigned char*) state->x + 64, 64);
		break;
	}

	return true;
}

/* hash a message,
 three inputs: message digest size in bits (hashbitlen); message (data); message length in bits (databitlen)
 one output:   message digest (hashval)
 */
static bool jh_hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) {
	jh_hashState state;

	if (hashbitlen == 224 || hashbitlen == 256 || hashbitlen == 384 || hashbitlen == 512) {
		Init(&state, hashbitlen);
		Update(&state, data, databitlen);
		Final(&state, hashval);
		return true;
	} else
		return false;
}

void hash_extra_jh(const void *data, size_t length, char *hash) {
	bool r = jh_hash(HASH_SIZE * 8, (const BitSequence *) data, 8 * length, (uint8_t*) hash);
	assert(r);
}

/*****************************************************************/
/*     512-bit Skein                                             */
/*****************************************************************/
/*
 **   Skein macros for getting/setting tweak words, etc.
 **   These are useful for partial input bytes, hash tree init/update, etc.
 **/
#define Skein_Get_Tweak(ctxPtr,TWK_NUM)         ((ctxPtr)->h.T[TWK_NUM])
#define Skein_Set_Tweak(ctxPtr,TWK_NUM,tVal)    {(ctxPtr)->h.T[TWK_NUM] = (tVal);}

#define Skein_Get_T0(ctxPtr)    Skein_Get_Tweak(ctxPtr,0)
#define Skein_Get_T1(ctxPtr)    Skein_Get_Tweak(ctxPtr,1)
#define Skein_Set_T0(ctxPtr,T0) Skein_Set_Tweak(ctxPtr,0,T0)
#define Skein_Set_T1(ctxPtr,T1) Skein_Set_Tweak(ctxPtr,1,T1)

/* set both tweak words at once */
#define Skein_Set_T0_T1(ctxPtr,T0,T1)           \
		{                                           \
	Skein_Set_T0(ctxPtr,(T0));                  \
	Skein_Set_T1(ctxPtr,(T1));                  \
		}

/* set up for starting with a new type: h.T[0]=0; h.T[1] = NEW_TYPE; h.bCnt=0; */
#define Skein_Start_New_Type(ctxPtr,BLK_TYPE)   \
		{ Skein_Set_T0_T1(ctxPtr,0,SKEIN_T1_FLAG_FIRST | SKEIN_T1_BLK_TYPE_##BLK_TYPE); (ctxPtr)->h.bCnt=0; }

#define Skein_Swap64(w64)  (w64)		// litle endian
#ifndef SKEIN_USE_ASM
#define SKEIN_USE_ASM   (0)                     /* default is all C code (no ASM) */
#endif

#ifndef SKEIN_LOOP
#define SKEIN_LOOP 001                          /* default: unroll 256 and 512, but not 1024 */
#endif

#define BLK_BITS        (WCNT*64)               /* some useful definitions for code here */
#define KW_TWK_BASE     (0)
#define KW_KEY_BASE     (3)
#define ks              (kw + KW_KEY_BASE)
#define ts              (kw + KW_TWK_BASE)
#ifdef SKEIN_DEBUG
#define DebugSaveTweak(ctx) { ctx->h.T[0] = ts[0]; ctx->h.T[1] = ts[1]; }
#else
#define DebugSaveTweak(ctx)
#endif
#define Skein_Show_Block(bits,ctx,X,blkPtr,wPtr,ksEvenPtr,ksOddPtr)
#define Skein_Show_Round(bits,ctx,r,X)
#define Skein_Show_R_Ptr(bits,ctx,r,X_ptr)
#define Skein_Show_Final(bits,ctx,cnt,outPtr)
#define Skein_Show_Key(bits,ctx,key,keyBytes)
#define RotL_64(x,N)    (((x) << (N)) | ((x) >> (64-(N))))
#ifndef SKEIN_ROUNDS
#define SKEIN_256_ROUNDS_TOTAL (72)          /* number of rounds for the different block sizes */
#define SKEIN_512_ROUNDS_TOTAL (72)
#define SKEIN1024_ROUNDS_TOTAL (80)
#else                                        /* allow command-line define in range 8*(5..14)   */
#define SKEIN_256_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS/100) + 5) % 10) + 5))
#define SKEIN_512_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS/ 10) + 5) % 10) + 5))
#define SKEIN1024_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS    ) + 5) % 10) + 5))
#endif
#define Skein_Put64_LSB_First(dst08,src64,bCnt) memcpy(dst08,src64,bCnt)
#define Skein_Get64_LSB_First(dst64,src08,wCnt) memcpy(dst64,src08,8*(wCnt))

/*****************************************************************
 ** Skein block function constants (shared across Ref and Opt code)
 ******************************************************************/
enum {
	/* Skein_256 round rotation constants */
	R_256_0_0 = 14,
	R_256_0_1 = 16,
	R_256_1_0 = 52,
	R_256_1_1 = 57,
	R_256_2_0 = 23,
	R_256_2_1 = 40,
	R_256_3_0 = 5,
	R_256_3_1 = 37,
	R_256_4_0 = 25,
	R_256_4_1 = 33,
	R_256_5_0 = 46,
	R_256_5_1 = 12,
	R_256_6_0 = 58,
	R_256_6_1 = 22,
	R_256_7_0 = 32,
	R_256_7_1 = 32,

	/* Skein_512 round rotation constants */
	R_512_0_0 = 46,
	R_512_0_1 = 36,
	R_512_0_2 = 19,
	R_512_0_3 = 37,
	R_512_1_0 = 33,
	R_512_1_1 = 27,
	R_512_1_2 = 14,
	R_512_1_3 = 42,
	R_512_2_0 = 17,
	R_512_2_1 = 49,
	R_512_2_2 = 36,
	R_512_2_3 = 39,
	R_512_3_0 = 44,
	R_512_3_1 = 9,
	R_512_3_2 = 54,
	R_512_3_3 = 56,
	R_512_4_0 = 39,
	R_512_4_1 = 30,
	R_512_4_2 = 34,
	R_512_4_3 = 24,
	R_512_5_0 = 13,
	R_512_5_1 = 50,
	R_512_5_2 = 10,
	R_512_5_3 = 17,
	R_512_6_0 = 25,
	R_512_6_1 = 29,
	R_512_6_2 = 39,
	R_512_6_3 = 43,
	R_512_7_0 = 8,
	R_512_7_1 = 35,
	R_512_7_2 = 56,
	R_512_7_3 = 22,

	/* Skein1024 round rotation constants */
	R1024_0_0 = 24,
	R1024_0_1 = 13,
	R1024_0_2 = 8,
	R1024_0_3 = 47,
	R1024_0_4 = 8,
	R1024_0_5 = 17,
	R1024_0_6 = 22,
	R1024_0_7 = 37,
	R1024_1_0 = 38,
	R1024_1_1 = 19,
	R1024_1_2 = 10,
	R1024_1_3 = 55,
	R1024_1_4 = 49,
	R1024_1_5 = 18,
	R1024_1_6 = 23,
	R1024_1_7 = 52,
	R1024_2_0 = 33,
	R1024_2_1 = 4,
	R1024_2_2 = 51,
	R1024_2_3 = 13,
	R1024_2_4 = 34,
	R1024_2_5 = 41,
	R1024_2_6 = 59,
	R1024_2_7 = 17,
	R1024_3_0 = 5,
	R1024_3_1 = 20,
	R1024_3_2 = 48,
	R1024_3_3 = 41,
	R1024_3_4 = 47,
	R1024_3_5 = 28,
	R1024_3_6 = 16,
	R1024_3_7 = 25,
	R1024_4_0 = 41,
	R1024_4_1 = 9,
	R1024_4_2 = 37,
	R1024_4_3 = 31,
	R1024_4_4 = 12,
	R1024_4_5 = 47,
	R1024_4_6 = 44,
	R1024_4_7 = 30,
	R1024_5_0 = 16,
	R1024_5_1 = 34,
	R1024_5_2 = 56,
	R1024_5_3 = 51,
	R1024_5_4 = 4,
	R1024_5_5 = 53,
	R1024_5_6 = 42,
	R1024_5_7 = 41,
	R1024_6_0 = 31,
	R1024_6_1 = 44,
	R1024_6_2 = 47,
	R1024_6_3 = 46,
	R1024_6_4 = 19,
	R1024_6_5 = 42,
	R1024_6_6 = 44,
	R1024_6_7 = 25,
	R1024_7_0 = 9,
	R1024_7_1 = 48,
	R1024_7_2 = 35,
	R1024_7_3 = 52,
	R1024_7_4 = 23,
	R1024_7_5 = 31,
	R1024_7_6 = 37,
	R1024_7_7 = 20
};

static void Skein_512_Process_Block(Skein_512_Ctxt_t *ctx, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd) { /* do it in C */
	enum {
		WCNT = SKEIN_512_STATE_WORDS
	};
#undef  RCNT
#define RCNT  (SKEIN_512_ROUNDS_TOTAL/8)

#ifdef  SKEIN_LOOP                              /* configure how much to unroll the loop */
#define SKEIN_UNROLL_512 (((SKEIN_LOOP)/10)%10)
#else
#define SKEIN_UNROLL_512 (0)
#endif

#if SKEIN_UNROLL_512
#if (RCNT % SKEIN_UNROLL_512)
#error "Invalid SKEIN_UNROLL_512"               /* sanity check on unroll count */
#endif
	size_t r;
	u64b_t kw[WCNT+4+RCNT*2]; /* key schedule words : chaining vars + tweak + "rotation"*/
#else
	uint64_t kw[WCNT + 4]; /* key schedule words : chaining vars + tweak */
#endif
	uint64_t X0, X1, X2, X3, X4, X5, X6, X7; /* local copy of vars, for speed */
	uint64_t w[WCNT]; /* local copy of input block */
#ifdef SKEIN_DEBUG
	const u64b_t *Xptr[8]; /* use for debugging (help compiler put Xn in registers) */
	Xptr[0] = &X0; Xptr[1] = &X1; Xptr[2] = &X2; Xptr[3] = &X3;
	Xptr[4] = &X4; Xptr[5] = &X5; Xptr[6] = &X6; Xptr[7] = &X7;
#endif

	assert(blkCnt != 0); /* never call with blkCnt == 0! */
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	do {
		/* this implementation only supports 2**64 input bytes (no carry out here) */
		ts[0] += byteCntAdd; /* update processed length */

		/* precompute the key schedule for this block */
		ks[0] = ctx->X[0];
		ks[1] = ctx->X[1];
		ks[2] = ctx->X[2];
		ks[3] = ctx->X[3];
		ks[4] = ctx->X[4];
		ks[5] = ctx->X[5];
		ks[6] = ctx->X[6];
		ks[7] = ctx->X[7];
		ks[8] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^
				ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ SKEIN_KS_PARITY;

		ts[2] = ts[0] ^ ts[1];

		Skein_Get64_LSB_First(w, blkPtr, WCNT); /* get input block in little-endian format */
		DebugSaveTweak(ctx);Skein_Show_Block(BLK_BITS,&ctx->h,ctx->X,blkPtr,w,ks,ts);

		X0 = w[0] + ks[0]; /* do the first full key injection */
		X1 = w[1] + ks[1];
		X2 = w[2] + ks[2];
		X3 = w[3] + ks[3];
		X4 = w[4] + ks[4];
		X5 = w[5] + ks[5] + ts[0];
		X6 = w[6] + ks[6] + ts[1];
		X7 = w[7] + ks[7];

		blkPtr += SKEIN_512_BLOCK_BYTES;

		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INITIAL,Xptr);
		/* run the rounds */
#define Round512(p0,p1,p2,p3,p4,p5,p6,p7,ROT,rNum)                  \
		X##p0 += X##p1; X##p1 = RotL_64(X##p1,ROT##_0); X##p1 ^= X##p0; \
		X##p2 += X##p3; X##p3 = RotL_64(X##p3,ROT##_1); X##p3 ^= X##p2; \
		X##p4 += X##p5; X##p5 = RotL_64(X##p5,ROT##_2); X##p5 ^= X##p4; \
		X##p6 += X##p7; X##p7 = RotL_64(X##p7,ROT##_3); X##p7 ^= X##p6; \

#if SKEIN_UNROLL_512 == 0
#define R512(p0,p1,p2,p3,p4,p5,p6,p7,ROT,rNum)      /* unrolled */  \
Round512(p0,p1,p2,p3,p4,p5,p6,p7,ROT,rNum)                      \
Skein_Show_R_Ptr(BLK_BITS,&ctx->h,rNum,Xptr);

#define I512(R)                                                     \
		X0   += ks[((R)+1) % 9];   /* inject the key schedule value */  \
		X1   += ks[((R)+2) % 9];                                        \
		X2   += ks[((R)+3) % 9];                                        \
		X3   += ks[((R)+4) % 9];                                        \
		X4   += ks[((R)+5) % 9];                                        \
		X5   += ks[((R)+6) % 9] + ts[((R)+1) % 3];                      \
		X6   += ks[((R)+7) % 9] + ts[((R)+2) % 3];                      \
		X7   += ks[((R)+8) % 9] +     (R)+1;                            \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);
#else                                       /* looping version */
#define R512(p0,p1,p2,p3,p4,p5,p6,p7,ROT,rNum)                      \
		Round512(p0,p1,p2,p3,p4,p5,p6,p7,ROT,rNum)                      \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,4*(r-1)+rNum,Xptr);

#define I512(R)                                                     \
		X0   += ks[r+(R)+0];        /* inject the key schedule value */ \
		X1   += ks[r+(R)+1];                                            \
		X2   += ks[r+(R)+2];                                            \
		X3   += ks[r+(R)+3];                                            \
		X4   += ks[r+(R)+4];                                            \
		X5   += ks[r+(R)+5] + ts[r+(R)+0];                              \
		X6   += ks[r+(R)+6] + ts[r+(R)+1];                              \
		X7   += ks[r+(R)+7] +    r+(R)   ;                              \
		ks[r +       (R)+8] = ks[r+(R)-1];  /* rotate key schedule */   \
		ts[r +       (R)+2] = ts[r+(R)-1];                              \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);

		for (r=1;r < 2*RCNT;r+=2*SKEIN_UNROLL_512) /* loop thru it */
#endif                         /* end of looped code definitions */
		{
#define R512_8_rounds(R)  /* do 8 full rounds */  \
R512(0,1,2,3,4,5,6,7,R_512_0,8*(R)+ 1);   \
R512(2,1,4,7,6,5,0,3,R_512_1,8*(R)+ 2);   \
R512(4,1,6,3,0,5,2,7,R_512_2,8*(R)+ 3);   \
R512(6,1,0,7,2,5,4,3,R_512_3,8*(R)+ 4);   \
I512(2*(R));                              \
R512(0,1,2,3,4,5,6,7,R_512_4,8*(R)+ 5);   \
R512(2,1,4,7,6,5,0,3,R_512_5,8*(R)+ 6);   \
R512(4,1,6,3,0,5,2,7,R_512_6,8*(R)+ 7);   \
R512(6,1,0,7,2,5,4,3,R_512_7,8*(R)+ 8);   \
I512(2*(R)+1);        /* and key injection */

R512_8_rounds(0);

#define R512_Unroll_R(NN) ((SKEIN_UNROLL_512 == 0 && SKEIN_512_ROUNDS_TOTAL/8 > (NN)) || (SKEIN_UNROLL_512 > (NN)))

#if   R512_Unroll_R( 1)
R512_8_rounds(1);
#endif
#if   R512_Unroll_R( 2)
R512_8_rounds(2);
#endif
#if   R512_Unroll_R( 3)
R512_8_rounds(3);
#endif
#if   R512_Unroll_R( 4)
R512_8_rounds(4);
#endif
#if   R512_Unroll_R( 5)
R512_8_rounds(5);
#endif
#if   R512_Unroll_R( 6)
R512_8_rounds(6);
#endif
#if   R512_Unroll_R( 7)
R512_8_rounds(7);
#endif
#if   R512_Unroll_R( 8)
R512_8_rounds(8);
#endif
#if   R512_Unroll_R( 9)
R512_8_rounds( 9);
#endif
#if   R512_Unroll_R(10)
R512_8_rounds(10);
#endif
#if   R512_Unroll_R(11)
R512_8_rounds(11);
#endif
#if   R512_Unroll_R(12)
R512_8_rounds(12);
#endif
#if   R512_Unroll_R(13)
R512_8_rounds(13);
#endif
#if   R512_Unroll_R(14)
R512_8_rounds(14);
#endif
#if  (SKEIN_UNROLL_512 > 14)
#error  "need more unrolling in Skein_512_Process_Block"
#endif
		}

		/* do the final "feedforward" xor, update context chaining vars */
		ctx->X[0] = X0 ^ w[0];
		ctx->X[1] = X1 ^ w[1];
		ctx->X[2] = X2 ^ w[2];
		ctx->X[3] = X3 ^ w[3];
		ctx->X[4] = X4 ^ w[4];
		ctx->X[5] = X5 ^ w[5];
		ctx->X[6] = X6 ^ w[6];
		ctx->X[7] = X7 ^ w[7];
		Skein_Show_Round(BLK_BITS,&ctx->h,SKEIN_RND_FEED_FWD,ctx->X);

		ts[1] &= ~SKEIN_T1_FLAG_FIRST;
	} while (--blkCnt);
	ctx->h.T[0] = ts[0];
	ctx->h.T[1] = ts[1];
}

#if defined(SKEIN_CODE_SIZE) || defined(SKEIN_PERF)
static size_t Skein_512_Process_Block_CodeSize(void)
{
	return ((u08b_t *) Skein_512_Process_Block_CodeSize) -
			((u08b_t *) Skein_512_Process_Block);
}
static uint_t Skein_512_Unroll_Cnt(void)
{
	return SKEIN_UNROLL_512;
}
#endif

static void Skein_256_Process_Block(Skein_256_Ctxt_t *ctx, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd) { /* do it in C */
	enum {
		WCNT = SKEIN_256_STATE_WORDS
	};
#undef  RCNT
#define RCNT  (SKEIN_256_ROUNDS_TOTAL/8)

#ifdef  SKEIN_LOOP                              /* configure how much to unroll the loop */
#define SKEIN_UNROLL_256 (((SKEIN_LOOP)/100)%10)
#else
#define SKEIN_UNROLL_256 (0)
#endif

#if SKEIN_UNROLL_256
#if (RCNT % SKEIN_UNROLL_256)
#error "Invalid SKEIN_UNROLL_256"               /* sanity check on unroll count */
#endif
	size_t r;
	u64b_t kw[WCNT+4+RCNT*2]; /* key schedule words : chaining vars + tweak + "rotation"*/
#else
	uint64_t kw[WCNT + 4]; /* key schedule words : chaining vars + tweak */
#endif
	uint64_t X0, X1, X2, X3; /* local copy of context vars, for speed */
	uint64_t w[WCNT]; /* local copy of input block */
#ifdef SKEIN_DEBUG
	const uint64_t *Xptr[4]; /* use for debugging (help compiler put Xn in registers) */
	Xptr[0] = &X0; Xptr[1] = &X1; Xptr[2] = &X2; Xptr[3] = &X3;
#endif
	assert(blkCnt != 0); /* never call with blkCnt == 0! */
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	do {
		/* this implementation only supports 2**64 input bytes (no carry out here) */
		ts[0] += byteCntAdd; /* update processed length */

		/* precompute the key schedule for this block */
		ks[0] = ctx->X[0];
		ks[1] = ctx->X[1];
		ks[2] = ctx->X[2];
		ks[3] = ctx->X[3];
		ks[4] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^ SKEIN_KS_PARITY;

		ts[2] = ts[0] ^ ts[1];

		Skein_Get64_LSB_First(w, blkPtr, WCNT); /* get input block in little-endian format */
		DebugSaveTweak(ctx);Skein_Show_Block(BLK_BITS,&ctx->h,ctx->X,blkPtr,w,ks,ts);

		X0 = w[0] + ks[0]; /* do the first full key injection */
		X1 = w[1] + ks[1] + ts[0];
		X2 = w[2] + ks[2] + ts[1];
		X3 = w[3] + ks[3];

		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INITIAL,Xptr); /* show starting state values */

		blkPtr += SKEIN_256_BLOCK_BYTES;

		/* run the rounds */

#define Round256(p0,p1,p2,p3,ROT,rNum)                              \
		X##p0 += X##p1; X##p1 = RotL_64(X##p1,ROT##_0); X##p1 ^= X##p0; \
		X##p2 += X##p3; X##p3 = RotL_64(X##p3,ROT##_1); X##p3 ^= X##p2; \

#if SKEIN_UNROLL_256 == 0
#define R256(p0,p1,p2,p3,ROT,rNum)           /* fully unrolled */   \
Round256(p0,p1,p2,p3,ROT,rNum)                                  \
Skein_Show_R_Ptr(BLK_BITS,&ctx->h,rNum,Xptr);

#define I256(R)                                                     \
		X0   += ks[((R)+1) % 5];    /* inject the key schedule value */ \
		X1   += ks[((R)+2) % 5] + ts[((R)+1) % 3];                      \
		X2   += ks[((R)+3) % 5] + ts[((R)+2) % 3];                      \
		X3   += ks[((R)+4) % 5] +     (R)+1;                            \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);
#else                                       /* looping version */
#define R256(p0,p1,p2,p3,ROT,rNum)                                  \
		Round256(p0,p1,p2,p3,ROT,rNum)                                  \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,4*(r-1)+rNum,Xptr);

#define I256(R)                                                     \
		X0   += ks[r+(R)+0];        /* inject the key schedule value */ \
		X1   += ks[r+(R)+1] + ts[r+(R)+0];                              \
		X2   += ks[r+(R)+2] + ts[r+(R)+1];                              \
		X3   += ks[r+(R)+3] +    r+(R)   ;                              \
		ks[r + (R)+4    ]   = ks[r+(R)-1];     /* rotate key schedule */\
		ts[r + (R)+2    ]   = ts[r+(R)-1];                              \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);

		for (r=1;r < 2*RCNT;r+=2*SKEIN_UNROLL_256) /* loop thru it */
#endif
		{
#define R256_8_rounds(R)                  \
		R256(0,1,2,3,R_256_0,8*(R) + 1);  \
		R256(0,3,2,1,R_256_1,8*(R) + 2);  \
		R256(0,1,2,3,R_256_2,8*(R) + 3);  \
		R256(0,3,2,1,R_256_3,8*(R) + 4);  \
		I256(2*(R));                      \
		R256(0,1,2,3,R_256_4,8*(R) + 5);  \
		R256(0,3,2,1,R_256_5,8*(R) + 6);  \
		R256(0,1,2,3,R_256_6,8*(R) + 7);  \
		R256(0,3,2,1,R_256_7,8*(R) + 8);  \
		I256(2*(R)+1);

			R256_8_rounds(0);

#define R256_Unroll_R(NN) ((SKEIN_UNROLL_256 == 0 && SKEIN_256_ROUNDS_TOTAL/8 > (NN)) || (SKEIN_UNROLL_256 > (NN)))

#if   R256_Unroll_R( 1)
			R256_8_rounds(1);
#endif
#if   R256_Unroll_R( 2)
			R256_8_rounds(2);
#endif
#if   R256_Unroll_R( 3)
			R256_8_rounds(3);
#endif
#if   R256_Unroll_R( 4)
			R256_8_rounds(4);
#endif
#if   R256_Unroll_R( 5)
			R256_8_rounds(5);
#endif
#if   R256_Unroll_R( 6)
			R256_8_rounds(6);
#endif
#if   R256_Unroll_R( 7)
			R256_8_rounds(7);
#endif
#if   R256_Unroll_R( 8)
			R256_8_rounds(8);
#endif
#if   R256_Unroll_R( 9)
			R256_8_rounds( 9);
#endif
#if   R256_Unroll_R(10)
			R256_8_rounds(10);
#endif
#if   R256_Unroll_R(11)
			R256_8_rounds(11);
#endif
#if   R256_Unroll_R(12)
			R256_8_rounds(12);
#endif
#if   R256_Unroll_R(13)
			R256_8_rounds(13);
#endif
#if   R256_Unroll_R(14)
			R256_8_rounds(14);
#endif
#if  (SKEIN_UNROLL_256 > 14)
#error  "need more unrolling in Skein_256_Process_Block"
#endif
		}
		/* do the final "feedforward" xor, update context chaining vars */
		ctx->X[0] = X0 ^ w[0];
		ctx->X[1] = X1 ^ w[1];
		ctx->X[2] = X2 ^ w[2];
		ctx->X[3] = X3 ^ w[3];

		Skein_Show_Round(BLK_BITS,&ctx->h,SKEIN_RND_FEED_FWD,ctx->X);

		ts[1] &= ~SKEIN_T1_FLAG_FIRST;
	} while (--blkCnt);
	ctx->h.T[0] = ts[0];
	ctx->h.T[1] = ts[1];
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
static bool Skein_256_Update(Skein_256_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt) {
	size_t n;

	Skein_Assert(ctx->h.bCnt <= SKEIN_256_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	/* process full blocks, if any */
	if (msgByteCnt + ctx->h.bCnt > SKEIN_256_BLOCK_BYTES) {
		if (ctx->h.bCnt) /* finish up any buffered message data */
		{
			n = SKEIN_256_BLOCK_BYTES - ctx->h.bCnt; /* # bytes free in buffer b[] */
			if (n) {
				assert(n < msgByteCnt); /* check on our logic here */
				memcpy(&ctx->b[ctx->h.bCnt], msg, n);
				msgByteCnt -= n;
				msg += n;
				ctx->h.bCnt += n;
			}
			assert(ctx->h.bCnt == SKEIN_256_BLOCK_BYTES);
			Skein_256_Process_Block(ctx, ctx->b, 1, SKEIN_256_BLOCK_BYTES);
			ctx->h.bCnt = 0;
		}
		/* now process any remaining full blocks, directly from input message data */
		if (msgByteCnt > SKEIN_256_BLOCK_BYTES) {
			n = (msgByteCnt - 1) / SKEIN_256_BLOCK_BYTES; /* number of full blocks to process */
			Skein_256_Process_Block(ctx, msg, n, SKEIN_256_BLOCK_BYTES);
			msgByteCnt -= n * SKEIN_256_BLOCK_BYTES;
			msg += n * SKEIN_256_BLOCK_BYTES;
		}
		assert(ctx->h.bCnt == 0);
	}

	/* copy any remaining source message data bytes into b[] */
	if (msgByteCnt) {
		assert(msgByteCnt + ctx->h.bCnt <= SKEIN_256_BLOCK_BYTES);
		memcpy(&ctx->b[ctx->h.bCnt], msg, msgByteCnt);
		ctx->h.bCnt += msgByteCnt;
	}

	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
static bool Skein_256_Final(Skein_256_Ctxt_t *ctx, unsigned char *hashVal) {
	size_t i, n, byteCnt;
	uint64_t X[SKEIN_256_STATE_WORDS];
	Skein_Assert(ctx->h.bCnt <= SKEIN_256_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL; /* tag as the final block */
	if (ctx->h.bCnt < SKEIN_256_BLOCK_BYTES) /* zero pad b[] if necessary */
		memset(&ctx->b[ctx->h.bCnt], 0, SKEIN_256_BLOCK_BYTES - ctx->h.bCnt);

	Skein_256_Process_Block(ctx, ctx->b, 1, ctx->h.bCnt); /* process the final block */

	/* now output the result */
	byteCnt = (ctx->h.hashBitLen + 7) >> 3; /* total number of output bytes */

	/* run Threefish in "counter mode" to generate output */
	memset(ctx->b, 0, sizeof(ctx->b)); /* zero out b[], so it can hold the counter */
	memcpy(X, ctx->X, sizeof(X)); /* keep a local copy of counter mode "key" */
	for (i = 0; i * SKEIN_256_BLOCK_BYTES < byteCnt; i++) {
		((uint64_t *) ctx->b)[0] = Skein_Swap64((uint64_t ) i); /* build the counter block */
		Skein_Start_New_Type(ctx, OUT_FINAL);
		Skein_256_Process_Block(ctx, ctx->b, 1, sizeof(uint64_t)); /* run "counter mode" */
		n = byteCnt - i * SKEIN_256_BLOCK_BYTES; /* number of output bytes left to go */
		if (n >= SKEIN_256_BLOCK_BYTES)
			n = SKEIN_256_BLOCK_BYTES;
		Skein_Put64_LSB_First(hashVal+i*SKEIN_256_BLOCK_BYTES, ctx->X, n); /* "output" the ctr mode bytes */
		Skein_Show_Final(256,&ctx->h,n,hashVal+i*SKEIN_256_BLOCK_BYTES);
		memcpy(ctx->X, X, sizeof(X)); /* restore the counter mode key for next time */
	}
	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* init the context for a straight hashing operation  */
static bool Skein_512_Init(Skein_512_Ctxt_t *ctx, size_t hashBitLen) {
	union {
		unsigned char 	b[SKEIN_512_STATE_BYTES];
		uint64_t 		w[SKEIN_512_STATE_WORDS];
	} cfg; 		// config block

	Skein_Assert(hashBitLen > 0, SKEIN_BAD_HASHLEN);
	ctx->h.hashBitLen = hashBitLen; 			// output hash bit count

	switch (hashBitLen) { 						// use pre-computed values, where available
#ifndef SKEIN_NO_PRECOMP
	case 512:
		memcpy(ctx->X, SKEIN_512_IV_512, sizeof(ctx->X));
		break;
	case 384:
		memcpy(ctx->X, SKEIN_512_IV_384, sizeof(ctx->X));
		break;
	case 256:
		memcpy(ctx->X, SKEIN_512_IV_256, sizeof(ctx->X));
		break;
	case 224:
		memcpy(ctx->X, SKEIN_512_IV_224, sizeof(ctx->X));
		break;
#endif
	default:
		/* here if there is no precomputed IV value available */
		/* build/process the config block, type == CONFIG (could be precomputed) */
		Skein_Start_New_Type(ctx, CFG_FINAL); // set tweaks: T0=0; T1=CFG | FINAL

		cfg.w[0] = Skein_Swap64(SKEIN_SCHEMA_VER); /* set the schema, version */
		cfg.w[1] = Skein_Swap64(hashBitLen); /* hash result length in bits */
		cfg.w[2] = Skein_Swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);
		memset(&cfg.w[3], 0, sizeof(cfg) - 3 * sizeof(cfg.w[0])); /* zero pad config block */

		/* compute the initial chaining values from config block */
		memset(ctx->X, 0, sizeof(ctx->X)); /* zero the chaining variables */
		Skein_512_Process_Block(ctx, cfg.b, 1, SKEIN_CFG_STR_LEN);
		break;
	}

	/* The chaining vars ctx->X are now initialized for the given hashBitLen. */
	/* Set up to process the data message portion of the hash (default) */
	Skein_Start_New_Type(ctx, MSG); /* T0=0, T1= MSG type */

	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
static bool Skein_512_Update(Skein_512_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt) {
	size_t n;

	Skein_Assert(ctx->h.bCnt <= SKEIN_512_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	/* process full blocks, if any */
	if (msgByteCnt + ctx->h.bCnt > SKEIN_512_BLOCK_BYTES) {
		if (ctx->h.bCnt) /* finish up any buffered message data */
		{
			n = SKEIN_512_BLOCK_BYTES - ctx->h.bCnt; /* # bytes free in buffer b[] */
			if (n) {
				assert(n < msgByteCnt); /* check on our logic here */
				memcpy(&ctx->b[ctx->h.bCnt], msg, n);
				msgByteCnt -= n;
				msg += n;
				ctx->h.bCnt += n;
			}
			assert(ctx->h.bCnt == SKEIN_512_BLOCK_BYTES);
			Skein_512_Process_Block(ctx, ctx->b, 1, SKEIN_512_BLOCK_BYTES);
			ctx->h.bCnt = 0;
		}
		/* now process any remaining full blocks, directly from input message data */
		if (msgByteCnt > SKEIN_512_BLOCK_BYTES) {
			n = (msgByteCnt - 1) / SKEIN_512_BLOCK_BYTES; /* number of full blocks to process */
			Skein_512_Process_Block(ctx, msg, n, SKEIN_512_BLOCK_BYTES);
			msgByteCnt -= n * SKEIN_512_BLOCK_BYTES;
			msg += n * SKEIN_512_BLOCK_BYTES;
		}
		assert(ctx->h.bCnt == 0);
	}

	/* copy any remaining source message data bytes into b[] */
	if (msgByteCnt) {
		assert(msgByteCnt + ctx->h.bCnt <= SKEIN_512_BLOCK_BYTES);
		memcpy(&ctx->b[ctx->h.bCnt], msg, msgByteCnt);
		ctx->h.bCnt += msgByteCnt;
	}

	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
static bool Skein_512_Final(Skein_512_Ctxt_t *ctx, unsigned char *hashVal) {
	size_t i, n, byteCnt;
	uint64_t X[SKEIN_512_STATE_WORDS];
	Skein_Assert(ctx->h.bCnt <= SKEIN_512_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL; /* tag as the final block */
	if (ctx->h.bCnt < SKEIN_512_BLOCK_BYTES) /* zero pad b[] if necessary */
		memset(&ctx->b[ctx->h.bCnt], 0, SKEIN_512_BLOCK_BYTES - ctx->h.bCnt);

	Skein_512_Process_Block(ctx, ctx->b, 1, ctx->h.bCnt); /* process the final block */

	/* now output the result */
	byteCnt = (ctx->h.hashBitLen + 7) >> 3; /* total number of output bytes */

	/* run Threefish in "counter mode" to generate output */
	memset(ctx->b, 0, sizeof(ctx->b)); /* zero out b[], so it can hold the counter */
	memcpy(X, ctx->X, sizeof(X)); /* keep a local copy of counter mode "key" */
	for (i = 0; i * SKEIN_512_BLOCK_BYTES < byteCnt; i++) {
		((uint64_t *) ctx->b)[0] = Skein_Swap64((uint64_t ) i); /* build the counter block */
		Skein_Start_New_Type(ctx, OUT_FINAL);
		Skein_512_Process_Block(ctx, ctx->b, 1, sizeof(uint64_t)); /* run "counter mode" */
		n = byteCnt - i * SKEIN_512_BLOCK_BYTES; /* number of output bytes left to go */
		if (n >= SKEIN_512_BLOCK_BYTES)
			n = SKEIN_512_BLOCK_BYTES;
		Skein_Put64_LSB_First(hashVal+i*SKEIN_512_BLOCK_BYTES, ctx->X, n); /* "output" the ctr mode bytes */
		Skein_Show_Final(512,&ctx->h,n,hashVal+i*SKEIN_512_BLOCK_BYTES);
		memcpy(ctx->X, X, sizeof(X)); /* restore the counter mode key for next time */
	}
	return true;
}
/*****************************  Skein1024 ******************************/
static void Skein1024_Process_Block(Skein1024_Ctxt_t *ctx, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd) { /* do it in C, always looping (unrolled is bigger AND slower!) */
	enum {
		WCNT = SKEIN1024_STATE_WORDS
	};
#undef  RCNT
#define RCNT  (SKEIN1024_ROUNDS_TOTAL/8)

#ifdef  SKEIN_LOOP                              /* configure how much to unroll the loop */
#define SKEIN_UNROLL_1024 ((SKEIN_LOOP)%10)
#else
#define SKEIN_UNROLL_1024 (0)
#endif

#if (SKEIN_UNROLL_1024 != 0)
#if (RCNT % SKEIN_UNROLL_1024)
#error "Invalid SKEIN_UNROLL_1024"              /* sanity check on unroll count */
#endif
	size_t r;
	uint64_t kw[WCNT + 4 + RCNT * 2]; /* key schedule words : chaining vars + tweak + "rotation"*/
#else
	uint64_t kw[WCNT+4]; /* key schedule words : chaining vars + tweak */
#endif

	uint64_t X00, X01, X02, X03, X04, X05, X06, X07, /* local copy of vars, for speed */
	X08, X09, X10, X11, X12, X13, X14, X15;
	uint64_t w[WCNT]; /* local copy of input block */
#ifdef SKEIN_DEBUG
	const u64b_t *Xptr[16]; /* use for debugging (help compiler put Xn in registers) */
	Xptr[ 0] = &X00; Xptr[ 1] = &X01; Xptr[ 2] = &X02; Xptr[ 3] = &X03;
	Xptr[ 4] = &X04; Xptr[ 5] = &X05; Xptr[ 6] = &X06; Xptr[ 7] = &X07;
	Xptr[ 8] = &X08; Xptr[ 9] = &X09; Xptr[10] = &X10; Xptr[11] = &X11;
	Xptr[12] = &X12; Xptr[13] = &X13; Xptr[14] = &X14; Xptr[15] = &X15;
#endif

	assert(blkCnt != 0); /* never call with blkCnt == 0! */
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	do {
		/* this implementation only supports 2**64 input bytes (no carry out here) */
		ts[0] += byteCntAdd; /* update processed length */

		/* precompute the key schedule for this block */
		ks[0] = ctx->X[0];
		ks[1] = ctx->X[1];
		ks[2] = ctx->X[2];
		ks[3] = ctx->X[3];
		ks[4] = ctx->X[4];
		ks[5] = ctx->X[5];
		ks[6] = ctx->X[6];
		ks[7] = ctx->X[7];
		ks[8] = ctx->X[8];
		ks[9] = ctx->X[9];
		ks[10] = ctx->X[10];
		ks[11] = ctx->X[11];
		ks[12] = ctx->X[12];
		ks[13] = ctx->X[13];
		ks[14] = ctx->X[14];
		ks[15] = ctx->X[15];
		ks[16] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^
				ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^
				ks[8] ^ ks[9] ^ ks[10] ^ ks[11] ^
				ks[12] ^ ks[13] ^ ks[14] ^ ks[15] ^ SKEIN_KS_PARITY;

		ts[2] = ts[0] ^ ts[1];

		Skein_Get64_LSB_First(w, blkPtr, WCNT); /* get input block in little-endian format */
		DebugSaveTweak(ctx);Skein_Show_Block(BLK_BITS,&ctx->h,ctx->X,blkPtr,w,ks,ts);

		X00 = w[0] + ks[0]; /* do the first full key injection */
		X01 = w[1] + ks[1];
		X02 = w[2] + ks[2];
		X03 = w[3] + ks[3];
		X04 = w[4] + ks[4];
		X05 = w[5] + ks[5];
		X06 = w[6] + ks[6];
		X07 = w[7] + ks[7];
		X08 = w[8] + ks[8];
		X09 = w[9] + ks[9];
		X10 = w[10] + ks[10];
		X11 = w[11] + ks[11];
		X12 = w[12] + ks[12];
		X13 = w[13] + ks[13] + ts[0];
		X14 = w[14] + ks[14] + ts[1];
		X15 = w[15] + ks[15];

		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INITIAL,Xptr);

#define Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rNum) \
		X##p0 += X##p1; X##p1 = RotL_64(X##p1,ROT##_0); X##p1 ^= X##p0;   \
		X##p2 += X##p3; X##p3 = RotL_64(X##p3,ROT##_1); X##p3 ^= X##p2;   \
		X##p4 += X##p5; X##p5 = RotL_64(X##p5,ROT##_2); X##p5 ^= X##p4;   \
		X##p6 += X##p7; X##p7 = RotL_64(X##p7,ROT##_3); X##p7 ^= X##p6;   \
		X##p8 += X##p9; X##p9 = RotL_64(X##p9,ROT##_4); X##p9 ^= X##p8;   \
		X##pA += X##pB; X##pB = RotL_64(X##pB,ROT##_5); X##pB ^= X##pA;   \
		X##pC += X##pD; X##pD = RotL_64(X##pD,ROT##_6); X##pD ^= X##pC;   \
		X##pE += X##pF; X##pF = RotL_64(X##pF,ROT##_7); X##pF ^= X##pE;   \

#if SKEIN_UNROLL_1024 == 0
#define R1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
		Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,rn,Xptr);

#define I1024(R)                                                      \
		X00   += ks[((R)+ 1) % 17]; /* inject the key schedule value */   \
		X01   += ks[((R)+ 2) % 17];                                       \
		X02   += ks[((R)+ 3) % 17];                                       \
		X03   += ks[((R)+ 4) % 17];                                       \
		X04   += ks[((R)+ 5) % 17];                                       \
		X05   += ks[((R)+ 6) % 17];                                       \
		X06   += ks[((R)+ 7) % 17];                                       \
		X07   += ks[((R)+ 8) % 17];                                       \
		X08   += ks[((R)+ 9) % 17];                                       \
		X09   += ks[((R)+10) % 17];                                       \
		X10   += ks[((R)+11) % 17];                                       \
		X11   += ks[((R)+12) % 17];                                       \
		X12   += ks[((R)+13) % 17];                                       \
		X13   += ks[((R)+14) % 17] + ts[((R)+1) % 3];                     \
		X14   += ks[((R)+15) % 17] + ts[((R)+2) % 3];                     \
		X15   += ks[((R)+16) % 17] +     (R)+1;                           \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);
#else                                       /* looping version */
#define R1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
		Round1024(p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,pA,pB,pC,pD,pE,pF,ROT,rn) \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,4*(r-1)+rn,Xptr);

#define I1024(R)                                                      \
		X00   += ks[r+(R)+ 0];    /* inject the key schedule value */     \
		X01   += ks[r+(R)+ 1];                                            \
		X02   += ks[r+(R)+ 2];                                            \
		X03   += ks[r+(R)+ 3];                                            \
		X04   += ks[r+(R)+ 4];                                            \
		X05   += ks[r+(R)+ 5];                                            \
		X06   += ks[r+(R)+ 6];                                            \
		X07   += ks[r+(R)+ 7];                                            \
		X08   += ks[r+(R)+ 8];                                            \
		X09   += ks[r+(R)+ 9];                                            \
		X10   += ks[r+(R)+10];                                            \
		X11   += ks[r+(R)+11];                                            \
		X12   += ks[r+(R)+12];                                            \
		X13   += ks[r+(R)+13] + ts[r+(R)+0];                              \
		X14   += ks[r+(R)+14] + ts[r+(R)+1];                              \
		X15   += ks[r+(R)+15] +    r+(R)   ;                              \
		ks[r  +       (R)+16] = ks[r+(R)-1];  /* rotate key schedule */   \
		ts[r  +       (R)+ 2] = ts[r+(R)-1];                              \
		Skein_Show_R_Ptr(BLK_BITS,&ctx->h,SKEIN_RND_KEY_INJECT,Xptr);

		for (r = 1; r <= 2 * RCNT; r += 2 * SKEIN_UNROLL_1024) /* loop thru it */
#endif
		{
#define R1024_8_rounds(R)    /* do 8 full rounds */                               \
R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_0,8*(R) + 1); \
R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_1,8*(R) + 2); \
R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_2,8*(R) + 3); \
R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_3,8*(R) + 4); \
I1024(2*(R));                                                             \
R1024(00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,R1024_4,8*(R) + 5); \
R1024(00,09,02,13,06,11,04,15,10,07,12,03,14,05,08,01,R1024_5,8*(R) + 6); \
R1024(00,07,02,05,04,03,06,01,12,15,14,13,08,11,10,09,R1024_6,8*(R) + 7); \
R1024(00,15,02,11,06,13,04,09,14,01,08,05,10,03,12,07,R1024_7,8*(R) + 8); \
I1024(2*(R)+1);

R1024_8_rounds(0);

#define R1024_Unroll_R(NN) ((SKEIN_UNROLL_1024 == 0 && SKEIN1024_ROUNDS_TOTAL/8 > (NN)) || (SKEIN_UNROLL_1024 > (NN)))

#if   R1024_Unroll_R( 1)
R1024_8_rounds( 1);
#endif
#if   R1024_Unroll_R( 2)
R1024_8_rounds( 2);
#endif
#if   R1024_Unroll_R( 3)
R1024_8_rounds( 3);
#endif
#if   R1024_Unroll_R( 4)
R1024_8_rounds( 4);
#endif
#if   R1024_Unroll_R( 5)
R1024_8_rounds( 5);
#endif
#if   R1024_Unroll_R( 6)
R1024_8_rounds( 6);
#endif
#if   R1024_Unroll_R( 7)
R1024_8_rounds( 7);
#endif
#if   R1024_Unroll_R( 8)
R1024_8_rounds( 8);
#endif
#if   R1024_Unroll_R( 9)
R1024_8_rounds( 9);
#endif
#if   R1024_Unroll_R(10)
R1024_8_rounds(10);
#endif
#if   R1024_Unroll_R(11)
R1024_8_rounds(11);
#endif
#if   R1024_Unroll_R(12)
R1024_8_rounds(12);
#endif
#if   R1024_Unroll_R(13)
R1024_8_rounds(13);
#endif
#if   R1024_Unroll_R(14)
R1024_8_rounds(14);
#endif
#if  (SKEIN_UNROLL_1024 > 14)
#error  "need more unrolling in Skein_1024_Process_Block"
#endif
		}
		/* do the final "feedforward" xor, update context chaining vars */

		ctx->X[0] = X00 ^ w[0];
		ctx->X[1] = X01 ^ w[1];
		ctx->X[2] = X02 ^ w[2];
		ctx->X[3] = X03 ^ w[3];
		ctx->X[4] = X04 ^ w[4];
		ctx->X[5] = X05 ^ w[5];
		ctx->X[6] = X06 ^ w[6];
		ctx->X[7] = X07 ^ w[7];
		ctx->X[8] = X08 ^ w[8];
		ctx->X[9] = X09 ^ w[9];
		ctx->X[10] = X10 ^ w[10];
		ctx->X[11] = X11 ^ w[11];
		ctx->X[12] = X12 ^ w[12];
		ctx->X[13] = X13 ^ w[13];
		ctx->X[14] = X14 ^ w[14];
		ctx->X[15] = X15 ^ w[15];

		Skein_Show_Round(BLK_BITS,&ctx->h,SKEIN_RND_FEED_FWD,ctx->X);

		ts[1] &= ~SKEIN_T1_FLAG_FIRST;
		blkPtr += SKEIN1024_BLOCK_BYTES;
	} while (--blkCnt);
	ctx->h.T[0] = ts[0];
	ctx->h.T[1] = ts[1];
}

/*****************************************************************/
/*    1024-bit Skein                                             */
/*****************************************************************/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* init the context for a straight hashing operation  */
static bool Skein1024_Init(Skein1024_Ctxt_t *ctx, size_t hashBitLen) {
	union {
		unsigned char b[SKEIN1024_STATE_BYTES];
		uint64_t w[SKEIN1024_STATE_WORDS];
	} cfg; /* config block */

	Skein_Assert(hashBitLen > 0, SKEIN_BAD_HASHLEN);
	ctx->h.hashBitLen = hashBitLen; /* output hash bit count */

	switch (hashBitLen) { /* use pre-computed values, where available */
#ifndef SKEIN_NO_PRECOMP
	case 512:
		memcpy(ctx->X, SKEIN1024_IV_512, sizeof(ctx->X));
		break;
	case 384:
		memcpy(ctx->X, SKEIN1024_IV_384, sizeof(ctx->X));
		break;
	case 1024:
		memcpy(ctx->X, SKEIN1024_IV_1024, sizeof(ctx->X));
		break;
#endif
	default:
		/* here if there is no precomputed IV value available */
		/* build/process the config block, type == CONFIG (could be precomputed) */
		Skein_Start_New_Type(ctx, CFG_FINAL)
		; /* set tweaks: T0=0; T1=CFG | FINAL */

		cfg.w[0] = Skein_Swap64(SKEIN_SCHEMA_VER); /* set the schema, version */
		cfg.w[1] = Skein_Swap64(hashBitLen); /* hash result length in bits */
		cfg.w[2] = Skein_Swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);
		memset(&cfg.w[3], 0, sizeof(cfg) - 3 * sizeof(cfg.w[0])); /* zero pad config block */

		/* compute the initial chaining values from config block */
		memset(ctx->X, 0, sizeof(ctx->X)); /* zero the chaining variables */
		Skein1024_Process_Block(ctx, cfg.b, 1, SKEIN_CFG_STR_LEN);
		break;
	}

	/* The chaining vars ctx->X are now initialized for the given hashBitLen. */
	/* Set up to process the data message portion of the hash (default) */
	Skein_Start_New_Type(ctx, MSG); /* T0=0, T1= MSG type */

	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
static bool Skein1024_Update(Skein1024_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt) {
	size_t n;

	Skein_Assert(ctx->h.bCnt <= SKEIN1024_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	/* process full blocks, if any */
	if (msgByteCnt + ctx->h.bCnt > SKEIN1024_BLOCK_BYTES) {
		if (ctx->h.bCnt) /* finish up any buffered message data */
		{
			n = SKEIN1024_BLOCK_BYTES - ctx->h.bCnt; /* # bytes free in buffer b[] */
			if (n) {
				assert(n < msgByteCnt); /* check on our logic here */
				memcpy(&ctx->b[ctx->h.bCnt], msg, n);
				msgByteCnt -= n;
				msg += n;
				ctx->h.bCnt += n;
			}
			assert(ctx->h.bCnt == SKEIN1024_BLOCK_BYTES);
			Skein1024_Process_Block(ctx, ctx->b, 1, SKEIN1024_BLOCK_BYTES);
			ctx->h.bCnt = 0;
		}
		/* now process any remaining full blocks, directly from input message data */
		if (msgByteCnt > SKEIN1024_BLOCK_BYTES) {
			n = (msgByteCnt - 1) / SKEIN1024_BLOCK_BYTES; /* number of full blocks to process */
			Skein1024_Process_Block(ctx, msg, n, SKEIN1024_BLOCK_BYTES);
			msgByteCnt -= n * SKEIN1024_BLOCK_BYTES;
			msg += n * SKEIN1024_BLOCK_BYTES;
		}
		assert(ctx->h.bCnt == 0);
	}

	/* copy any remaining source message data bytes into b[] */
	if (msgByteCnt) {
		assert(msgByteCnt + ctx->h.bCnt <= SKEIN1024_BLOCK_BYTES);
		memcpy(&ctx->b[ctx->h.bCnt], msg, msgByteCnt);
		ctx->h.bCnt += msgByteCnt;
	}

	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
static bool Skein1024_Final(Skein1024_Ctxt_t *ctx, unsigned char *hashVal) {
	size_t i, n, byteCnt;
	uint64_t X[SKEIN1024_STATE_WORDS];
	Skein_Assert(ctx->h.bCnt <= SKEIN1024_BLOCK_BYTES, SKEIN_FAIL); /* catch uninitialized context */

	ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL; /* tag as the final block */
	if (ctx->h.bCnt < SKEIN1024_BLOCK_BYTES) /* zero pad b[] if necessary */
		memset(&ctx->b[ctx->h.bCnt], 0, SKEIN1024_BLOCK_BYTES - ctx->h.bCnt);

	Skein1024_Process_Block(ctx, ctx->b, 1, ctx->h.bCnt); /* process the final block */

	/* now output the result */
	byteCnt = (ctx->h.hashBitLen + 7) >> 3; /* total number of output bytes */

	/* run Threefish in "counter mode" to generate output */
	memset(ctx->b, 0, sizeof(ctx->b)); /* zero out b[], so it can hold the counter */
	memcpy(X, ctx->X, sizeof(X)); /* keep a local copy of counter mode "key" */
	for (i = 0; i * SKEIN1024_BLOCK_BYTES < byteCnt; i++) {
		((uint64_t *) ctx->b)[0] = Skein_Swap64((uint64_t ) i); /* build the counter block */
		Skein_Start_New_Type(ctx, OUT_FINAL);
		Skein1024_Process_Block(ctx, ctx->b, 1, sizeof(uint64_t)); /* run "counter mode" */
		n = byteCnt - i * SKEIN1024_BLOCK_BYTES; /* number of output bytes left to go */
		if (n >= SKEIN1024_BLOCK_BYTES)
			n = SKEIN1024_BLOCK_BYTES;
		Skein_Put64_LSB_First(hashVal+i*SKEIN1024_BLOCK_BYTES, ctx->X, n); /* "output" the ctr mode bytes */
		Skein_Show_Final(1024,&ctx->h,n,hashVal+i*SKEIN1024_BLOCK_BYTES);
		memcpy(ctx->X, X, sizeof(X)); /* restore the counter mode key for next time */
	}
	return true;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* select the context size and init the context */
static bool Init(skein_hashState *state, int hashbitlen) {
#if SKEIN_256_NIST_MAX_HASHBITS
	if (hashbitlen <= SKEIN_256_NIST_MAX_HASHBITS)
	{
		Skein_Assert(hashbitlen > 0,BAD_HASHLEN);
		state->statebits = 64*SKEIN_256_STATE_WORDS;
		return Skein_256_Init(&state->u.ctx_256,(size_t) hashbitlen);
	}
#endif
	if (hashbitlen <= SKEIN_512_NIST_MAX_HASHBITS) {
		state->statebits = 64 * SKEIN_512_STATE_WORDS;
		return Skein_512_Init(&state->u.ctx_512, (size_t) hashbitlen);
	} else {
		state->statebits = 64 * SKEIN1024_STATE_WORDS;
		return Skein1024_Init(&state->u.ctx1024, (size_t) hashbitlen);
	}
}

#define Skein_Clear_First_Flag(hdr)      { (hdr).T[1] &= ~SKEIN_T1_FLAG_FIRST;       }
#define Skein_Set_Bit_Pad_Flag(hdr)      { (hdr).T[1] |=  SKEIN_T1_FLAG_BIT_PAD;     }

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process data to be hashed */
static bool Update(skein_hashState *state, const BitSequence *data, DataLength databitlen) {
	/* only the final Update() call is allowed do partial bytes, else assert an error */
	Skein_Assert((state->u.h.T[1] & SKEIN_T1_FLAG_BIT_PAD) == 0 || databitlen == 0, SKEIN_FAIL);

	Skein_Assert(state->statebits % 256 == 0 && (state->statebits - 256) < 1024, SKEIN_FAIL);
	if ((databitlen & 7) == 0) /* partial bytes? */
	{
		switch ((state->statebits >> 8) & 3) {
		case 2:
			return Skein_512_Update(&state->u.ctx_512, data, databitlen >> 3);
		case 1:
			return Skein_256_Update(&state->u.ctx_256, data, databitlen >> 3);
		case 0:
			return Skein1024_Update(&state->u.ctx1024, data, databitlen >> 3);
		default:
			return false;
		}
	} else { /* handle partial final byte */
		size_t bCnt = (databitlen >> 3) + 1; /* number of bytes to handle (nonzero here!) */
		unsigned char b, mask;

		mask = (unsigned char) (1u << (7 - (databitlen & 7))); /* partial byte bit mask */
		b = (unsigned char) ((data[bCnt - 1] & (0 - mask)) | mask); /* apply bit padding on final byte */

		switch ((state->statebits >> 8) & 3) {
		case 2:
			Skein_512_Update(&state->u.ctx_512, data, bCnt - 1); /* process all but the final byte    */
			Skein_512_Update(&state->u.ctx_512, &b, 1); /* process the (masked) partial byte */
			break;
		case 1:
			Skein_256_Update(&state->u.ctx_256, data, bCnt - 1); /* process all but the final byte    */
			Skein_256_Update(&state->u.ctx_256, &b, 1); /* process the (masked) partial byte */
			break;
		case 0:
			Skein1024_Update(&state->u.ctx1024, data, bCnt - 1); /* process all but the final byte    */
			Skein1024_Update(&state->u.ctx1024, &b, 1); /* process the (masked) partial byte */
			break;
		default:
			return false;
		}
		Skein_Set_Bit_Pad_Flag(state->u.h); /* set tweak flag for the final call */

		return true;
	}
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize hash computation and output the result (hashbitlen bits) */
static bool Final(skein_hashState *state, BitSequence *hashval) {
	Skein_Assert(state->statebits % 256 == 0 && (state->statebits - 256) < 1024, FAIL);
	switch ((state->statebits >> 8) & 3) {
	case 2:
		return Skein_512_Final(&state->u.ctx_512, hashval);
	case 1:
		return Skein_256_Final(&state->u.ctx_256, hashval);
	case 0:
		return Skein1024_Final(&state->u.ctx1024, hashval);
	default:
		return false;
	}
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* all-in-one hash function */
static bool skein_hash(int hashbitlen, const BitSequence *data,DataLength databitlen, BitSequence *hashval) {
	skein_hashState state;
	bool r = Init(&state, hashbitlen);
	if (r) { /* these calls do not fail when called properly */
		r = Update(&state, data, databitlen);
		Final(&state, hashval);
	}
	return r;
}

static void hash_extra_skein(const void *data, size_t length, char *hash) {
	bool r = skein_hash(8 * HASH_SIZE, (const BitSequence *) data, 8 * length, (uint8_t*) hash);
	assert(r);
}

static void check_data(size_t* data_index, const size_t bytes_needed, int8_t* data, const size_t data_size) {
	if (*data_index + bytes_needed > data_size)
	{
		hash_extra_blake(data, data_size, (char*)data);
		*data_index = 0;
	}
}

static OAES_RET oaes_key_destroy(oaes_key ** key) {
	if ( NULL == *key)
		return OAES_RET_SUCCESS;

	if ((*key)->data) {
		free((*key)->data);
		(*key)->data = NULL;
	}

	if ((*key)->exp_data) {
		free((*key)->exp_data);
		(*key)->exp_data = NULL;
	}

	(*key)->data_len = 0;
	(*key)->exp_data_len = 0;
	(*key)->num_keys = 0;
	(*key)->key_base = 0;
	free(*key);
	*key = NULL;

	return OAES_RET_SUCCESS;
}

static OAES_RET oaes_word_rot_left(uint8_t word[OAES_COL_LEN]) {
	uint8_t _temp[OAES_COL_LEN];

	if ( NULL == word)
		return OAES_RET_ARG1;

	memcpy(_temp, word + 1, OAES_COL_LEN - 1);
	_temp[OAES_COL_LEN - 1] = word[0];
	memcpy(word, _temp, OAES_COL_LEN);

	return OAES_RET_SUCCESS;
}

static uint8_t oaes_sub_byte_value[16][16] = {
// 		0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    a,    b,    c,    d,    e,    f,
		/*0*/{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
		/*1*/{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
		/*2*/{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
		/*3*/{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
		/*4*/{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
		/*5*/{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
		/*6*/{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
		/*7*/{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
		/*8*/{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
		/*9*/{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
		/*a*/{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
		/*b*/{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
		/*c*/{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
		/*d*/{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
		/*e*/{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
		/*f*/{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }, };

static uint8_t oaes_gf_8[] = {	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static OAES_RET oaes_sub_byte(uint8_t * byte) {
	size_t _x, _y;

	if ( NULL == byte)
		return OAES_RET_ARG1;

	_x = _y = *byte;
	_x &= 0x0f;
	_y &= 0xf0;
	_y >>= 4;
	*byte = oaes_sub_byte_value[_y][_x];

	return OAES_RET_SUCCESS;
}

static OAES_RET oaes_key_expand(OAES_CTX * ctx) {
	size_t _i, _j;
	oaes_ctx * _ctx = (oaes_ctx *) ctx;

	if ( NULL == _ctx)
		return OAES_RET_ARG1;

	if ( NULL == _ctx->key)
		return OAES_RET_NOKEY;

	_ctx->key->key_base = _ctx->key->data_len / OAES_RKEY_LEN;
	_ctx->key->num_keys = _ctx->key->key_base + OAES_ROUND_BASE;

	_ctx->key->exp_data_len = _ctx->key->num_keys * OAES_RKEY_LEN * OAES_COL_LEN;
	_ctx->key->exp_data = (uint8_t *) calloc(_ctx->key->exp_data_len, sizeof(uint8_t));

	if ( NULL == _ctx->key->exp_data)
		return OAES_RET_MEM;

	// the first _ctx->key->data_len are a direct copy
	memcpy(_ctx->key->exp_data, _ctx->key->data, _ctx->key->data_len);

	// apply ExpandKey algorithm for remainder
	for (_i = _ctx->key->key_base; _i < _ctx->key->num_keys * OAES_RKEY_LEN; _i++) {
		uint8_t _temp[OAES_COL_LEN];

		memcpy(_temp, _ctx->key->exp_data + (_i - 1) * OAES_RKEY_LEN, OAES_COL_LEN);

		// transform key column
		if (0 == _i % _ctx->key->key_base) {
			oaes_word_rot_left(_temp);

			for (_j = 0; _j < OAES_COL_LEN; _j++)
				oaes_sub_byte(_temp + _j);

			_temp[0] = _temp[0] ^ oaes_gf_8[_i / _ctx->key->key_base - 1];
		} else if (_ctx->key->key_base > 6 && 4 == _i % _ctx->key->key_base) {
			for (_j = 0; _j < OAES_COL_LEN; _j++)
				oaes_sub_byte(_temp + _j);
		}

		for (_j = 0; _j < OAES_COL_LEN; _j++) {
			_ctx->key->exp_data[_i * OAES_RKEY_LEN + _j] = _ctx->key->exp_data[(_i - _ctx->key->key_base) * OAES_RKEY_LEN + _j] ^ _temp[_j];
		}
	}

	return OAES_RET_SUCCESS;
}

static OAES_RET oaes_key_import_data(OAES_CTX * ctx, const uint8_t * data, size_t data_len) {
	oaes_ctx * _ctx = (oaes_ctx *) ctx;
	OAES_RET _rc = OAES_RET_SUCCESS;

	if ( NULL == _ctx)
		return OAES_RET_ARG1;

	if ( NULL == data)
		return OAES_RET_ARG2;

	switch (data_len) {
	case 16:
	case 24:
	case 32:
		break;
	default:
		return OAES_RET_ARG3;
	}

	if (_ctx->key)
		oaes_key_destroy(&(_ctx->key));

	_ctx->key = (oaes_key *) calloc(sizeof(oaes_key), 1);

	if ( NULL == _ctx->key)
		return OAES_RET_MEM;

	_ctx->key->data_len = data_len;
	_ctx->key->data = (uint8_t *) calloc(data_len, sizeof(uint8_t));

	if ( NULL == _ctx->key->data) {
		oaes_key_destroy(&(_ctx->key));
		return OAES_RET_MEM;
	}

	memcpy(_ctx->key->data, data, data_len);
	//_rc = _rc || oaes_key_expand(ctx);

	if (_rc != OAES_RET_SUCCESS || oaes_key_expand(ctx) != OAES_RET_SUCCESS) {
		oaes_key_destroy(&(_ctx->key));
		return _rc;
	}

	return OAES_RET_SUCCESS;
}

static OAES_RET oaes_set_option(OAES_CTX * ctx, OAES_OPTION option, const void * value) {
	size_t _i;
	oaes_ctx * _ctx = (oaes_ctx *) ctx;

	if ( NULL == _ctx)
		return OAES_RET_ARG1;

	switch (option) {
	case OAES_OPTION_ECB:
		_ctx->options &= ~OAES_OPTION_CBC;
		memset(_ctx->iv, 0, OAES_BLOCK_SIZE);
		break;

	case OAES_OPTION_CBC:
		_ctx->options &= ~OAES_OPTION_ECB;
		if (value)
			memcpy(_ctx->iv, value, OAES_BLOCK_SIZE);
		else {
			for (_i = 0; _i < OAES_BLOCK_SIZE; _i++)
#ifdef OAES_HAVE_ISAAC
				_ctx->iv[_i] = (uint8_t) rand( _ctx->rctx );
#else
				_ctx->iv[_i] = (uint8_t) rand();
#endif // OAES_HAVE_ISAAC
		}
		break;

#ifdef OAES_DEBUG

		case OAES_OPTION_STEP_ON:
		if( value )
		{
			_ctx->options &= ~OAES_OPTION_STEP_OFF;
			_ctx->step_cb = value;
		}
		else
		{
			_ctx->options &= ~OAES_OPTION_STEP_ON;
			_ctx->options |= OAES_OPTION_STEP_OFF;
			_ctx->step_cb = NULL;
			return OAES_RET_ARG3;
		}
		break;

		case OAES_OPTION_STEP_OFF:
		_ctx->options &= ~OAES_OPTION_STEP_ON;
		_ctx->step_cb = NULL;
		break;

#endif // OAES_DEBUG

	default:
		return OAES_RET_ARG2;
	}

	_ctx->options |= option;

	return OAES_RET_SUCCESS;
}

#ifdef _MSC_VER
#define GETPID() _getpid()
#else
#define GETPID() getpid()
#endif

#ifdef OAES_HAVE_ISAAC
static void oaes_get_seed( char buf[RANDSIZ + 1] )
{
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
	struct timeb timer;
	struct tm *gmTimer;
	char * _test = NULL;

	ftime (&timer);
	gmTimer = gmtime( &timer.time );
	_test = (char *) calloc( sizeof( char ), timer.millitm );
	sprintf( buf, "%04d%02d%02d%02d%02d%02d%03d%p%d",
			gmTimer->tm_year + 1900, gmTimer->tm_mon + 1, gmTimer->tm_mday,
			gmTimer->tm_hour, gmTimer->tm_min, gmTimer->tm_sec, timer.millitm,
			_test + timer.millitm, GETPID() );
#else
	struct timeval timer;
	struct tm *gmTimer;
	char * _test = NULL;

	gettimeofday(&timer, NULL);
	gmTimer = gmtime( &timer.tv_sec );
	_test = (char *) calloc( sizeof( char ), timer.tv_usec/1000 );
	sprintf( buf, "%04d%02d%02d%02d%02d%02d%03d%p%d",
			gmTimer->tm_year + 1900, gmTimer->tm_mon + 1, gmTimer->tm_mday,
			gmTimer->tm_hour, gmTimer->tm_min, gmTimer->tm_sec, timer.tv_usec/1000,
			_test + timer.tv_usec/1000, GETPID() );
#endif

	if( _test )
	free( _test );
}
#else
static uint32_t oaes_get_seed(void) {
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__ANDROID__) && !defined(__NetBSD__)
	struct timeb timer;
	struct tm *gmTimer;
	char * _test = NULL;
	uint32_t _ret = 0;

	ftime(&timer);
	gmTimer = gmtime(&timer.time);
	_test = (char *) calloc(sizeof(char), timer.millitm);
	_ret = gmTimer->tm_year + 1900 + gmTimer->tm_mon + 1 + gmTimer->tm_mday + gmTimer->tm_hour + gmTimer->tm_min + gmTimer->tm_sec + timer.millitm + (uintptr_t) (_test + timer.millitm) + GETPID();
#else
	struct timeval timer;
	struct tm *gmTimer;
	char * _test = NULL;
	uint32_t _ret = 0;

	gettimeofday(&timer, NULL);
	gmTimer = gmtime( &timer.tv_sec );
	_test = (char *) calloc( sizeof( char ), timer.tv_usec/1000 );
	_ret = gmTimer->tm_year + 1900 + gmTimer->tm_mon + 1 + gmTimer->tm_mday +
	gmTimer->tm_hour + gmTimer->tm_min + gmTimer->tm_sec + timer.tv_usec/1000 +
	(uintptr_t) ( _test + timer.tv_usec/1000 ) + GETPID();
#endif

	if (_test)
		free(_test);

	return _ret;
}
#endif // OAES_HAVE_ISAAC

OAES_CTX * oaes_alloc(void) {
	oaes_ctx * _ctx = (oaes_ctx *) calloc(sizeof(oaes_ctx), 1);

	if ( NULL == _ctx)
		return NULL;

#ifdef OAES_HAVE_ISAAC
	{
		ub4 _i = 0;
		char _seed[RANDSIZ + 1];

		_ctx->rctx = (randctx *) calloc( sizeof( randctx ), 1 );

		if( NULL == _ctx->rctx )
		{
			free( _ctx );
			return NULL;
		}

		oaes_get_seed( _seed );
		memset( _ctx->rctx->randrsl, 0, RANDSIZ );
		memcpy( _ctx->rctx->randrsl, _seed, RANDSIZ );
		randinit( _ctx->rctx, TRUE);
	}
#else
	srand(oaes_get_seed());
#endif // OAES_HAVE_ISAAC

	_ctx	->key = NULL;
	oaes_set_option(_ctx, OAES_OPTION_CBC, NULL);

#ifdef OAES_DEBUG
	_ctx->step_cb = NULL;
	oaes_set_option( _ctx, OAES_OPTION_STEP_OFF, NULL );
#endif // OAES_DEBUG

	return (OAES_CTX *) _ctx;
}

OAES_RET oaes_free(OAES_CTX ** ctx) {
	oaes_ctx ** _ctx = (oaes_ctx **) ctx;

	if ( NULL == _ctx)
		return OAES_RET_ARG1;

	if ( NULL == *_ctx)
		return OAES_RET_SUCCESS;

	if ((*_ctx)->key)
		oaes_key_destroy(&((*_ctx)->key));

#ifdef OAES_HAVE_ISAAC
	if( (*_ctx)->rctx )
	{
		free( (*_ctx)->rctx );
		(*_ctx)->rctx = NULL;
	}
#endif // OAES_HAVE_ISAAC

	free(*_ctx);
	*_ctx = NULL;

	return OAES_RET_SUCCESS;
}

#define TABLE_ALIGN     32
#define WPOLY           0x011b
#define N_COLS          4
#define AES_BLOCK_SIZE  16
#define RC_LENGTH (5 * (AES_BLOCK_SIZE / 4 - 2))

#define rf1(r,c) (r)
#define word_in(x,c) (*((uint32_t*)(x)+(c)))
#define word_out(x,c,v) (*((uint32_t*)(x)+(c)) = (v))
#define s(x,c) x[c]
#define si(y,x,c) (s(y,c) = word_in(x, c))
#define so(y,x,c) word_out(y, c, s(x,c))
#define state_in(y,x) si(y,x,0); si(y,x,1); si(y,x,2); si(y,x,3)
#define state_out(y,x)  so(y,x,0); so(y,x,1); so(y,x,2); so(y,x,3)
#define round(rm,y,x,k) rm(y,x,k,0); rm(y,x,k,1); rm(y,x,k,2); rm(y,x,k,3)
#define to_byte(x) ((x) & 0xff)
#define bval(x,n) to_byte((x) >> (8 * (n)))

#define fwd_var(x,r,c)\
 ( r == 0 ? ( c == 0 ? s(x,0) : c == 1 ? s(x,1) : c == 2 ? s(x,2) : s(x,3))\
 : r == 1 ? ( c == 0 ? s(x,1) : c == 1 ? s(x,2) : c == 2 ? s(x,3) : s(x,0))\
 : r == 2 ? ( c == 0 ? s(x,2) : c == 1 ? s(x,3) : c == 2 ? s(x,0) : s(x,1))\
 :          ( c == 0 ? s(x,3) : c == 1 ? s(x,0) : c == 2 ? s(x,1) : s(x,2)))

#define fwd_rnd(y,x,k,c)  (s(y,c) = (k)[c] ^ (four_tables(x,t_use(f,n),fwd_var,rf1,c)))

#define sb_data(w) {\
  w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
  w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
  w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
  w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
  w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
  w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
  w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
  w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
  w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
  w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
  w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
  w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
  w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
  w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
  w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
  w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
  w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
  w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
  w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
  w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
  w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
  w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
  w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
  w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
  w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
  w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
  w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
  w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
  w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
  w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
  w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
  w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define rc_data(w) {\
  w(0x01), w(0x02), w(0x04), w(0x08), w(0x10),w(0x20), w(0x40), w(0x80),\
  w(0x1b), w(0x36) }

#define bytes2word(b0, b1, b2, b3) (((uint32_t)(b3) << 24) | \
    ((uint32_t)(b2) << 16) | ((uint32_t)(b1) << 8) | (b0))

#define h0(x)   (x)
#define w0(p)   bytes2word(p, 0, 0, 0)
#define w1(p)   bytes2word(0, p, 0, 0)
#define w2(p)   bytes2word(0, 0, p, 0)
#define w3(p)   bytes2word(0, 0, 0, p)

#define u0(p)   bytes2word(f2(p), p, p, f3(p))
#define u1(p)   bytes2word(f3(p), f2(p), p, p)
#define u2(p)   bytes2word(p, f3(p), f2(p), p)
#define u3(p)   bytes2word(p, p, f3(p), f2(p))

#define v0(p)   bytes2word(fe(p), f9(p), fd(p), fb(p))
#define v1(p)   bytes2word(fb(p), fe(p), f9(p), fd(p))
#define v2(p)   bytes2word(fd(p), fb(p), fe(p), f9(p))
#define v3(p)   bytes2word(f9(p), fd(p), fb(p), fe(p))

#define f2(x)   ((x<<1) ^ (((x>>7) & 1) * WPOLY))
#define f4(x)   ((x<<2) ^ (((x>>6) & 1) * WPOLY) ^ (((x>>6) & 2) * WPOLY))
#define f8(x)   ((x<<3) ^ (((x>>5) & 1) * WPOLY) ^ (((x>>5) & 2) * WPOLY) ^ (((x>>5) & 4) * WPOLY))
#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

#define t_dec(m,n) t_##m##n
#define t_set(m,n) t_##m##n
#define t_use(m,n) t_##m##n

#define d_4(t,n,b,e,f,g,h) const t n[4][256] = { b(e), b(f), b(g), b(h) }

#define four_tables(x,tab,vf,rf,c) \
  (tab[0][bval(vf(x,0,c),rf(0,c))] \
   ^ tab[1][bval(vf(x,1,c),rf(1,c))] \
   ^ tab[2][bval(vf(x,2,c),rf(2,c))] \
   ^ tab[3][bval(vf(x,3,c),rf(3,c))])

d_4(uint32_t, t_dec(f,n), sb_data, u0, u1, u2, u3);

static void aesb_single_round(const uint8_t *in, uint8_t *out, uint8_t *expandedKey) {
	uint32_t b0[4], b1[4];
	const uint32_t *kp = (uint32_t *) expandedKey;
	state_in(b0, in);

	round(fwd_rnd, b1, b0, kp);

	state_out(out, b1);
}

static void aesb_pseudo_round(const uint8_t *in, uint8_t *out, uint8_t *expandedKey) {
	uint32_t b0[4], b1[4];
	const uint32_t *kp = (uint32_t *) expandedKey;
	state_in(b0, in);

	round(fwd_rnd, b1, b0, kp);
	round(fwd_rnd, b0, b1, kp + 1 * N_COLS);
	round(fwd_rnd, b1, b0, kp + 2 * N_COLS);
	round(fwd_rnd, b0, b1, kp + 3 * N_COLS);
	round(fwd_rnd, b1, b0, kp + 4 * N_COLS);
	round(fwd_rnd, b0, b1, kp + 5 * N_COLS);
	round(fwd_rnd, b1, b0, kp + 6 * N_COLS);
	round(fwd_rnd, b0, b1, kp + 7 * N_COLS);
	round(fwd_rnd, b1, b0, kp + 8 * N_COLS);
	round(fwd_rnd, b0, b1, kp + 9 * N_COLS);

	state_out(out, b0);
}

static void xor_blocks(uint8_t *a, const uint8_t *b) {
	U64(a)[0] ^= U64(b)[0];
	U64(a)[1] ^= U64(b)[1];
}

// Generates as many random math operations as possible with given latency and ALU restrictions
int v4_random_math_init(struct V4_Instruction* code, const uint64_t height, CryptoType cryptoType ) {
	// MUL is 3 cycles, 3-way addition and rotations are 2 cycles, SUB/XOR are 1 cycle
	// These latencies match real-life instruction latencies for Intel CPUs starting from Sandy Bridge and up to Skylake/Coffee lake
	//
	// AMD Ryzen has the same latencies except 1-cycle ROR/ROL, so it'll be a bit faster than Intel Sandy Bridge and newer processors
	// Surprisingly, Intel Nehalem also has 1-cycle ROR/ROL, so it'll also be faster than Intel Sandy Bridge and newer processors
	// AMD Bulldozer has 4 cycles latency for MUL (slower than Intel) and 1 cycle for ROR/ROL (faster than Intel), so average performance will be the same
	// Source: https://www.agner.org/optimize/instruction_tables.pdf
	const int op_latency[V4_INSTRUCTION_COUNT] = { 3, 2, 1, 2, 2, 1 };

	// Instruction latencies for theoretical ASIC implementation
	const int asic_op_latency[V4_INSTRUCTION_COUNT] = { 3, 1, 1, 1, 1, 1 };

	// Available ALUs for each instruction
	const int op_ALUs[V4_INSTRUCTION_COUNT] = { ALU_COUNT_MUL, ALU_COUNT, ALU_COUNT, ALU_COUNT, ALU_COUNT, ALU_COUNT };

	int8_t data[32];
	memset(data, 0, sizeof(data));
	*((uint64_t*)data) = height;

	if (cryptoType == MoneroCrypto) {
		data[20] =  0xda;
	}


	// Set data_index past the last byte in data
	// to trigger full data update with blake hash
	// before we start using it
	size_t data_index = sizeof(data);

	int code_size;

	// There is a small chance (1.8%) that register R8 won't be used in the generated program
	// So we keep track of it and try again if it's not used
	bool r8_used;
	do {
		int latency[9];
		int asic_latency[9];

		// Tracks previous instruction and value of the source operand for registers R0-R3 throughout code execution
		// byte 0: current value of the destination register
		// byte 1: instruction opcode
		// byte 2: current value of the source register
		//
		// Registers R4-R8 are constant and are treated as having the same value because when we do
		// the same operation twice with two constant source registers, it can be optimized into a single operation
		uint32_t inst_data[9] = { 0, 1, 2, 3, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF };

		bool alu_busy[TOTAL_LATENCY + 1][ALU_COUNT];
		bool is_rotation[V4_INSTRUCTION_COUNT];
		bool rotated[4];
		int rotate_count = 0;

		memset(latency, 0, sizeof(latency));
		memset(asic_latency, 0, sizeof(asic_latency));
		memset(alu_busy, 0, sizeof(alu_busy));
		memset(is_rotation, 0, sizeof(is_rotation));
		memset(rotated, 0, sizeof(rotated));
		is_rotation[ROR] = true;
		is_rotation[ROL] = true;

		int num_retries = 0;
		code_size = 0;

		int total_iterations = 0;
		r8_used = cryptoType == WowneroCrypto;

		// Generate random code to achieve minimal required latency for our abstract CPU
		// Try to get this latency for all 4 registers
		while (((latency[0] < TOTAL_LATENCY) || (latency[1] < TOTAL_LATENCY) || (latency[2] < TOTAL_LATENCY) || (latency[3] < TOTAL_LATENCY)) && (num_retries < 64))
		{
			// Fail-safe to guarantee loop termination
			++total_iterations;
			if (total_iterations > 256)
				break;

			check_data(&data_index, 1, data, sizeof(data));

			const uint8_t c = ((uint8_t*)data)[data_index++];

			// MUL = opcodes 0-2
			// ADD = opcode 3
			// SUB = opcode 4
			// ROR/ROL = opcode 5, shift direction is selected randomly
			// XOR = opcodes 6-7
			uint8_t opcode = c & ((1 << V4_OPCODE_BITS) - 1);
			if (opcode == 5)
			{
				check_data(&data_index, 1, data, sizeof(data));
				opcode = (data[data_index++] >= 0) ? ROR : ROL;
			}
			else if (opcode >= 6)
			{
				opcode = XOR;
			}
			else
			{
				opcode = (opcode <= 2) ? MUL : (opcode - 2);
			}

			uint8_t dst_index = (c >> V4_OPCODE_BITS) & ((1 << V4_DST_INDEX_BITS) - 1);
			uint8_t src_index = (c >> (V4_OPCODE_BITS + V4_DST_INDEX_BITS)) & ((1 << V4_SRC_INDEX_BITS) - 1);

			const int a = dst_index;
			int b = src_index;

			// Don't do ADD/SUB/XOR with the same register
			if (((opcode == ADD) || (opcode == SUB) || (opcode == XOR)) && (a == b))
			{
				// Use register R8 as source instead
				b = (cryptoType == WowneroCrypto) ? (a + 4) : 8;
				src_index = b;
			}

			// Don't do rotation with the same destination twice because it's equal to a single rotation
			if (is_rotation[opcode] && rotated[a])
			{
				continue;
			}

			// Don't do the same instruction (except MUL) with the same source value twice because all other cases can be optimized:
			// 2xADD(a, b, C) = ADD(a, b*2, C1+C2), same for SUB and rotations
			// 2xXOR(a, b) = NOP
			if ((opcode != MUL) && ((inst_data[a] & 0xFFFF00) == (opcode << 8) + ((inst_data[b] & 255) << 16)))
			{
				continue;
			}

			// Find which ALU is available (and when) for this instruction
			int next_latency = (latency[a] > latency[b]) ? latency[a] : latency[b];
			int alu_index = -1;
			while (next_latency < TOTAL_LATENCY)
			{
				for (int i = op_ALUs[opcode] - 1; i >= 0; --i)
				{
					if (!alu_busy[next_latency][i])
					{
						// ADD is implemented as two 1-cycle instructions on a real CPU, so do an additional availability check
						if ((opcode == ADD) && alu_busy[next_latency + 1][i])
						{
							continue;
						}

						// Rotation can only start when previous rotation is finished, so do an additional availability check
						if (is_rotation[opcode] && (next_latency < rotate_count * op_latency[opcode]))
						{
							continue;
						}

						alu_index = i;
						break;
					}
				}
				if (alu_index >= 0)
				{
					break;
				}
				++next_latency;
			}

			// Don't generate instructions that leave some register unchanged for more than 7 cycles
			if (next_latency > latency[a] + 7)
			{
				continue;
			}

			next_latency += op_latency[opcode];

			if (next_latency <= TOTAL_LATENCY)
			{
				if (is_rotation[opcode])
				{
					++rotate_count;
				}

				// Mark ALU as busy only for the first cycle when it starts executing the instruction because ALUs are fully pipelined
				alu_busy[next_latency - op_latency[opcode]][alu_index] = true;
				latency[a] = next_latency;

				// ASIC is supposed to have enough ALUs to run as many independent instructions per cycle as possible, so latency calculation for ASIC is simple
				asic_latency[a] = ((asic_latency[a] > asic_latency[b]) ? asic_latency[a] : asic_latency[b]) + asic_op_latency[opcode];

				rotated[a] = is_rotation[opcode];

				inst_data[a] = code_size + (opcode << 8) + ((inst_data[b] & 255) << 16);

				code[code_size].opcode = opcode;
				code[code_size].dst_index = dst_index;
				code[code_size].src_index = src_index;
				code[code_size].C = 0;

				if (src_index == 8) {
					r8_used = true;
				}

				if (opcode == ADD)
				{
					// ADD instruction is implemented as two 1-cycle instructions on a real CPU, so mark ALU as busy for the next cycle too
					alu_busy[next_latency - op_latency[opcode] + 1][alu_index] = true;

					// ADD instruction requires 4 more random bytes for 32-bit constant "C" in "a = a + b + C"
					check_data(&data_index, sizeof(uint32_t), data, sizeof(data));
					code[code_size].C = *((uint32_t*) &data[data_index]);
					data_index += sizeof(uint32_t);
				}

				++code_size;
				if (code_size >= NUM_INSTRUCTIONS_MIN)
				{
					break;
				}
			}
			else
			{
				++num_retries;
			}
		}

		// ASIC has more execution resources and can extract as much parallelism from the code as possible
		// We need to add a few more MUL and ROR instructions to achieve minimal required latency for ASIC
		// Get this latency for at least 1 of the 4 registers
		const int prev_code_size = code_size;
		while ((code_size < NUM_INSTRUCTIONS_MAX) && (asic_latency[0] < TOTAL_LATENCY) && (asic_latency[1] < TOTAL_LATENCY) && (asic_latency[2] < TOTAL_LATENCY) && (asic_latency[3] < TOTAL_LATENCY))
		{
			int min_idx = 0;
			int max_idx = 0;
			for (int i = 1; i < 4; ++i)
			{
				if (asic_latency[i] < asic_latency[min_idx]) min_idx = i;
				if (asic_latency[i] > asic_latency[max_idx]) max_idx = i;
			}

			const uint8_t pattern[3] = { ROR, MUL, MUL };
			const uint8_t opcode = pattern[(code_size - prev_code_size) % 3];
			latency[min_idx] = latency[max_idx] + op_latency[opcode];
			asic_latency[min_idx] = asic_latency[max_idx] + asic_op_latency[opcode];

			code[code_size].opcode = opcode;
			code[code_size].dst_index = min_idx;
			code[code_size].src_index = max_idx;
			code[code_size].C = 0;
			++code_size;
		}

	// There is ~98.15% chance that loop condition is false, so this loop will execute only 1 iteration most of the time
	// It never does more than 4 iterations for all block heights < 10,000,000
	}  while (!r8_used || (code_size < NUM_INSTRUCTIONS_MIN) || (code_size > NUM_INSTRUCTIONS_MAX));

	// It's guaranteed that NUM_INSTRUCTIONS_MIN <= code_size <= NUM_INSTRUCTIONS_MAX here
	// Add final instruction to stop the interpreter
	code[code_size].opcode = RET;
	code[code_size].dst_index = 0;
	code[code_size].src_index = 0;
	code[code_size].C = 0;

	return code_size;
}


#define VARIANT4_RANDOM_MATH_INIT() \
		v4_reg r[9]; \
		struct V4_Instruction code[TOTAL_LATENCY * ALU_COUNT + 1]; \
		if (cpuMiner.variant >= 4) \
		{ \
			v4_reg* data = (v4_reg*)(cpuMiner.shs.hs.w + 12); \
			r[0] = data[0]; \
			r[1] = data[1]; \
			r[2] = data[2]; \
			r[3] = data[3]; \
			v4_random_math_init(code, height,cpuMiner.type); \
		};

#define VARIANT4_RANDOM_MATH(a, b, r, _b, _b1) \
		if (cpuMiner.variant == 4 && cpuMiner.type == WowneroCrypto ) { \
			if (sizeof(v4_reg) == sizeof(uint32_t)) \
				U64(b)[0] ^= (r[0] + r[1]) | ((uint64_t)(r[2] + r[3]) << 32); \
			else \
				U64(b)[0] ^= (r[0] + r[1]) ^ (r[2] + r[3]); \
			r[4] = ((v4_reg*)(a))[0]; \
			r[5] = ((v4_reg*)(a))[sizeof(uint64_t) / sizeof(v4_reg)]; \
			r[6] = ((v4_reg*)(_b))[0]; \
			r[7] = ((v4_reg*)(_b1))[0]; \
			v4_random_math(code, r); \
		} else if (cpuMiner.variant == 4 && cpuMiner.type == MoneroCrypto ) { \
		    uint64_t t[2]; \
		    memcpy(t, b, sizeof(uint64_t)); \
		    if (sizeof(v4_reg) == sizeof(uint32_t)) \
		      t[0] ^= (r[0] + r[1]) | ((uint64_t)(r[2] + r[3]) << 32); \
		    else \
		      t[0] ^= (r[0] + r[1]) ^ (r[2] + r[3]); \
		    memcpy(b, t, sizeof(uint64_t)); \
			r[4] = ((v4_reg*)(a))[0]; \
			r[5] = ((v4_reg*)(a))[sizeof(uint64_t) / sizeof(v4_reg)]; \
			r[6] = ((v4_reg*)(_b))[0]; \
			r[7] = ((v4_reg*)(_b1))[0]; \
			r[8] = ((v4_reg*)(_b1))[2]; \
		    v4_random_math(code, r); \
		    memcpy(t, a, sizeof(uint64_t) * 2); \
		    if (sizeof(v4_reg) == sizeof(uint32_t)) { \
		      t[0] ^= r[2] | ((uint64_t)(r[3]) << 32); \
		      t[1] ^= r[0] | ((uint64_t)(r[1]) << 32); \
		    } else { \
		      t[0] ^= r[2] ^ r[3]; \
		      t[1] ^= r[0] ^ r[1]; \
		    } \
		    memcpy(a, t, sizeof(uint64_t) * 2); \
		}


typedef struct {
	uint8_t hash_state[224]; 		// Need only 200, explicit align
	uint8_t* long_state;
	uint8_t ctx_info[24]; 			//Use some of the extra memory for flags
} cryptonight_ctx;

/**
 * @brief the hash function implementing CryptoNight, used for the Monero proof-of-work
 *
 * Computes the hash of <data> (which consists of <length> bytes), returning the
 * hash in <hash>.  The CryptoNight hash operates by first using Keccak 1600,
 * the 1600 bit variant of the Keccak hash used in SHA-3, to create a 200 byte
 * buffer of pseudorandom data by hashing the supplied data.  It then uses this
 * random data to fill a large 2MB buffer with pseudorandom data by iteratively
 * encrypting it using 10 rounds of AES per entry.  After this initialization,
 * it executes 524,288 rounds of mixing through the random 2MB buffer using
 * AES (typically provided in hardware on modern CPUs) and a 64 bit multiply.
 * Finally, it re-mixes this large buffer back into
 * the 200 byte "text" buffer, and then hashes this buffer using one of four
 * pseudorandomly selected hash functions (Blake, Groestl, JH, or Skein)
 * to populate the output.
 *
 * The 2MB buffer and choice of functions for mixing are designed to make the
 * algorithm "CPU-friendly" (and thus, reduce the advantage of GPU, FPGA,
 * or ASIC-based implementations):  the functions used are fast on modern
 * CPUs, and the 2MB size matches the typical amount of L3 cache available per
 * core on 2013-era CPUs.  When available, this implementation will use hardware
 * AES support on x86 CPUs.
 *
 * A diagram of the inner loop of this function can be found at
 * http://www.cs.cmu.edu/~dga/crypto/xmr/cryptonight.png
 *
 * @param data the data to hash
 * @param length the length in bytes of the data
 * @param hash a pointer to a buffer in which the final 256 bit hash will be stored
 */
bool cn_slow_hash(const void *data, size_t length,unsigned char *hash, CPUMiner &cpuMiner, int gpuIndex, uint64_t height) {
	RDATA_ALIGN16 uint8_t expandedKey[240]; 	// These buffers are aligned to use later with SSE functions

	uint8_t text[INIT_SIZE_BYTE];
	RDATA_ALIGN16 uint64_t a[2];
	RDATA_ALIGN16 uint64_t b[4];
	RDATA_ALIGN16 uint64_t c[2];
	__m128i _a, _b, _b1, _c;
	uint64_t hi, lo;

	size_t i, j;
	uint64_t *p = NULL;
	int isLight = cpuMiner.type == TurtleCrypto ? 2 : 1;
	oaes_ctx *aes_ctx = NULL;

	static void (* const extra_hashes[4])(const void *, size_t, char *) =
	{
		hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
	};

	// this isn't supposed to happen, but guard against it for now.
	if (cpuMiner.hp_state == nullptr)
		slow_hash_allocate_state(cpuMiner);

	uint8_t *php_state = cpuMiner.hp_state;

	// CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data.
	hash_process(&(cpuMiner.shs.hs), (const uint8_t *) data, length);
	memcpy(text, cpuMiner.shs.init, INIT_SIZE_BYTE);

	VARIANT1_INIT64();
	VARIANT2_INIT64();

	VARIANT4_RANDOM_MATH_INIT();

	/* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
	 * the 2MB large random access buffer.
	 */
#ifdef SOFT_AES
	aes_ctx = (oaes_ctx *) oaes_alloc();
	oaes_key_import_data(aes_ctx, cpuMiner.shs.hs.b, AES_KEY_SIZE);
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);

		memcpy(&cpuMiner.hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
	}
#else
	aes_expand_key(cpuMiner.shs.hs.b, expandedKey);
	for (i = 0; i < MEMORY / getMemFactor(cpuMiner.type) / INIT_SIZE_BYTE; i++) {
		aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);
		memcpy(&cpuMiner.hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
	}
#endif
	U64(a)[0] = U64(&cpuMiner.shs.k[0])[0] ^ U64(&cpuMiner.shs.k[32])[0];
	U64(a)[1] = U64(&cpuMiner.shs.k[0])[1] ^ U64(&cpuMiner.shs.k[32])[1];
	U64(b)[0] = U64(&cpuMiner.shs.k[16])[0] ^ U64(&cpuMiner.shs.k[48])[0];
	U64(b)[1] = U64(&cpuMiner.shs.k[16])[1] ^ U64(&cpuMiner.shs.k[48])[1];

	/* CryptoNight Step 3:  Bounce randomly 1,048,576 times (1<<20) through the mixing buffer,
	 * using 524,288 iterations of the following mixing function.  Each execution
	 * performs two reads and writes from the mixing buffer.
	 */
	_b = _mm_load_si128(R128(b));
	_b1 = _mm_load_si128(R128(b) + 1);
	// Two independent versions, one with AES, one without, to ensure that
	// the useAes test is only performed once, not every iteration.
	for (i = 0; i < ITER / getIterationFactor(cpuMiner.type) / 2; i++) {
		pre_aes();
#ifdef SOFT_AES
		aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
#else
		_c = _mm_aesenc_si128(_c, _a);
#endif
		post_aes();
	}

	/* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
	 * of AES encryption to mix the random data back into the 'text' buffer.  'text'
	 * was originally created with the output of Keccak1600. */
	memcpy(text, cpuMiner.shs.init, INIT_SIZE_BYTE);
#ifdef SOFT_AES
	oaes_key_import_data(aes_ctx, &cpuMiner.shs.hs.b[32], AES_KEY_SIZE);
	for (i = 0; i < MEMORY / getMemFactor(cpuMiner.type) / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j * AES_BLOCK_SIZE], &php_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
			aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
		}
	}
#else
	aes_expand_key(&cpuMiner.shs.hs.b[32], expandedKey);
	for (i = 0; i < MEMORY / getMemFactor(cpuMiner.type) / INIT_SIZE_BYTE; i++) {
		// add the xor to the pseudo round
		aes_pseudo_round_xor(text, text, expandedKey, &php_state[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
	}
#endif

	/* CryptoNight Step 5:  Apply Keccak to the state again, and then
	 * use the resulting data to select which of four finalizer
	 * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
	 * Use this hash to squeeze the state array down
	 * to the final 256 bit hash output.
	 */
	memcpy(cpuMiner.shs.init, text, INIT_SIZE_BYTE);
	hash_permutation(&cpuMiner.shs.hs);
	extra_hashes[cpuMiner.shs.hs.b[0] & 3](&cpuMiner.shs.hs.b, 200, (char *)hash);

	const uint64_t hashVal = *(uint64_t*)(hash+24);

	if (hashVal > getTarget()) {
		if (getCurrentPool() == 0) {
			char tmp[256];
			sprintf(tmp,"GPU #%d",gpuIndex);
			error("Hash rejected on ",tmp);
			incBadHash(gpuIndex);
		}
		return false;
	} else
		incGoodHash(gpuIndex);
	return (hashVal < getTarget());
}
