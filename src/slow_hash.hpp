#ifndef SLOW_HASH_HPP_
#define SLOW_HASH_HPP_


#define MEMORY         (1 << 21)
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))

union hash_state {
  uint8_t b[200];
  uint64_t w[25];
};

union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};

typedef struct CPUMiner {
	uint8_t *hp_state;
	int variant;
	bool hp_allocated;
	bool isLight;
	CryptoType type;
	cn_slow_hash_state shs;
} CPUMiner;


bool cn_slow_hash(const void *data, size_t length,unsigned char *hash, CPUMiner &cpuMiner, int gpuId, uint64_t height);
int v4_random_math_init(struct V4_Instruction* code, const uint64_t height);

#endif /* SLOW_HASH_HPP_ */
