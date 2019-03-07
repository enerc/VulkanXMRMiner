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
	int  memFactor;
	bool debugNetwork;
	CryptoType type;
	cn_slow_hash_state shs;
} CPUMiner;


typedef void OAES_CTX;
typedef uint16_t OAES_OPTION;
#define OAES_VERSION "0.8.1"
#define OAES_BLOCK_SIZE 16
#define OAES_RKEY_LEN 4
#define OAES_COL_LEN 4
#define OAES_ROUND_BASE 7
// no option
#define OAES_OPTION_NONE 0
// enable ECB mode, disable CBC mode
#define OAES_OPTION_ECB 1
// enable CBC mode, disable ECB mode
// value is optional, may pass uint8_t iv[OAES_BLOCK_SIZE] to specify
// the value of the initialization vector, iv
#define OAES_OPTION_CBC 2

typedef enum {
	OAES_RET_FIRST = 0,
	OAES_RET_SUCCESS = 0,
	OAES_RET_UNKNOWN,
	OAES_RET_ARG1,
	OAES_RET_ARG2,
	OAES_RET_ARG3,
	OAES_RET_ARG4,
	OAES_RET_ARG5,
	OAES_RET_NOKEY,
	OAES_RET_MEM,
	OAES_RET_BUF,
	OAES_RET_HEADER,
	OAES_RET_COUNT
} OAES_RET;

typedef struct _oaes_key {
	size_t data_len;
	uint8_t *data;
	size_t exp_data_len;
	uint8_t *exp_data;
	size_t num_keys;
	size_t key_base;
} oaes_key;

typedef struct _oaes_ctx
{
#ifdef OAES_HAVE_ISAAC
  randctx * rctx;
#endif // OAES_HAVE_ISAAC

#ifdef OAES_DEBUG
  oaes_step_cb step_cb;
#endif // OAES_DEBUG

  oaes_key * key;
  OAES_OPTION options;
  uint8_t iv[OAES_BLOCK_SIZE];
} oaes_ctx;

bool cn_slow_hash(const void *data, size_t length,unsigned char *hash, CPUMiner &cpuMiner, int gpuId, uint64_t height);
int v4_random_math_init(struct V4_Instruction* code, const uint64_t height,CryptoType cryptoType);
void destroyCPUScratchPad(CPUMiner &);
#endif /* SLOW_HASH_HPP_ */
