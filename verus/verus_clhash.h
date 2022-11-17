#include "SSE2NEON.h"


uint64_t verusclhash_port2_1(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *  __restrict fixrand, uint32_t * __restrict fixrandex);
uint64_t verusclhash_port2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *  __restrict fixrand, uint32_t * __restrict fixrandex);
void *alloc_aligned_buffer(uint64_t bufSize);

// special high speed hasher for VerusHash 2.0
struct verusclhasher {
    uint64_t keySizeInBytes;
    uint64_t keyMask;
    uint64_t (*verusclhashfunction)(void * random, const unsigned char buf[64], uint64_t keyMask, __m128i **pMoveScratch);
    __m128i (*verusinternalclhashfunction)(__m128i *randomsource, const __m128i buf[4], uint64_t keyMask, __m128i **pMoveScratch);

    static inline uint64_t keymask(uint64_t keysize)
    {
        int i = 0;
        while (keysize >>= 1)
        {
            i++;
        }
        return i ? (((uint64_t)1) << i) - 1 : 0;
    }
};
