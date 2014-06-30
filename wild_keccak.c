// Modified for CPUminer by Archit

#include "cpuminer-config.h"
#include "miner.h"
#include "wild_keccak/KeccakNISTInterface.h"


void wild_keccak_dbl_opt(const uint32_t *in, uint32_t *md, size_t inlen, uint64_t* pscr, uint64_t scr_sz)
{      
	Hash(256, (const uint8_t*)in, inlen*8, (const uint8_t*)md, pscr, scr_sz);
    Hash(256, (const uint8_t*)md, 32*8, (const uint8_t*)md, pscr, scr_sz);
}

void wildkeccak_hash(void* output, const void* input, size_t len, uint64_t* scratchpad, uint64_t scratchsize) {
	wild_keccak_dbl_opt((const uint32_t*)input, (const uint32_t*)output, 81, scratchpad, scratchsize);
}

int scanhash_wild_keccak(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done, uint64_t* scratchpad, uint64_t scratchsize) {
    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 1);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    uint32_t hash[32];
    
	do {
            *nonceptr = ++n;
            wild_keccak_dbl_opt(pdata, hash, 81, scratchpad, scratchsize);
            if (unlikely(hash[7] < ptarget[7])) {
                *hashes_done = n - first_nonce + 1;
                free(ctx);
                return true;
            }
        } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
    }
    
    *hashes_done = n - first_nonce + 1;
    return 0;
}
