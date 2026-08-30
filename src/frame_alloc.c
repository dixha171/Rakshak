#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/frame_alloc.h"

/*
 * VULNERABLE (CWE-190): `num_samples * sample_size` is computed in
 * signed 32-bit int arithmetic with no bounds/overflow check. Crafted
 * large inputs wrap around, so malloc() receives a tiny (or negative,
 * UB-then-huge-as-size_t) size while callers proceed to write
 * num_samples * sample_size bytes into the undersized buffer.
 */
void *frame_alloc(int num_samples, int sample_size) {
    if (num_samples <= 0 || sample_size <= 0) {
        return NULL;
    }
    int total = num_samples * sample_size; /* BUG: no overflow check */
    void *buf = malloc((size_t)total);
    return buf;
}

#ifdef FRAME_ALLOC_STANDALONE
int main(void) {
    /* Trigger: num_samples * sample_size overflows INT_MAX and wraps
       to a small positive number, e.g. 65536 * 65537 overflows. */
    int num_samples = 65536;
    int sample_size = 65537;
    void *buf = frame_alloc(num_samples, sample_size);
    if (!buf) {
        printf("alloc failed (unexpected for this harness)\n");
        return 1;
    }
    /* Caller believes it got num_samples*sample_size bytes and writes
       accordingly -> heap buffer overflow on the undersized chunk. */
    size_t intended_len = (size_t)num_samples * (size_t)sample_size;
    memset(buf, 0x41, intended_len > (1u << 20) ? (1u << 20) : intended_len);
    printf("wrote into frame buffer, intended_len=%zu\n", intended_len);
    free(buf);
    return 0;
}
#endif
