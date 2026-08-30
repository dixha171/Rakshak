#ifndef FRAME_ALLOC_H
#define FRAME_ALLOC_H

#include <stddef.h>

/*
 * Allocates a radar frame buffer sized for `num_samples` samples of
 * `sample_size` bytes each.
 *
 * NOTE (CWE-190): the reference implementation multiplies
 * num_samples * sample_size using `int` arithmetic with no overflow
 * check before passing the result to malloc(), so a large
 * `num_samples` wraps around to a small/negative value, causing a
 * dangerously undersized allocation relative to what callers believe
 * they received.
 */
void *frame_alloc(int num_samples, int sample_size);

#endif /* FRAME_ALLOC_H */
