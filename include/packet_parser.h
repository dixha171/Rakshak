#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>

#define PACKET_BUF_SIZE 256

typedef struct {
    unsigned char payload[PACKET_BUF_SIZE];
    size_t payload_len;
} PacketBuffer;

/*
 * Decodes a tactical packet stream frame into `out`.
 * `raw` is a length-prefixed frame: [2-byte LE length][payload bytes...]
 * Returns 0 on success, -1 on error.
 *
 * NOTE (CWE-119): the reference implementation trusts the length field
 * from the wire and copies `len` bytes into a fixed 256-byte buffer
 * without checking `len <= PACKET_BUF_SIZE`, permitting a buffer
 * overflow on crafted input.
 */
int decode_packet(const unsigned char *raw, size_t raw_len, PacketBuffer *out);

#endif /* PACKET_PARSER_H */
