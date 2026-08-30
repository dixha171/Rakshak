#include <string.h>
#include <stdio.h>
#include "../include/packet_parser.h"

/*
 * VULNERABLE (CWE-119 / CWE-120): the length field is read directly from
 * the wire and used as the copy size for memcpy() into a fixed-size
 * stack/struct buffer, with no upper-bounds check against
 * PACKET_BUF_SIZE. A crafted `raw` frame with len > 256 overflows
 * `out->payload`.
 */
int decode_packet(const unsigned char *raw, size_t raw_len, PacketBuffer *out) {
    if (!raw || !out || raw_len < 2) {
        return -1;
    }

    unsigned short len = (unsigned short)(raw[0] | (raw[1] << 8));

    if (raw_len < (size_t)(2 + len)) {
        /* not enough bytes on the wire for the declared length */
        return -1;
    }

    /* BUG: missing `if (len > PACKET_BUF_SIZE) return -1;` check here */
    memcpy(out->payload, raw + 2, len);
    out->payload_len = len;

    return 0;
}

#ifdef PACKET_PARSER_STANDALONE
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    PacketBuffer pb;
    unsigned char frame[512];
    /* Example crafted overflow trigger: length = 400, payload = 400 bytes */
    frame[0] = 0x90; /* 0x0190 = 400 */
    frame[1] = 0x01;
    memset(frame + 2, 0x41, 400);
    int rc = decode_packet(frame, sizeof(frame), &pb);
    printf("decode_packet rc=%d payload_len=%zu\n", rc, pb.payload_len);
    return 0;
}
#endif
