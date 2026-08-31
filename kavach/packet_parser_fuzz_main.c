#include <stdio.h>
#include "../../include/packet_parser.h"

/*
 * Fuzzing harness for decode_packet().
 *
 * packet_parser.c's own PACKET_PARSER_STANDALONE main() always replays
 * one fixed, hardcoded overflow example — it never reads external input,
 * so it's useless for fuzzing (every run would "find" the identical
 * crash regardless of what the fuzzer generated). This harness instead
 * reads the fuzzer-supplied bytes from stdin and hands them directly to
 * decode_packet() as the raw wire frame, so the actual bytes being
 * mutated are what determines whether it crashes.
 *
 * Built WITHOUT defining PACKET_PARSER_STANDALONE, so packet_parser.c's
 * own main() is compiled out and there's no symbol clash with this one.
 */
int main(void) {
    static unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), stdin);

    PacketBuffer pb;
    decode_packet(buf, n, &pb);

    return 0;
}
