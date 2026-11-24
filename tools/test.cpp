#include "../source/alac.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
int main(int argc, char** argv) {
    // args: packets.bin ref.pcm frame pb mb kb
    alac::Config c; c.frameLength = atoi(argv[3]); c.pb = atoi(argv[4]); c.mb = atoi(argv[5]); c.kb = atoi(argv[6]);
    static alac::Decoder d;
    if (!d.init(c)) { puts("init failed"); return 2; }
    FILE* f = fopen(argv[1], "rb"); FILE* r = fopen(argv[2], "rb");
    std::vector<int16_t> out(c.frameLength * 2), ref(c.frameLength * 2);
    long frames = 0, bad = 0, packets = 0, firstBad = -1;
    uint32_t size;
    static uint8_t buf[32768];
    while (fread(&size, 4, 1, f) == 1) {
        if (fread(buf, 1, size, f) != size) break;
        packets++;
        const int n = d.decode(buf, size, out.data());
        if (n < 0) { printf("packet %ld: decode error\n", packets); bad++; if (firstBad < 0) firstBad = packets; continue; }
        const size_t got = fread(ref.data(), 4, size_t(n), r);
        if (got != size_t(n)) { printf("reference ended early at packet %ld\n", packets); break; }
        for (int i = 0; i < n * 2; i++) if (out[i] != ref[i]) { if (firstBad < 0) { firstBad = packets; printf("packet %ld sample %d: got %d want %d\n", packets, i, out[i], ref[i]); } bad++; break; }
        frames += n;
    }
    printf("%ld packets, %ld frames, %ld bad packets\n", packets, frames, bad);
    return bad ? 1 : 0;
}
