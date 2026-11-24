#include "../source/alac.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
int main(int, char** argv) {
    alac::Config c; c.frameLength = 352;
    static alac::Decoder d; d.init(c);
    FILE* f = fopen(argv[1], "rb"); uint32_t size; static uint8_t buf[32768]; static int16_t out[4096 * 2];
    srand(1); long runs = 0, errs = 0;
    std::vector<std::vector<uint8_t>> pk;
    while (fread(&size, 4, 1, f) == 1 && size <= 20000) { std::vector<uint8_t> v(size); fread(v.data(), 1, size, f); pk.push_back(v); }
    for (auto& v : pk) for (int t = 0; t < 40; t++) {
        std::vector<uint8_t> w = v;
        const int mode = t % 4;
        if (mode == 0) { for (int k = 0; k < 4 && !w.empty(); k++) w[rand() % w.size()] ^= uint8_t(1 << (rand() % 8)); }
        else if (mode == 1) w.resize(rand() % (w.size() + 1));
        else if (mode == 2) { for (auto& b : w) b = uint8_t(rand()); }
        else { for (size_t k = 0; k < w.size() && k < 16; k++) w[k] = uint8_t(rand()); }
        runs++; if (d.decode(w.data(), w.size(), out) < 0) errs++;
    }
    printf("%ld corrupted packets decoded without a crash (%ld refused)\n", runs, errs);
}
