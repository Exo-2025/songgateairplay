/*
 * Songate AirPlay receiver (background) · alac.hpp
 * An Apple Lossless (ALAC) decoder for what AirPlay 1 sends: 16-bit, 44.1 kHz, stereo, one frame per packet (352 samples).
 * Written from the format's published structure for this receiver (the app uses FFmpeg for it, which does not fit in a sysmodule);
 * checked bit for bit against FFmpeg's decoder on the host (airplay-bg/tools/alactest). Header only, no allocation, no exceptions.
 *
 * What it does not do: mono or more than 2 channels, bit depths other than 16 and the "shifted" low bytes of 24-bit: they return -1.
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace alac {

struct Config {
    uint32_t frameLength = 352;   // samples per packet (the largest allowed: kMaxFrame)
    uint8_t bitDepth = 16, pb = 40, mb = 10, kb = 14, channels = 2;
    uint16_t maxRun = 255;
};

class Decoder {
public:
    static constexpr uint32_t kMaxFrame = 4096;
    static constexpr size_t kMaxPacket = 16512;   // (an uncompressed 4096-sample frame; AirPlay's are under 2 KB)

    bool init(const Config& c) {
        if (c.bitDepth != 16 || c.channels != 2 || c.frameLength < 1 || c.frameLength > kMaxFrame || c.kb < 1 || c.kb > 24) return false;
        c_ = c;
        ok_ = true;
        return true;
    }

    /** One (already decrypted) packet in; interleaved left, right 16-bit out (room for frameLength frames). Frames decoded, or -1. */
    int decode(const uint8_t* in, size_t size, int16_t* out) {
        if (!ok_ || !in || size < 1 || size > kMaxPacket) return -1;
        memcpy(buf_, in, size);
        memset(buf_ + size, 0, 16);   // the reader may look up to 8 bytes past the end
        limit_ = size * 8;
        pos_ = 0;
        int frames = -1;
        for (int elements = 0; elements < 4; elements++) {
            if (left() < 3) return -1;
            const unsigned tag = read(3);
            if (tag == 7) return pos_ <= limit_ ? frames : -1;   // END
            if (tag != 1 || frames >= 0) return -1;              // only one stereo pair (CPE) per packet
            frames = element(out);
            if (frames < 0) return -1;
        }
        return -1;
    }

private:
    Config c_;
    bool ok_ = false;
    uint8_t buf_[kMaxPacket + 16];
    size_t limit_ = 0, pos_ = 0;
    int32_t u_[kMaxFrame], v_[kMaxFrame], err_[kMaxFrame];

    // ---- bits, most significant first
    size_t left() const { return pos_ <= limit_ ? limit_ - pos_ : 0; }
    uint32_t peek(int n) const {   // 0 <= n <= 32
        if (n == 0) return 0;
        const size_t b = pos_ >> 3;
        uint64_t w = 0;
        for (int i = 0; i < 8; i++) w = (w << 8) | buf_[b + size_t(i)];
        w <<= (pos_ & 7);
        return uint32_t(w >> (64 - n));
    }
    uint32_t read(int n) { const uint32_t v = peek(n); pos_ += size_t(n); return v; }
    unsigned bit() { return read(1); }

    static int32_t sext(int32_t v, int bits) { const int s = 32 - bits; return int32_t(uint32_t(v) << s) >> s; }
    static int32_t add(int32_t a, int32_t b) { return int32_t(uint32_t(a) + uint32_t(b)); }   // wraps, as the format's maths does
    static int32_t sub(int32_t a, int32_t b) { return int32_t(uint32_t(a) - uint32_t(b)); }
    static int sign(int32_t v) { return v < 0 ? -1 : v > 0 ? 1 : 0; }
    static int log2u(uint32_t x) { return x ? 31 - __builtin_clz(x) : 0; }

    /** One Golomb-Rice number: a unary prefix (up to 9 ones), then k bits; a long prefix means "the number follows in `bps` bits". */
    uint32_t scalar(int k, int bps) {
        uint32_t x = 0;
        while (x < 9 && bit()) x++;
        if (x > 8) return read(bps);
        if (k != 1) {
            const uint32_t extra = peek(k);
            x = (x << k) - x;   // x * (2^k - 1)
            if (extra > 1) { x += extra - 1; pos_ += size_t(k); }
            else pos_ += size_t(k - 1);
        }
        return x;
    }

    bool rice(int32_t* out, int n, int bps, int pbMul) {
        uint32_t history = c_.mb;
        uint32_t signMod = 0;
        int i = 0;
        while (i < n) {
            if (left() == 0) return false;
            int k = log2u((history >> 9) + 3);
            if (k > c_.kb) k = c_.kb;
            uint32_t x = scalar(k, bps) + signMod;
            signMod = 0;
            out[i++] = int32_t(x >> 1) ^ -int32_t(x & 1);
            if (x > 0xffff) history = 0xffff;
            else history += x * uint32_t(pbMul) - ((history * uint32_t(pbMul)) >> 9);
            if (history < 128 && i < n) {   // a run of zeros
                k = 7 - log2u(history) + int((history + 16) >> 6);
                if (k > c_.kb) k = c_.kb;
                if (k < 1) k = 1;
                uint32_t run = scalar(k, 16);
                if (run > 0) {
                    if (run > uint32_t(n - i)) return false;   // (a run may end exactly at the frame's end)
                    for (uint32_t j = 0; j < run; j++) out[i++] = 0;
                }
                if (run <= 0xffff) signMod = 1;
                history = 0;
            }
        }
        return left() > 0 || pos_ <= limit_;
    }

    /** The predictor. coefs are in stream order (the first is for the latest sample); they adapt as it goes, so it takes a copy. */
    static void predict(const int32_t* e, int32_t* o, int n, int bps, int16_t* coefs, int order, int quant) {
        o[0] = e[0];
        if (n <= 1) return;
        if (order == 0) { if (o != e) memcpy(o + 1, e + 1, size_t(n - 1) * 4); return; }
        if (order == 31) {
            for (int i = 1; i < n; i++) o[i] = sext(add(o[i - 1], e[i]), bps);
            return;
        }
        int i = 1;
        for (; i <= order && i < n; i++) o[i] = sext(add(o[i - 1], e[i]), bps);
        const int32_t round = quant > 0 ? (1 << (quant - 1)) : 0;
        for (; i < n; i++) {
            const int32_t top = o[i - order - 1];
            uint32_t sum = 0;
            for (int k = 0; k < order; k++) sum += (uint32_t(o[i - 1 - k]) - uint32_t(top)) * uint32_t(int32_t(coefs[k]));
            o[i] = sext(add(add(int32_t(sum + uint32_t(round)) >> quant, top), e[i]), bps);
            int32_t ev = e[i];
            const int es = sign(ev);
            if (es) {   // the coefficients follow the error, the oldest sample's first
                for (int j = 0; j < order && (es > 0 ? ev > 0 : ev < 0); j++) {
                    const int k = order - 1 - j;
                    int32_t d = sub(top, o[i - 1 - k]);
                    const int sg = sign(d) * es;
                    coefs[k] = int16_t(coefs[k] - sg);
                    if (sg < 0) d = sub(0, d);
                    ev = sub(ev, int32_t(uint32_t(d >> quant) * uint32_t(j + 1)));
                }
            }
        }
    }

    int element(int16_t* out) {
        read(4);    // the element's instance tag
        read(12);   // unused
        const bool hasSize = bit();
        const unsigned shifted = read(2);
        const bool escape = bit();
        if (shifted != 0) return -1;
        uint32_t n = c_.frameLength;
        if (hasSize) { n = read(32); if (n < 1 || n > c_.frameLength) return -1; }
        const int bps = 16 + 1;   // a stereo pair's channels carry one more bit
        int mixBits = 0, mixRes = 0;
        if (!escape) {
            mixBits = int(read(8));
            mixRes = int8_t(read(8));
            if (mixBits > 31) return -1;
            int mode[2], quant[2], order[2], pbMul[2];
            int16_t coefs[2][32];
            for (int ch = 0; ch < 2; ch++) {
                mode[ch] = int(read(4));
                quant[ch] = int(read(4));
                pbMul[ch] = int(read(3));
                order[ch] = int(read(5));
                for (int i = 0; i < order[ch] && i < 32; i++) coefs[ch][i] = int16_t(read(16));
                if (left() == 0) return -1;
            }
            int32_t* dst[2] = { u_, v_ };
            for (int ch = 0; ch < 2; ch++) {
                if (!rice(err_, int(n), bps, (c_.pb * pbMul[ch]) / 4)) return -1;
                if (mode[ch] != 0) predict(err_, err_, int(n), bps, nullptr, 31, 0);   // the two-pass mode: a first order pass first
                predict(err_, dst[ch], int(n), bps, coefs[ch], order[ch], quant[ch]);
            }
        } else {
            for (uint32_t i = 0; i < n; i++) {   // not compressed: the samples as they are
                if (left() < 32) return -1;
                u_[i] = sext(int32_t(read(16)), 16);
                v_[i] = sext(int32_t(read(16)), 16);
            }
        }
        if (pos_ > limit_) return -1;
        if (mixRes != 0) {   // matrixed stereo: the channels carry a mid and a difference
            for (uint32_t i = 0; i < n; i++) {
                const int32_t l = sub(add(u_[i], v_[i]), int32_t((int64_t(mixRes) * v_[i]) >> mixBits));
                out[i * 2] = int16_t(l);
                out[i * 2 + 1] = int16_t(sub(l, v_[i]));
            }
        } else {
            for (uint32_t i = 0; i < n; i++) { out[i * 2] = int16_t(u_[i]); out[i * 2 + 1] = int16_t(v_[i]); }
        }
        return int(n);
    }
};

}  // namespace alac
