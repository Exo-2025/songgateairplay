/*
 * Songate AirPlay receiver (background) · audio.hpp
 * The sound out: a ring of 48 kHz stereo 16-bit frames that the receiver fills (from 44.1 kHz decoded audio, resampled) and a thread
 * that hands it to the console's audio output (audout), as the background player does (sysmodule/source/engine.cpp).
 *
 * It opens audout only while a stream plays, so nothing is held while idle (audout's sessions are few and shared). The sound starts when
 * half a second of it is in the ring and, on running dry, waits for that much again rather than crackling.
 */
#pragma once
#include <switch.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

class AudioOut {
public:
    static constexpr unsigned Ring = 1u << 17;                 // frames: 2.7 s
    static constexpr unsigned Prime = 24000;                   // frames in the ring before the sound starts (0.5 s)
    static constexpr unsigned TooFull = 96000;                 // more than this (2 s) and the sender's clock is ahead of ours: trimmed to Prime

    /** Allocates the ring and starts the thread. False if there is no memory or the thread cannot start. */
    bool start() {
        if (on_) return true;
        ring_ = new (std::nothrow) int16_t[size_t(Ring) * 2];
        if (!ring_) return false;
        memset(ring_, 0, size_t(Ring) * 4);
        w_ = r_ = 0;
        quit_ = false;
        primed_ = false;
        flush_ = trim_ = false;
        underruns_ = dropped_ = openFails_ = 0;
        opened_ = false;
        pos_ = -(int64_t(1) << 32);
        prevL_ = prevR_ = 0;
        if (R_FAILED(threadCreate(&th_, &AudioOut::entry, this, nullptr, 0x6000, 0x2B, -2))) { delete[] ring_; ring_ = nullptr; return false; }
        if (R_FAILED(threadStart(&th_))) { threadClose(&th_); delete[] ring_; ring_ = nullptr; return false; }
        on_ = true;
        return true;
    }

    /** Ends the thread (audout is closed by it) and frees the ring. */
    void stop() {
        if (!on_) return;
        quit_ = true;
        threadWaitForExit(&th_);
        threadClose(&th_);
        delete[] ring_;
        ring_ = nullptr;
        on_ = false;
    }

    bool running() const { return on_; }
    void setGain(float g) { gain_.store(g, std::memory_order_relaxed); }
    unsigned fill() const { return w_.load(std::memory_order_acquire) - r_.load(std::memory_order_acquire); }
    unsigned underruns() const { return underruns_; }
    unsigned dropped() const { return dropped_; }
    bool opened() const { return opened_; }                  // audout is open and the sound can come out
    unsigned openFailures() const { return openFails_; }
    /** What is waiting, dropped and sounding again from the next packet (a FLUSH: a skip or a seek). */
    void flush() { flush_.store(true, std::memory_order_release); }

    /** 44.1 kHz stereo frames in (interleaved L, R): resampled to 48 kHz by linear interpolation into the ring. */
    void push44(const int16_t* in, int n) {
        if (!on_ || n <= 0) return;
        unsigned w = w_.load(std::memory_order_relaxed);
        const unsigned fillNow = w - r_.load(std::memory_order_acquire);
        const unsigned worst = unsigned(n) * 12 / 10 + 4;
        if (Ring - fillNow < worst) { dropped_++; return; }
        if (fillNow > TooFull) trim_.store(true, std::memory_order_release);
        constexpr int64_t step = (int64_t(44100) << 32) / 48000;   // input frames per output frame, 32.32
        // The input is x[-1] (the last frame of the block before) then x[0..n-1]. pos_ is where the next output falls, in those terms.
        auto at = [&](int i, int ch) -> int32_t { return i < 0 ? (ch ? prevR_ : prevL_) : in[i * 2 + ch]; };
        while ((pos_ >> 32) <= int64_t(n) - 2) {
            const int i = int(pos_ >> 32);
            const int32_t f = int32_t((pos_ & 0xFFFFFFFFll) >> 16);   // 0..65535
            for (int ch = 0; ch < 2; ch++) {
                const int32_t a = at(i, ch), b = at(i + 1, ch);
                ring_[size_t(w & (Ring - 1)) * 2 + size_t(ch)] = int16_t(a + int32_t((int64_t(b - a) * f) >> 16));
            }
            w++;
            pos_ += step;
        }
        pos_ -= int64_t(n) << 32;
        prevL_ = in[(n - 1) * 2];
        prevR_ = in[(n - 1) * 2 + 1];
        w_.store(w, std::memory_order_release);
    }

    /** A lost packet: this many 48 kHz frames of silence, to keep the rest in time. */
    void pushSilence(int frames) {
        if (!on_ || frames <= 0) return;
        unsigned w = w_.load(std::memory_order_relaxed);
        if (Ring - (w - r_.load(std::memory_order_acquire)) < unsigned(frames)) { dropped_++; return; }
        for (int i = 0; i < frames; i++, w++) { ring_[size_t(w & (Ring - 1)) * 2] = 0; ring_[size_t(w & (Ring - 1)) * 2 + 1] = 0; }
        w_.store(w, std::memory_order_release);
    }

private:
    static constexpr int BufFrames = 1024, BufCount = 4;   // 4 × 21 ms in flight

    static void entry(void* self) { static_cast<AudioOut*>(self)->run(); }

    void run() {
        const size_t bytes = (size_t(BufFrames) * 4 + 0xFFF) & ~size_t(0xFFF);
        AudioOutBuffer bufs[BufCount] = {};
        bool busy[BufCount] = {};
        for (auto& b : bufs) {
            b.buffer = aligned_alloc(0x1000, bytes);
            b.buffer_size = bytes;
            if (!b.buffer) { quit_ = true; }
        }
        bool open = false;
        auto release = [&](AudioOutBuffer* rel) { for (int i = 0; i < BufCount; i++) if (rel == &bufs[i]) busy[i] = false; };
        auto reclaim = [&] {
            for (int k = 0; k < BufCount; k++) {
                AudioOutBuffer* rel = nullptr;
                u32 cnt = 0;
                if (R_FAILED(audoutGetReleasedAudioOutBuffer(&rel, &cnt)) || cnt == 0 || !rel) break;
                release(rel);
            }
        };
        while (!quit_.load(std::memory_order_relaxed)) {
            if (!open) {   // audout may not be up yet, or may need opening again after sleep
                open = R_SUCCEEDED(audoutInitialize());
                if (open && R_FAILED(audoutStartAudioOut())) { audoutExit(); open = false; }
                if (!open) { openFails_++; svcSleepThread(200'000'000ull); continue; }
                opened_ = true;
                for (bool& b : busy) b = false;
            }
            reclaim();
            unsigned r = r_.load(std::memory_order_relaxed);
            const unsigned w = w_.load(std::memory_order_acquire);
            if (flush_.exchange(false)) { r = w; r_.store(r, std::memory_order_release); primed_ = false; }
            if (trim_.exchange(false) && w - r > Prime) { r = w - Prime; r_.store(r, std::memory_order_release); }
            if (!primed_ && w - r >= Prime) primed_ = true;

            int slot = -1;
            for (int i = 0; i < BufCount; i++) if (!busy[i]) { slot = i; break; }
            if (slot >= 0 && primed_) {
                const unsigned have = w - r;
                const int n = int(have < unsigned(BufFrames) ? have : unsigned(BufFrames));
                AudioOutBuffer& b = bufs[slot];
                int16_t* o = static_cast<int16_t*>(b.buffer);
                const int32_t g = int32_t(gain_.load(std::memory_order_relaxed) * 32768.f);   // 0..32768: the product fits 32 bits
                for (int i = 0; i < n; i++, r++) {
                    o[i * 2] = int16_t((int32_t(ring_[size_t(r & (Ring - 1)) * 2]) * g) >> 15);
                    o[i * 2 + 1] = int16_t((int32_t(ring_[size_t(r & (Ring - 1)) * 2 + 1]) * g) >> 15);
                }
                r_.store(r, std::memory_order_release);
                if (n < BufFrames) {   // ran dry: the rest is silence, and the sound waits until half a second is in again
                    memset(o + size_t(n) * 2, 0, size_t(BufFrames - n) * 4);
                    primed_ = false;
                    underruns_++;
                }
                b.data_size = size_t(BufFrames) * 4;
                b.data_offset = 0;
                armDCacheFlush(b.buffer, b.data_size);
                if (R_SUCCEEDED(audoutAppendAudioOutBuffer(&b))) busy[slot] = true;
                else { audoutStopAudioOut(); audoutExit(); open = false; }
                continue;
            }
            bool any = false;
            for (bool b : busy) any |= b;
            if (any) {
                AudioOutBuffer* rel = nullptr;
                u32 cnt = 0;
                if (R_SUCCEEDED(audoutWaitPlayFinish(&rel, &cnt, 10'000'000ull)) && cnt && rel) release(rel);
            } else {
                svcSleepThread(5'000'000ull);
            }
        }
        opened_ = false;
        if (open) { audoutStopAudioOut(); audoutExit(); }
        for (auto& b : bufs) free(b.buffer);
    }

    int16_t* ring_ = nullptr;
    std::atomic<unsigned> w_{ 0 }, r_{ 0 };
    std::atomic<bool> quit_{ false }, primed_{ false }, flush_{ false }, trim_{ false };
    std::atomic<float> gain_{ 1.f };
    std::atomic<unsigned> underruns_{ 0 }, dropped_{ 0 }, openFails_{ 0 };
    std::atomic<bool> opened_{ false };
    Thread th_{};
    bool on_ = false;
    int64_t pos_ = -(int64_t(1) << 32);   // the producer's (main thread's) resampler state
    int16_t prevL_ = 0, prevR_ = 0;
};
