/*
 * Songate AirPlay receiver (background) · main.cpp
 *
 * STEP 1 of a separate sysmodule that lets an iPhone find this console in its AirPlay list and open a stream while Songate (the app)
 * is closed. It does only the "handshake" half of an AirPlay 1 receiver, ported from source/airplay.cpp:
 *
 *   - announces itself over mDNS (_raop._tcp) and answers iOS's questions,
 *   - answers iOS's RTSP (OPTIONS with the Apple-Challenge signed by the AirPort key, ANNOUNCE, SETUP, RECORD, FLUSH, TEARDOWN,
 *     SET_PARAMETER), and unwraps the stream's AES key to check it could be played,
 *   - receives the RTP packets and only COUNTS them (no decoding, no sound yet: steps 2 and 3),
 *   - survives the console's sleep: after a wake (or a changed IP address) it closes everything and announces again.
 *
 * It runs next to the app without clashing: its own title id (4200000047464E59), its own ports (RTSP 5006, media 6010-6012) and its own
 * name in the AirPlay list ("Songate BG on <console>"). Everything it does is written to sdmc:/config/songate-nx/airplay-bg.log.
 *
 * Not started at boot: there is no flags/boot2.flag in this build on purpose (see BUILD.md).
 */
#include <switch.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/rsa.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "airport_key.inc"   // ../source: iOS sends nothing to a receiver that cannot sign with it. Never printed or logged.

// ---- the process: heap, applet type, services ----------------------------------------------------------------------------------

#define HEAP_SIZE 0x200000   // 2 MiB: mbedtls' RSA, the sockets' transfer memory (about 300 KB), strings. (Step 2 will decide what audio needs.)

extern "C" {

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;   // as every sysmodule keeps: fsp-srv's sessions are few and shared by the whole system

void __libnx_initheap(void) {
    static u8 heap[HEAP_SIZE];
    extern void* fake_heap_start;
    extern void* fake_heap_end;
    fake_heap_start = heap;
    fake_heap_end = heap + sizeof heap;
}

void __appInit(void) {
    if (R_FAILED(smInitialize())) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));
    if (R_SUCCEEDED(setsysInitialize())) {
        SetSysFirmwareVersion fw;
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw))) hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        // (setsys stays open: the console's name is read in main)
    }
    if (R_FAILED(fsInitialize())) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));
    fsdevMountSdmc();
    timeInitialize();   // the wall clock: a jump of it that the system tick does not show means the console slept
    // The sockets are opened in main (a failure there is logged and retried, not a crash at boot).
}

void __appExit(void) {
    socketExit();
    timeExit();
    fsdevUnmountAll();
    fsExit();
    setsysExit();
    smExit();
}

}  // extern "C"

namespace {

constexpr int kRtspPort = 5006, kAudio = 6010, kControl = 6011, kTiming = 6012;   // (the app's own are 5005 and 6000-6002)
constexpr size_t kMaxHead = 8 * 1024, kMaxBody = 1024 * 1024;   // a cover comes in one SET_PARAMETER; beyond this a request is dropped
constexpr const char* kLogPath = "sdmc:/config/songate-nx/airplay-bg.log";
constexpr const char* kTxt[] = { "txtvers=1", "ch=2", "cn=0,1", "et=0,1", "ek=1", "sr=44100", "ss=16", "sv=false", "da=true", "pw=false", "md=0,1,2",
                                 "tp=UDP", "vn=65537", "vs=105.1", "sf=0x4", "am=Songate" };

// ---- time and the log ------------------------------------------------------------------------------------------------------------

double tickSeconds() { return double(armTicksToNs(armGetSystemTick())) / 1e9; }

u64 wallSeconds() {
    u64 t = 0;
    return R_SUCCEEDED(timeGetCurrentTime(TimeType_LocalSystemClock, &t)) ? t : 0;
}

void lg(const char* fmt, ...) {
    char line[256];
    int n = snprintf(line, sizeof line, "[%7.1f] ", tickSeconds());
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof line - size_t(n) - 2, fmt, ap);
    va_end(ap);
    size_t len = strlen(line);
    line[len++] = '\n';
    line[len] = 0;
    // Open, write, close: no file is held between lines (one file-system session, shared with the whole system).
    FILE* f = fopen(kLogPath, "ab");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fclose(f);
    f = fopen(kLogPath, size > 64 * 1024 ? "wb" : "ab");   // grows to 64 KB, then starts over
    if (!f) return;
    fwrite(line, 1, len, f);
    fclose(f);
}

// ---- small helpers (from source/airplay.cpp) ---------------------------------------------------------------------------------------

void put16(std::vector<uint8_t>& o, unsigned v) { o.push_back(uint8_t(v >> 8)); o.push_back(uint8_t(v)); }
void put32(std::vector<uint8_t>& o, unsigned v) { put16(o, v >> 16); put16(o, v & 0xffff); }
void dnsName(std::vector<uint8_t>& o, const std::vector<std::string>& labels) {
    for (const std::string& l : labels) {
        const size_t k = std::min<size_t>(l.size(), 63);
        o.push_back(uint8_t(k));
        o.insert(o.end(), l.begin(), l.begin() + std::ptrdiff_t(k));
    }
    o.push_back(0);
}
void record(std::vector<uint8_t>& o, const std::vector<std::string>& owner, unsigned type, unsigned cls, unsigned ttl, const std::vector<uint8_t>& data) {
    dnsName(o, owner);
    put16(o, type);
    put16(o, cls);
    put32(o, ttl);
    put16(o, unsigned(data.size()));
    o.insert(o.end(), data.begin(), data.end());
}
bool holds(const uint8_t* d, size_t n, const char* s) {
    const size_t k = strlen(s);
    for (size_t i = 0; i + k <= n; i++) if (!memcmp(d + i, s, k)) return true;
    return false;
}
std::vector<uint8_t> unbase64(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '=' || s.back() == '\r')) s.pop_back();
    while (s.size() % 4) s += '=';
    std::vector<uint8_t> out(s.size() + 1);
    size_t n = 0;
    if (mbedtls_base64_decode(out.data(), out.size(), &n, reinterpret_cast<const unsigned char*>(s.data()), s.size()) != 0) n = 0;
    out.resize(n);
    return out;
}
std::string lineOf(const std::string& text, const char* key) {
    const size_t s = text.find(key);
    if (s == std::string::npos) return "";
    const size_t from = s + strlen(key), e = text.find_first_of("\r\n", from);
    return text.substr(from, e == std::string::npos ? e : e - from);
}
int rng(void*, unsigned char* o, size_t n) { randomGet(o, n); return 0; }

void closeFd(int& fd) { if (fd >= 0) { close(fd); fd = -1; } }
void nonBlocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }
bool wouldBlock() { return errno == EWOULDBLOCK || errno == EAGAIN; }

// ---- the receiver -------------------------------------------------------------------------------------------------------------------

struct Conn {
    int fd = -1;
    uint32_t peer = 0;
    std::string in;
    double since = 0;
};

struct Receiver {
    // sockets
    int mdns = -1, listener = -1, media[3] = { -1, -1, -1 };
    Conn conns[2];
    uint32_t ip = 0;
    bool open = false;
    // identity
    std::string console = "Nintendo Switch", instance, host;
    uint8_t hw[6] = {};
    std::vector<uint8_t> announce;
    // keys
    mbedtls_pk_context pk;
    mbedtls_rsa_context* rsa = nullptr;
    // the stream, as far as step 1 follows it
    bool streaming = false;
    unsigned long packets = 0, packetsAtLog = 0;
    double lastAnnounce = 0, lastStreamLog = 0, lastAlive = 0, openedAt = 0, burstAt = 0;
    unsigned questions = 0, accepted = 0, refreshes = 0;
    int burst = 0;                 // extra announcements after an open: the first may be missed (a phone just woke, a router busy)
    bool dirty = false;            // a network error was seen: everything is closed and opened again
    bool quiet = false;            // a routine refresh: not logged
    bool selfTested = false;

    /** Errors that mean the network under the sockets went away (sleep, Wi-Fi lost, address changed). */
    static bool netGone(int e) { return e == 114 || e == 115 || e == 118 || e == 125 || e == 126 || e == 9 || e == 19; }
    bool anyConn() const { for (const Conn& c : conns) if (c.fd >= 0) return true; return false; }

    Receiver() {
        mbedtls_pk_init(&pk);
        if (mbedtls_pk_parse_key(&pk, reinterpret_cast<const unsigned char*>(kAirportKey), sizeof kAirportKey, nullptr, 0) == 0 &&
            mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA) {
            rsa = mbedtls_pk_rsa(pk);
            if (mbedtls_rsa_complete(rsa) != 0) rsa = nullptr;
        }
    }

    // ---- the network's state

    static uint32_t currentIp() {
        uint32_t ip = 0;
        if (R_FAILED(nifmInitialize(NifmServiceType_User))) return 0;   // (opened for the call only: nifm allows few sessions)
        u32 a = 0, mask = 0, gate = 0, d1 = 0, d2 = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&a, &mask, &gate, &d1, &d2))) ip = a;
        nifmExit();
        return ip;
    }

    void readConsoleName() {
        SetSysDeviceNickName n{};
        if (R_SUCCEEDED(setsysGetDeviceNickname(&n)) && n.nickname[0]) console = n.nickname;
        uint64_t h = 1469598103934665603ull;   // a made-up hardware address from the name, as the app does (+ a salt: it is another receiver)
        for (char c : console) h = (h ^ uint8_t(c)) * 1099511628211ull;
        h = (h ^ 0xB6) * 1099511628211ull;
        for (int i = 0; i < 6; i++) hw[i] = uint8_t(h >> (i * 8));
        hw[0] = uint8_t((hw[0] | 2) & 0xFE);
        char id[16];
        snprintf(id, sizeof id, "%02X%02X%02X%02X%02X%02X", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
        instance = std::string(id) + "@Songate BG on " + console;
        host = std::string("songate-bg-") + id;
        for (char& c : host) c = char(tolower(uint8_t(c)));
    }

    // ---- mDNS

    std::vector<uint8_t> buildAnnounce(unsigned ttl) {
        const std::vector<std::string> service = { "_raop", "_tcp", "local" }, me = { instance, "_raop", "_tcp", "local" }, hostName = { host, "local" };
        std::vector<uint8_t> o, d;
        put16(o, 0); put16(o, 0x8400); put16(o, 0); put16(o, 4); put16(o, 0); put16(o, 0);
        dnsName(d, me);
        record(o, service, 12, 1, ttl ? 4500 : 0, d);
        d.clear();
        put16(d, 0); put16(d, 0); put16(d, kRtspPort);
        dnsName(d, hostName);
        record(o, me, 33, 0x8001, ttl, d);
        d.clear();
        for (const char* t : kTxt) {
            d.push_back(uint8_t(strlen(t)));
            d.insert(d.end(), t, t + strlen(t));
        }
        record(o, me, 16, 0x8001, ttl, d);
        d.assign(reinterpret_cast<uint8_t*>(&ip), reinterpret_cast<uint8_t*>(&ip) + 4);
        record(o, hostName, 1, 0x8001, ttl, d);
        return o;
    }

    void sayAnnounce(const std::vector<uint8_t>& what) {
        if (mdns < 0) return;
        sockaddr_in g{};
        g.sin_family = AF_INET;
        g.sin_port = htons(5353);
        g.sin_addr.s_addr = inet_addr("224.0.0.251");
        if (sendto(mdns, what.data(), what.size(), 0, reinterpret_cast<sockaddr*>(&g), sizeof g) < 0) {
            const int e = errno;
            lg("mDNS send failed (errno %d)", e);
            if (netGone(e)) dirty = true;
        }
    }

    void onMdns() {
        uint8_t d[1500];
        sockaddr_in from{};
        socklen_t len = sizeof from;
        int n;
        while ((n = int(recvfrom(mdns, d, sizeof d, 0, reinterpret_cast<sockaddr*>(&from), &len))) > 0) {
            len = sizeof from;
            if (from.sin_addr.s_addr == ip || n <= 12 || (d[2] & 0x80) || !holds(d, size_t(n), "_raop")) continue;
            if (++questions <= 5) { const uint8_t* q = reinterpret_cast<const uint8_t*>(&from.sin_addr.s_addr); lg("mDNS question from %u.%u.%u.%u:%u: answered", q[0], q[1], q[2], q[3], unsigned(ntohs(from.sin_port))); }
            sayAnnounce(announce);
            // asked from another port (a sender that holds 5353 itself): the answer goes straight back as well (legacy unicast)
            if (ntohs(from.sin_port) != 5353) sendto(mdns, announce.data(), announce.size(), 0, reinterpret_cast<sockaddr*>(&from), sizeof from);
        }
        if (n < 0 && !wouldBlock()) {
            const int e = errno;
            lg("mDNS receive failed (errno %d)", e);
            if (netGone(e)) dirty = true;
        }
    }

    // ---- opening and closing: all or nothing, so a wake or a new address starts clean

    bool openAll() {
        ip = currentIp();
        if (!ip) return false;
        int on = 1;
        sockaddr_in me{};
        me.sin_family = AF_INET;
        me.sin_addr.s_addr = htonl(INADDR_ANY);

        mdns = socket(AF_INET, SOCK_DGRAM, 0);
        if (mdns < 0) return fail("mdns socket");
        setsockopt(mdns, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        setsockopt(mdns, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        me.sin_port = htons(5353);
        if (bind(mdns, reinterpret_cast<sockaddr*>(&me), sizeof me) != 0) return fail("mdns bind 5353");
        ip_mreq group{};
        group.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
        group.imr_interface.s_addr = ip;
        if (setsockopt(mdns, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof group) != 0) return fail("mdns join");
        in_addr out{};
        out.s_addr = ip;
        setsockopt(mdns, IPPROTO_IP, IP_MULTICAST_IF, &out, sizeof out);
        unsigned char ttl = 255;
        setsockopt(mdns, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
        nonBlocking(mdns);

        listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0) return fail("rtsp socket");
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        me.sin_port = htons(kRtspPort);
        if (bind(listener, reinterpret_cast<sockaddr*>(&me), sizeof me) != 0 || listen(listener, 2) != 0) return fail("rtsp bind/listen");
        nonBlocking(listener);

        for (int i = 0; i < 3; i++) {
            media[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (media[i] < 0) return fail("media socket");
            me.sin_port = htons(uint16_t(kAudio + i));
            if (bind(media[i], reinterpret_cast<sockaddr*>(&me), sizeof me) != 0) return fail("media bind");
            nonBlocking(media[i]);
        }
        announce = buildAnnounce(120);
        sayAnnounce(announce);
        lastAnnounce = openedAt = tickSeconds();
        burst = 3;
        burstAt = lastAnnounce + 1.0;
        dirty = false;
        open = true;
        if (quiet) { quiet = false; return true; }
        const uint8_t* b = reinterpret_cast<const uint8_t*>(&ip);
        lg("open: %u.%u.%u.%u as \"%s\", rtsp %d, media %d-%d%s", b[0], b[1], b[2], b[3], instance.c_str(), kRtspPort, kAudio, kTiming, rsa ? "" : " (NO KEY: handshakes will fail)");
        return true;
    }

    bool fail(const char* what) {
        lg("open failed: %s (errno %d)", what, errno);
        closeAll(false);
        return false;
    }

    void closeAll(bool sayGoodbye) {
        if (sayGoodbye && open && mdns >= 0) sayAnnounce(buildAnnounce(0));   // iOS lists it no longer
        for (Conn& c : conns) { closeFd(c.fd); c.in.clear(); }
        closeFd(mdns);
        closeFd(listener);
        for (int& m : media) closeFd(m);
        streaming = false;
        packets = packetsAtLog = 0;
        open = false;
    }

    // ---- a self-test: connects to this receiver's own RTSP port and sees whether accept() gets it. If it does, the sockets work and
    // a missing iPhone connection is the network's or iOS's; if it does not, the fault is here (buffers, ports).
    void selfTest() {
        const int t = socket(AF_INET, SOCK_STREAM, 0);
        if (t < 0) { lg("self-test: no client socket (errno %d)", errno); return; }
        nonBlocking(t);
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(kRtspPort);
        to.sin_addr.s_addr = ip;
        const int rc = connect(t, reinterpret_cast<sockaddr*>(&to), sizeof to);
        const int err = errno;
        int got = -1;
        for (int i = 0; i < 100 && got < 0; i++) {   // up to 2 s
            got = accept(listener, nullptr, nullptr);
            if (got < 0) svcSleepThread(20'000'000ull);
        }
        if (got >= 0) lg("self-test: accept works (connect rc %d)", rc);
        else lg("self-test: NOT accepted after 2 s (connect rc %d, errno %d, accept errno %d)", rc, err, errno);
        closeFd(got);
        int tt = t;
        closeFd(tt);
    }

    // ---- the handshake

    std::string answerChallenge(const std::string& challenge) {
        const std::vector<uint8_t> c = unbase64(challenge);
        if (c.size() != 16 || !rsa) return "";
        uint8_t data[32] = {};
        memcpy(data, c.data(), 16);
        memcpy(data + 16, &ip, 4);
        memcpy(data + 20, hw, 6);
        const size_t size = mbedtls_rsa_get_len(rsa);
        std::vector<uint8_t> em(size, 0xFF), sig(size);
        em[0] = 0;
        em[1] = 1;
        em[size - 33] = 0;
        memcpy(em.data() + size - 32, data, 32);
        if (mbedtls_rsa_private(rsa, rng, nullptr, em.data(), sig.data()) != 0) return "";
        std::string out(size * 2, 0);
        size_t n = 0;
        if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(&out[0]), out.size(), &n, sig.data(), size) != 0) return "";
        out.resize(n);
        while (!out.empty() && out.back() == '=') out.pop_back();
        return out;
    }

    /** Whether the stream's description could be played: its AES key unwraps and its format is the one iOS sends (44.1 kHz stereo 16-bit ALAC). */
    bool playable(const std::string& body) {
        if (!rsa) return false;
        const std::vector<uint8_t> w = unbase64(lineOf(body, "a=rsaaeskey:")), i = unbase64(lineOf(body, "a=aesiv:"));
        if (w.size() != mbedtls_rsa_get_len(rsa) || i.size() != 16) return false;
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
        uint8_t key[32];
        size_t n = 0;
        const bool unwrapped = mbedtls_rsa_rsaes_oaep_decrypt(rsa, rng, nullptr, MBEDTLS_RSA_PRIVATE, nullptr, 0, &n, w.data(), key, sizeof key) == 0 && n == 16;
        mbedtls_platform_zeroize(key, sizeof key);   // (step 1 keeps no key: it only checks)
        if (!unwrapped) return false;
        unsigned pt, fp, compat, bits, pb, mb, kb, ch, run, maxBytes, avg, rate;
        if (sscanf(lineOf(body, "a=fmtp:").c_str(), "%u %u %u %u %u %u %u %u %u %u %u %u", &pt, &fp, &compat, &bits, &pb, &mb, &kb, &ch, &run, &maxBytes, &avg, &rate) != 12) return false;
        return fp >= 1 && fp <= 4096 && bits == 16 && ch == 2 && rate == 44100;
    }

    void send(Conn& c, const std::string& s) {
        size_t off = 0;
        for (int tries = 0; off < s.size() && tries < 400; tries++) {   // (a reply is small; waits at most 400 ms for a full buffer)
            const ssize_t n = ::send(c.fd, s.data() + off, s.size() - off, 0);
            if (n > 0) off += size_t(n);
            else if (n < 0 && wouldBlock()) svcSleepThread(1'000'000ull);
            else { lg("send failed (errno %d)", errno); break; }
        }
        if (off < s.size()) lg("reply not fully sent (%zu of %zu)", off, s.size());
    }

    void hangUp(Conn& c) {
        closeFd(c.fd);
        c.in.clear();
        if (streaming) lg("stream ended (%lu packets)", packets);
        streaming = false;
        packets = packetsAtLog = 0;
    }

    void onRequest(Conn& c, const std::string& head, const std::string& body) {
        const std::string method = head.substr(0, head.find(' '));
        lg("RTSP %s%s", method.substr(0, 20).c_str(), lineOf(head, "Apple-Challenge:").empty() ? "" : " (with challenge)");
        std::string cseq = lineOf(head, "CSeq:");
        if (cseq.size() > 16) cseq.resize(16);
        std::string reply = "RTSP/1.0 200 OK\r\nServer: AirTunes/105.1\r\nCSeq:" + cseq + "\r\n";
        std::string challenge = lineOf(head, "Apple-Challenge:");
        if (!challenge.empty()) {
            while (!challenge.empty() && challenge[0] == ' ') challenge.erase(0, 1);
            const std::string answer = answerChallenge(challenge);
            if (!answer.empty()) reply += "Apple-Response: " + answer + "\r\n";
            else lg("challenge not answered");
        }
        if (method == "OPTIONS") {
            reply += "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n";
        } else if (method == "ANNOUNCE") {
            // Step 1 has no "ask" question and no allowed list: any device on the network is let through, which is fine for a test but not
            // for use (step 3 brings the app's allowed devices over).
            if (!playable(body)) {
                lg("ANNOUNCE refused: not a stream this receiver can play");
                reply = "RTSP/1.0 400 Bad Request\r\nServer: AirTunes/105.1\r\nCSeq:" + cseq + "\r\n";
            } else {
                std::string name = lineOf(body, "i=");
                for (char& ch : name) if (uint8_t(ch) < 0x20) ch = ' ';
                lg("ANNOUNCE from \"%s\"", name.substr(0, 64).c_str());
                streaming = false;
                packets = packetsAtLog = 0;
            }
        } else if (method == "SETUP") {
            char t[140];
            snprintf(t, sizeof t, "Session: 1\r\nAudio-Jack-Status: connected\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=%d;control_port=%d;timing_port=%d\r\n", kAudio, kControl, kTiming);
            reply += t;
            lg("SETUP");
        } else if (method == "RECORD") {
            reply += "Audio-Latency: 11025\r\nSession: 1\r\n";
            streaming = true;
            packets = packetsAtLog = 0;
            lastStreamLog = tickSeconds();
            lg("RECORD: streaming (audio is counted and dropped in this step)");
        } else if (method == "FLUSH") {
            lg("FLUSH");
        } else if (method == "TEARDOWN") {
            lg("TEARDOWN");
            send(c, reply + "\r\n");
            hangUp(c);
            return;
        } else if (method == "SET_PARAMETER") {
            const std::string type = lineOf(head, "Content-Type:");
            if (type.find("text/parameters") != std::string::npos) {
                const std::string v = lineOf(body, "volume:");
                if (!v.empty()) lg("volume %s dB", v.c_str());
            }
        } else if (method != "GET_PARAMETER" && method != "PAUSE") {
            reply = "RTSP/1.0 404 Not Found\r\nServer: AirTunes/105.1\r\nCSeq:" + cseq + "\r\n";
        }
        reply += "\r\n";
        send(c, reply);
    }

    // ---- connections

    void acceptNew() {
        for (;;) {
            sockaddr_in from{};
            socklen_t len = sizeof from;
            const int fd = accept(listener, reinterpret_cast<sockaddr*>(&from), &len);
            if (fd < 0) { if (!wouldBlock()) lg("accept failed (errno %d)", errno); return; }
            accepted++;
            { const uint8_t* q = reinterpret_cast<const uint8_t*>(&from.sin_addr.s_addr); lg("RTSP connection from %u.%u.%u.%u", q[0], q[1], q[2], q[3]); }
            // Only this network's own addresses may talk to it (the app checks the same)
            Conn* slot = nullptr;
            for (Conn& c : conns) if (c.fd < 0) { slot = &c; break; }
            if (!slot) slot = conns[0].since <= conns[1].since ? &conns[0] : &conns[1];   // the oldest makes room
            if (slot->fd >= 0) hangUp(*slot);
            nonBlocking(fd);
            *slot = Conn{};
            slot->fd = fd;
            slot->peer = from.sin_addr.s_addr;
            slot->since = tickSeconds();
        }
    }

    void pumpConn(Conn& c) {
        char buf[4096];
        for (;;) {
            const ssize_t n = recv(c.fd, buf, sizeof buf, 0);
            if (n > 0) {
                c.in.append(buf, size_t(n));
                if (c.in.size() > kMaxHead + kMaxBody) { lg("request too big: dropped"); hangUp(c); return; }
            } else if (n == 0) { lg("peer closed the connection (%zu bytes unread)", c.in.size()); hangUp(c); return; }
            else if (wouldBlock()) break;
            else {
                const int e = errno;
                lg("recv failed (errno %d)", e);
                if (netGone(e)) dirty = true;   // (the console's network went down: sleep. Everything is opened again.)
                hangUp(c);
                return;
            }
        }
        for (;;) {   // whole requests only; a body still arriving waits
            const size_t end = c.in.find("\r\n\r\n");
            if (end == std::string::npos) { if (c.in.size() > kMaxHead) { hangUp(c); } return; }
            if (end > kMaxHead) { hangUp(c); return; }
            const std::string head = c.in.substr(0, end);
            const long want = atol(lineOf(head, "Content-Length:").c_str());
            if (want < 0 || size_t(want) > kMaxBody) { lg("body too big: dropped"); hangUp(c); return; }
            if (c.in.size() < end + 4 + size_t(want)) return;
            const std::string body = c.in.substr(end + 4, size_t(want));
            c.in.erase(0, end + 4 + size_t(want));
            onRequest(c, head, body);
            if (c.fd < 0) return;
        }
    }

    void drainMedia() {
        uint8_t d[2048];
        for (int i = 0; i < 3; i++) {
            for (int k = 0; k < 64; k++) {   // a bounded bite per turn
                const ssize_t n = recv(media[i], d, sizeof d, 0);
                if (n <= 0) break;
                if (i == 0 && streaming) packets++;
            }
        }
    }

    void pump() {
        onMdns();
        acceptNew();
        for (Conn& c : conns) if (c.fd >= 0) pumpConn(c);
        drainMedia();
        const double now = tickSeconds();
        if (streaming && now - lastStreamLog >= 5) {
            lg("streaming: %lu packets (+%lu in 5 s)", packets, packets - packetsAtLog);
            packetsAtLog = packets;
            lastStreamLog = now;
        }
        if (burst > 0 && now >= burstAt) { sayAnnounce(announce); burst--; burstAt = now + 1.5; }
        if (now - lastAnnounce >= 15) { sayAnnounce(announce); lastAnnounce = now; }   // (iOS also asks; this is for one that missed it)
        if (now - lastAlive >= 30) { lastAlive = now; lg("alive: %u mDNS questions, %u RTSP connections, %u idle refreshes so far", questions, accepted, refreshes); }   // (iOS also asks; this is for one that missed it)
    }
};

}  // namespace

int main(int, char**) {
    mkdir("sdmc:/config", 0777);
    mkdir("sdmc:/config/songate-nx", 0777);
    lg("---- airplay-bg step 1 starting (build %s %s, build 4: sleep/wake recovery)", __DATE__, __TIME__);

    // Small buffers: the default config's are sized for a game. Fields set by name, so the struct's order does not matter.
    SocketInitConfig cfg = *socketGetDefaultInitConfig();
    cfg.tcp_tx_buf_size = 0x4000;
    cfg.tcp_rx_buf_size = 0x4000;
    cfg.tcp_tx_buf_max_size = 0x10000;
    cfg.tcp_rx_buf_max_size = 0x10000;
    cfg.udp_tx_buf_size = 0x800;
    cfg.udp_rx_buf_size = 0x4000;
    cfg.sb_efficiency = 2;
    cfg.num_bsd_sessions = 3;

    static Receiver rx;
    rx.readConsoleName();

    bool sockets = false;
    double lastTick = tickSeconds(), lastCheck = lastTick;
    u64 lastWall = wallSeconds();
    for (;;) {
        const double now = tickSeconds();
        const u64 wall = wallSeconds();
        // The console slept if the wall clock moved on by more than the system tick did. What was open is not to be trusted
        // (Wi-Fi went down and came back): everything is closed and opened again, and announced again.
        const bool woke = wall && lastWall && double(wall - lastWall) > (now - lastTick) + 4;
        const double gap = now - lastTick;   // the loop sleeps 10 ms: a long gap means the process was held (the console slept)
        lastTick = now;
        lastWall = wall;
        if (gap > 0.8 && rx.open) {
            lg("loop stalled %.1f s (sleep?)", gap);
            if (!rx.streaming) rx.closeAll(false);   // idle: opened again below, as new
        }
        if (rx.dirty && rx.open) { lg("network error seen: reopening everything"); rx.closeAll(false); }
        // Idle for a minute: the sockets are made new, quietly. A socket that a sleep or a Wi-Fi change left dead (no error to show it:
        // its multicast membership gone, say) is then back within a minute, whatever else went unseen.
        if (rx.open && !rx.streaming && !rx.anyConn() && now - rx.openedAt >= 60) { rx.refreshes++; rx.quiet = true; rx.closeAll(false); }
        if (woke && rx.open) { lg("woke from sleep (clock jumped): reopening"); rx.closeAll(false); }

        if (!sockets) {
            if (R_FAILED(socketInitialize(&cfg))) { lg("sockets not available yet"); svcSleepThread(3'000'000'000ull); continue; }
            sockets = true;
        }
        if (!rx.open) {
            if (!rx.openAll()) { svcSleepThread(3'000'000'000ull); continue; }
            if (!rx.selfTested) { rx.selfTested = true; rx.selfTest(); }
            lastCheck = now;
        }
        // The address can change without a sleep (Wi-Fi roams, a new network): checked every 5 s; changed: closed, then opened on the new one.
        if (now - lastCheck >= 5) {
            lastCheck = now;
            const uint32_t cur = Receiver::currentIp();
            if (cur != rx.ip) { lg("address changed: reopening"); rx.closeAll(false); continue; }
        }
        rx.pump();
        svcSleepThread(10'000'000ull);   // 10 ms: the packets wait in the socket's buffer meanwhile
    }
}
