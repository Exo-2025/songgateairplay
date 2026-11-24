# airplay-bg: where this stands (updated 2026-11-24)

## Goal
Let an iPhone use AirPlay to the Switch while Songate (the app) is closed, i.e. with the background player and overlay.
The app already has AirPlay (source/airplay.cpp) but only while it is open. Chosen approach: a **separate sysmodule**
(program 4200000047464E59), because the background player's heap is only 2 MiB, and has no network, TLS or ALAC.

## Done: step 1 (working, tested on a real console, build 4)
- Announces itself over mDNS as "Songate BG on <console name>"; answers the iPhone's RTSP (AirPort-key challenge, ANNOUNCE, SETUP,
  RECORD, FLUSH, TEARDOWN, SET_PARAMETER); receives the RTP audio packets and only counts them.
- Verified from logs: connects, streams (~625 packets per 5 s), and ends cleanly on TEARDOWN.
- Sleep/wake: recovered by itself. It reopens all sockets on a network error (errno 115), on a loop stall (> 0.8 s, not streaming),
  and refreshes idle sockets after 60 s; it announces 3 extra times after each open.
- Lessons: build 1 could not accept connections (socket buffers too small; build 3 raised them and the heap to 2 MiB). The clock-jump
  wake detection never fired; error-based detection did.
- Runs beside the app: its own ports (RTSP 5006, media 6010-6012) and its own name in the AirPlay list.
- No boot2.flag on purpose: start it by hand from a sysmodule manager.

## Step 2 (written 2026-11-24, build 5: NOT yet tested on a console)
- source/alac.hpp: ALAC decoder written from the format, bit-exact against FFmpeg on 15 test files (tools/), fuzzed with corrupted packets.
- source/audio.hpp: ring + audout thread + 44.1->48 kHz linear resampler (checked on the host: pitch, continuity).
- main.cpp: keeps the AES key, puts RTP packets in order (256 slots, asks for lost ones on the control port), decrypts, decodes, plays;
  iPhone volume -> gain; pauses the background player (gfbg IPC) on RECORD, resumes it on stream end; big SET_PARAMETER bodies (covers) are
  thrown away instead of kept (memory).
- To test: see BUILD.md. All files in airplay-bg/source/ must be uploaded (new: alac.hpp, audio.hpp, gfbg.h, gfcfgdir.h, gfeqcfg.h).

## Not done (the original step 2 plan, kept for reference)
- **Step 2: sound.** Write a compact ALAC decoder (no FFmpeg in a sysmodule; the sandbox had no network to fetch Apple's),
  decrypt the AES-128-CBC packets (key from ANNOUNCE: keep the unwrapped key, step 1 discards it), resample 44.1 -> 48 kHz, play through
  audout (as sysmodule/source/engine.cpp does), pause the background player (gfbg.h commands) while a stream plays, resume after.
  Needs a test round or two on a console (crackle / wrong speed are the usual faults).
- **Step 3:** cover, title, progress, volume; an "allowed devices" question (step 1 lets any device on the network connect);
  overlay controls (overlay/ talks only to the background player today); optionally start at boot (add flags/boot2.flag).

## Build without devkitPro
GitHub repo (private) with: airplay-bg/ (this folder, including airplay-bg/source/airport_key.inc beside main.cpp) and
.github/workflows/airplay-bg.yml. Both are in this zip. Actions tab -> run "airplay-bg" -> download the artifact,
copy its atmosphere/ folder onto the SD card. If pkg.devkitpro.org answers 403, re-run later (the workflow retries).
Stop the module before replacing exefs.nsp; delete airplay-bg.log while it is stopped. The first log line names the build.

## To continue
Open a new chat, attach this zip (and the original Songate source if available), and say: "continue airplay-bg from STATUS.md, start step 2".
