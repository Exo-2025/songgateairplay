# airplay-bg: AirPlay in the background (step 2: sound)

A separate sysmodule (program `4200000047464E59`) that makes the console appear in an iPhone's AirPlay list and plays the iPhone's audio
while Songate (the app) is closed. It pauses the background music player while a stream plays and plays it again afterwards (only if it
was playing). It runs beside the app: its own ports (RTSP 5006, media 6010-6012) and the name **"Songate BG on <console name>"**.

## Files that must be in the repository

    airplay-bg/Makefile
    airplay-bg/airplay-bg.json
    airplay-bg/toolbox.json
    airplay-bg/source/main.cpp
    airplay-bg/source/alac.hpp          (new in step 2: the ALAC decoder)
    airplay-bg/source/audio.hpp         (new in step 2: the sound out)
    airplay-bg/source/gfbg.h            (new in step 2: copies of the music player's protocol headers)
    airplay-bg/source/gfcfgdir.h
    airplay-bg/source/gfeqcfg.h
    airplay-bg/source/airport_key.inc   (from the Songate source)
    .github/workflows/airplay-bg.yml

(`airplay-bg/tools/` and the `.md` files are optional.) Step 1 only had main.cpp and airport_key.inc in `source/`: upload the new files too.

## Build without devkitPro (GitHub Actions)

Actions tab -> **airplay-bg** -> Run workflow -> download the **airplay-bg** artifact. If `pkg.devkitpro.org` answers 403, run it again later.

## Install

1. Stop the module (sysmodule manager). Copy the artifact's `atmosphere/` folder onto the SD card (merge).
2. Delete `sdmc:/config/songate-nx/airplay-bg.log` while the module is stopped. Start the module.
3. No `boot2.flag` on purpose: it does not start at boot.

## What to test

1. First log line says "step 2 ... build 5: sound". Pick "Songate BG" in the iPhone's AirPlay list and play a song.
2. **Sound** should come out of the console (speakers, dock or headphones), about half a second after the song starts.
3. If the background music player was playing, it pauses when the stream starts and plays again when the stream ends.
4. The log, every 5 s: `streaming: N packets (+~625), X ms queued, lost, repaired, underruns, dropped, sound open`.
   Healthy: `lost 0`, `underruns 0`, `sound open`, X around 500-1500 ms.
5. Try: pause and play on the iPhone, skip a track, change the volume on the iPhone, sleep and wake the console.
6. Send me the log and what you heard (silence, crackle, too fast or slow, too quiet, dropouts, how often).

## Known limits

- Untested on a console. The ALAC decoder was checked against FFmpeg on a PC (bit-exact, see tools/README.md); the rest was only
  syntax-checked.
- Sound only: no cover, title, progress or overlay controls yet (step 3). No "allow this device" question: any device on the network can connect.
- The iPhone's clock is not followed: the sound starts after half a second of it has arrived, and the two clocks drift apart slowly, so
  there may be an occasional short gap or trim on a long stream.
- The iPhone's volume is applied as the app does (-20 dB is quiet; turn the iPhone's slider up).
