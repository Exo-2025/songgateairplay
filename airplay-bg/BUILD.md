# airplay-bg, step 1: the AirPlay handshake in the background

A separate sysmodule (program `4200000047464E59`) that makes the console appear in an iPhone's AirPlay list and accept a stream
while Songate is closed. **Step 1 only does the handshake**: no sound yet, the audio packets are counted and dropped.
Steps 2 and 3 (decode and play through the background player, sleep/wake, the overlay) come after this works.

It runs beside the app: its own ports (RTSP 5006, media 6010-6012), and it shows in the list as **"Songate BG on <console name>"**,
so it never clashes with the app's own "Songate on <console name>".

## Build without devkitPro (GitHub Actions)

1. Make a free GitHub account and a new **private** repository.
2. Upload the whole `Songate-2.2.0` source folder to it (drag the files into the page, or use `git`). The `.github` folder must go too.
3. Open the repository's **Actions** tab, choose **airplay-bg**, press **Run workflow**.
4. When it is green, open the run and download the **airplay-bg** artifact (a zip).

## Install (test only)

1. Copy the zip's `atmosphere/` folder onto the SD card (it adds `atmosphere/contents/4200000047464E59/`).
2. **There is no `boot2.flag` on purpose**: it does not start at boot, so a bug in it cannot affect starting the console.
   Start it by hand from a sysmodule manager (Ultrahand's Status Monitor / sys-ftpd-style managers, or Tesla's *ovl-sysmodules*), which
   lists it through `toolbox.json`. Or reboot after adding `flags/boot2.flag` (an empty file) once you trust it.
3. To remove it: stop it and delete `atmosphere/contents/4200000047464E59`.

## What to test

1. Console online, start the module. In an iPhone's AirPlay list **"Songate BG on <name>"** should appear.
2. Pick it. The iPhone should connect without an error and play to it (silently: no sound yet).
3. Read `sdmc:/config/songate-nx/airplay-bg.log`. A good run shows, in order: `open`, `ANNOUNCE from "<iPhone>"`, `SETUP`, `RECORD`,
   then `streaming: N packets` every 5 s with N growing. `TEARDOWN` / `stream ended` when you stop.
4. Sleep the console, wake it, and look again at the list: the log should say `woke from sleep (clock jumped): reopening` and then
   `open` again, and the name should be back in the list.
5. Send me the log, and what the iPhone did, if anything differs.

## Known limits of step 1

- Untested on a console: it was written and syntax-checked without the Switch toolchain.
- No question to the user and no allowed list: any device on the network can connect (the app asks; step 3 brings that over).
- No sound, no cover, no title, no volume: the handshake and the stream's arrival only.
- If the app's own AirPlay is on at the same time, both are listed; pick "Songate BG" to test this one.
