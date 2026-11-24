Host-side tests for source/alac.hpp (run on a PC with g++, ffmpeg, ffprobe and python3+numpy; not part of the console build):

    python3 gen.py                                   # test audio
    for l in 0 1 2; do for f in music noise full mono square; do ffmpeg -y -i $f.wav -c:a alac -compression_level $l ${f}_$l.m4a; done; done
    g++ -O1 -g -fsanitize=address,undefined -std=gnu++20 -o test test.cpp
    for f in *_?.m4a; do b=${f%.m4a}; p=$(python3 extract.py $f $b.pk); ffmpeg -y -i $f -f s16le -acodec pcm_s16le $b.pcm; ./test $b.pk $b.pcm $p; done
    g++ -O1 -g -fsanitize=address,undefined -std=gnu++20 -o fuzz fuzz.cpp && ./fuzz music_1.pk   # corrupted packets must never crash

Result when written (2026-11-24): all 15 files bit-exact against FFmpeg's decoder; 6,520 corrupted packets without a crash.
