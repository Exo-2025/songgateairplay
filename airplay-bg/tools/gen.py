import numpy as np, wave, sys
rng=np.random.default_rng(7)
sr=44100
def save(name, L, R):
    a=np.stack([L,R],1).clip(-32768,32767).astype('<i2')
    w=wave.open(name,'wb'); w.setnchannels(2); w.setsampwidth(2); w.setframerate(sr); w.writeframes(a.tobytes()); w.close()
t=np.arange(sr*6)/sr
# music-like: chords + vibrato + noise, different L/R, gaps of silence
def tone(f,a): return a*np.sin(2*np.pi*f*t+0.3*np.sin(2*np.pi*5*t))
L=tone(220,6000)+tone(330,4000)+tone(1250,1500)+rng.normal(0,200,len(t))
R=tone(220,5000)+tone(440,3500)+tone(2500,900)+rng.normal(0,200,len(t))
L[sr*2:sr*3]=0; R[sr*2:sr*3]=0                     # a second of digital silence (zero runs)
L[sr*4:sr*4+3000]*=0.001; R[sr*4:sr*4+3000]*=0.001  # near-silence
save('music.wav',L,R)
save('noise.wav',rng.normal(0,9000,sr*3),rng.normal(0,9000,sr*3))  # loud noise: long codes
x=rng.integers(-32768,32767,sr*2).astype(float); save('full.wav',x,-x)  # full-scale, anti-phase
m=tone(440,12000); save('mono.wav',m,m)             # identical channels
save('square.wav',np.where(np.sin(2*np.pi*100*t)>0,30000,-30000),np.where(np.sin(2*np.pi*150*t)>0,25000,-25000))
