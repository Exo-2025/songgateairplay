# m4a -> packets.bin (u32 size + data per packet) + cookie fields printed; also reference PCM from ffmpeg's own decoder
import subprocess, struct, sys
f=sys.argv[1]; out=sys.argv[2]
data=open(f,'rb').read()
i=data.rfind(b'\x00\x00\x00\x24alac')
c=data[i+12:i+12+24]   # skip size,'alac', 4 bytes version/flags
frame,compat,bits,pb,mb,kb,ch,run,maxb,avg,rate=struct.unpack('>IBBBBBBHIII',c)
pk=subprocess.run(['ffprobe','-v','error','-select_streams','a:0','-show_entries','packet=pos,size','-of','csv=p=0',f],capture_output=True,text=True).stdout.split()
with open(out,'wb') as o:
    for line in pk:
        size,pos=map(int,line.split(","))
        o.write(struct.pack('<I',size)+data[pos:pos+size])
print(frame,40 if pb==0 else pb,10 if mb==0 else mb,14 if kb==0 else kb)
