import os

def conversion():  
    os.system(f"sox --type raw --rate 8000 -e u-law audio.g711u audio.wav")

conversion()