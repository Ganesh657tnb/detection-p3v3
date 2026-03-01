import streamlit as st
import tempfile, subprocess, wave
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
SECRET_KEY = b"SixteenByteKey!!"   # MUST match App-1
WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN = 64  # 8 bytes UID

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

def extract_bits(segment):
    pn = pn_sequence(len(segment))
    spb = len(segment) // BIT_LEN

    if spb < 200:
        return None

    bits = ""
    for i in range(BIT_LEN):
        seg = segment[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn[i*spb:(i+1)*spb])
        bits += "1" if corr > 0 else "0"

    return bits

# ================= CRYPTO =================
def decrypt_bits(bits):
    try:
        data = int(bits, 2).to_bytes(len(bits)//8, 'big')
        ctr = Counter.new(128)
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data).decode()
    except:
        return None

# ================= DETECTION =================
def detect_watermark(video_bytes):
    with tempfile.TemporaryDirectory() as tmp:
        vpath = f"{tmp}/vid.mp4"
        wav = f"{tmp}/audio.wav"

        with open(vpath,"wb") as f:
            f.write(video_bytes)

        subprocess.run([
            "ffmpeg","-y","-i",vpath,
            "-vn","-ac","1","-ar","44100",
            wav
        ], check=True, capture_output=True)

        with wave.open(wav,'rb') as w:
            audio = np.frombuffer(
                w.readframes(w.getnframes()),
                dtype=np.int16
            ).astype(np.float32)
            sr = w.getframerate()

    recovered = []

    for start,dur in WM_SEGMENTS:
        s = int(start * sr)
        e = int((start+dur) * sr)
        if e <= len(audio):
            bits = extract_bits(audio[s:e])
            if bits:
                recovered.append(bits)

    if not recovered:
        return None

    # majority vote
    final_bits = ""
    for i in range(BIT_LEN):
        votes = [blk[i] for blk in recovered]
        final_bits += max(set(votes), key=votes.count)

    return decrypt_bits(final_bits)

# ================= STREAMLIT =================
def main():
    st.set_page_config("Guardian App-2","🔍",layout="wide")
    st.title("🔍 Guardian – Watermark Detection")

    f = st.file_uploader("Upload suspected video", type=["mp4","mkv","mov"])

    if f and st.button("Analyse"):
        with st.spinner("Detecting watermark..."):
            uid = detect_watermark(f.read())

        if uid is None:
            st.success("✅ No watermark detected")
        else:
            st.error("🚨 WATERMARK FOUND")
            st.code(uid)

if __name__ == "__main__":
    main()
