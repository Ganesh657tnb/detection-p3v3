import streamlit as st
import tempfile, subprocess, wave
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
SECRET_KEY = b"SixteenByteKey!!"   # MUST match App-1
GAIN = 0.006

# MUST match App-1 exactly
WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN = 64   # 8 bytes UID → 64 bits

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)  # MUST match App-1
    return (np.random.randint(0, 2, n) * 2 - 1).astype(np.float32)

def extract_bits(audio):
    pn = pn_sequence(len(audio))
    spb = len(audio) // BIT_LEN

    if spb < 200:
        return None

    bits = ""
    for i in range(BIT_LEN):
        seg = audio[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn[i*spb:(i+1)*spb])
        bits += "1" if corr > 0 else "0"
    return bits

# ================= CRYPTO =================
def decrypt_bits(bit_string):
    try:
        data = int(bit_string, 2).to_bytes(len(bit_string)//8, 'big')

        # MUST match App-1 exactly
        ctr = Counter.new(128)
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)

        uid = cipher.decrypt(data).decode()
        return uid   # keep leading zeros
    except:
        return None

# ================= DETECTOR =================
def detect_watermark(video_bytes):
    with tempfile.TemporaryDirectory() as tmp:
        vpath = f"{tmp}/leak.mp4"
        wavpath = f"{tmp}/audio.wav"

        with open(vpath, "wb") as f:
            f.write(video_bytes)

        subprocess.run([
            "ffmpeg","-y","-i",vpath,
            "-vn","-ac","1","-ar","44100",
            wavpath
        ], check=True, capture_output=True)

        with wave.open(wavpath,'rb') as w:
            audio = np.frombuffer(
                w.readframes(w.getnframes()),
                dtype=np.int16
            ).astype(np.float32)
            sr = w.getframerate()

    recovered_blocks = []

    for start,dur in WM_SEGMENTS:
        s = int(start * sr)
        e = int((start + dur) * sr)
        if e <= len(audio):
            bits = extract_bits(audio[s:e])
            if bits:
                recovered_blocks.append(bits)

    if not recovered_blocks:
        return None

    # Majority voting across segments
    final_bits = ""
    for i in range(BIT_LEN):
        votes = [blk[i] for blk in recovered_blocks]
        final_bits += max(set(votes), key=votes.count)

    return decrypt_bits(final_bits)

# ================= STREAMLIT UI =================
def main():
    st.set_page_config("Guardian App-2","🔍",layout="wide")
    st.title("🔍 Guardian – Watermark Detection Portal")

    st.markdown("""
    Upload a **suspected leaked video**.  
    This tool will:
    - Extract the hidden audio watermark  
    - Recover the encrypted User ID  
    - Display the original downloader ID  
    """)

    leaked = st.file_uploader(
        "Upload Suspected Video",
        type=["mp4","mkv","mov"]
    )

    if leaked and st.button("Analyse Watermark"):
        with st.spinner("Detecting watermark..."):
            uid = detect_watermark(leaked.read())

        if uid is None:
            st.success("✅ No valid watermark detected")
            return

        st.error("🚨 WATERMARK DETECTED")
        st.markdown(f"""
        ### 🔴 Leak Source Identified
        **Embedded User ID:**  
        ```text
        {uid}
        ```
        """)

if __name__ == "__main__":
    main()
