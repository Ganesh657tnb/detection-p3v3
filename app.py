import streamlit as st
import tempfile, subprocess, wave, hashlib
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG (MUST MATCH APP-1) =================
SECRET_KEY = b"SixteenByteKey!!"

GAIN = 0.03
WM_SEGMENTS = [(10,3), (40,3), (70,3)]

BIT_LEN_NONCE = 64
BIT_LEN_DATA = 64
TOTAL_BITS = BIT_LEN_NONCE + BIT_LEN_DATA
FIXED_SEED = 9999

# ================= PN SEQUENCES =================
def fixed_pn(n):
    np.random.seed(FIXED_SEED)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

def derived_pn(n, nonce):
    seed_material = hashlib.sha256(SECRET_KEY + nonce).digest()
    seed = int.from_bytes(seed_material[:4], "big")
    np.random.seed(seed)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

# ================= BIT EXTRACTION =================
def extract_bits(audio, pn):
    spb = len(audio) // TOTAL_BITS
    if spb < 200:
        return None

    bits = ""
    for i in range(TOTAL_BITS):
        seg = audio[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn[i*spb:(i+1)*spb])
        bits += "1" if corr > 0 else "0"
    return bits

# ================= AES DECRYPT =================
def decrypt_uid(nonce, ciphertext):
    try:
        ctr = Counter.new(64, prefix=nonce)
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
        uid = cipher.decrypt(ciphertext).decode()
        return uid
    except:
        return None

# ================= DETECTION CORE =================
def detect_watermark(video_bytes):
    with tempfile.TemporaryDirectory() as tmp:
        vpath = f"{tmp}/leak.mp4"
        wavpath = f"{tmp}/audio.wav"

        with open(vpath,"wb") as f:
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

    recovered = []

    for start,dur in WM_SEGMENTS:
        s = int(start*sr)
        e = int((start+dur)*sr)
        if e <= len(audio):
            seg = audio[s:e]

            pn_fixed = fixed_pn(len(seg))
            bits = extract_bits(seg, pn_fixed)
            if bits:
                recovered.append(bits)

    if not recovered:
        return None

    # Majority vote
    final_bits = ""
    for i in range(TOTAL_BITS):
        votes = [blk[i] for blk in recovered]
        final_bits += max(set(votes), key=votes.count)

    nonce_bits = final_bits[:BIT_LEN_NONCE]
    data_bits = final_bits[BIT_LEN_NONCE:]

    nonce = int(nonce_bits, 2).to_bytes(8, 'big')
    ciphertext = int(data_bits, 2).to_bytes(8, 'big')

    return decrypt_uid(nonce, ciphertext)

# ================= STREAMLIT UI =================
def main():
    st.set_page_config("Guardian App-2","🔍",layout="wide")
    st.title("🔍 Guardian – Watermark Detection Portal")

    st.markdown("""
    Upload a **suspected leaked video**.  
    This system will:
    - Extract embedded audio watermark  
    - Recover encrypted User ID  
    - Identify the original downloader  
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
        else:
            st.error("🚨 WATERMARK FOUND")
            st.markdown(f"""
            ### 🔴 Leak Source Identified
            **Embedded User ID**
            ```
            {uid}
            ```
            """)

if __name__ == "__main__":
    main()
