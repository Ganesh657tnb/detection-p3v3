import streamlit as st
import os, sqlite3, tempfile, subprocess, wave
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
DB_NAME = "guardian_app1.db"      # SAME DB
SECRET_KEY = b"SixteenByteKey!!"  # SAME KEY
WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN = 64                     # 8 chars × 8 bits

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

def recover_bits(audio):
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
        ctr = Counter.new(128)   # ✅ MUST MATCH APP-1
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data).decode().lstrip("0")
    except:
        return None

# ================= WATERMARK DETECTOR =================
def detect_watermark(video_bytes):
    with tempfile.TemporaryDirectory() as tmp:
        vpath = os.path.join(tmp, "leak.mp4")
        wavpath = os.path.join(tmp, "audio.wav")

        with open(vpath, "wb") as f:
            f.write(video_bytes)

        subprocess.run([
            "ffmpeg","-y","-i",vpath,
            "-vn","-ac","1","-ar","44100",
            wavpath
        ], check=True)

        with wave.open(wavpath, 'rb') as w:
            audio = np.frombuffer(
                w.readframes(w.getnframes()),
                dtype=np.int16
            ).astype(np.float32)
            sr = w.getframerate()

    recovered = []

    # 🔁 scan ONLY watermark windows
    for start,dur in WM_SEGMENTS:
        s = int(start * sr)
        e = int((start+dur) * sr)
        if e <= len(audio):
            bits = recover_bits(audio[s:e])
            if bits:
                recovered.append(bits)

    if not recovered:
        return None

    # 🗳️ majority voting
    final_bits = ""
    for i in range(BIT_LEN):
        votes = [r[i] for r in recovered]
        final_bits += max(set(votes), key=votes.count)

    return decrypt_bits(final_bits)

# ================= DATABASE LOOKUP =================
def lookup_user(uid):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        "SELECT username, email, phone FROM users WHERE id=?",
        (uid,)
    ).fetchone()
    conn.close()
    return row

# ================= STREAMLIT UI =================
def main():
    st.set_page_config("Guardian App-2","🔍",layout="wide")
    st.title("🔍 Guardian – Piracy Detection Portal")

    leaked = st.file_uploader(
        "Upload Suspected Video",
        type=["mp4","mkv","mov"]
    )

    if leaked and st.button("Analyse Watermark"):
        with st.spinner("Extracting hidden watermark…"):
            uid = detect_watermark(leaked.read())

        if not uid:
            st.success("✅ No valid watermark detected")
            return

        user = lookup_user(uid)
        if not user:
            st.warning("⚠️ Watermark found, user not in DB")
            return

        u,e,p = user
        st.error("🚨 PIRACY CONFIRMED")
        st.markdown(f"""
        **Leaked By**
        - User ID: `{uid}`
        - Username: `{u}`
        - Email: `{e}`
        - Phone: `{p}`
        """)

if __name__ == "__main__":
    main()
