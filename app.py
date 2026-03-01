import streamlit as st
import os, sqlite3, tempfile, subprocess, wave
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# ================= CONFIG =================
DB_NAME = "guardian_app1.db"      # SAME DB AS APP-1
SECRET_KEY = b"SixteenByteKey!!"  # SAME KEY AS APP-1
GAIN = 0.006

# ================= DSSS =================
def pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0, 2, n) * 2 - 1).astype(np.float32)

# ================= CRYPTO =================
def decrypt_bits(bit_string):
    try:
        data = int(bit_string, 2).to_bytes(len(bit_string) // 8, 'big')
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=Counter.new(64))
        return cipher.decrypt(data).decode().strip("\x00")
    except:
        return None

# ================= FFMPEG =================
def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True)

# ================= DETECTION CORE =================
def detect_watermark(video_bytes):
    with tempfile.TemporaryDirectory() as tmp:
        vpath = os.path.join(tmp, "leak.mp4")
        wavpath = os.path.join(tmp, "audio.wav")

        with open(vpath, "wb") as f:
            f.write(video_bytes)

        # Extract audio
        run([
            "ffmpeg", "-y", "-i", vpath,
            "-vn", "-ac", "1", "-ar", "44100",
            wavpath
        ])

        with wave.open(wavpath, 'rb') as w:
            audio = np.frombuffer(
                w.readframes(w.getnframes()),
                dtype=np.int16
            ).astype(np.float32)

    BIT_LEN = 128
    pn = pn_sequence(len(audio))
    spb = len(audio) // BIT_LEN

    if spb < 200:
        return None

    recovered_bits = ""
    for i in range(BIT_LEN):
        seg = audio[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn[i*spb:(i+1)*spb])
        recovered_bits += "1" if corr > 0 else "0"

    return decrypt_bits(recovered_bits)

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
    st.set_page_config("Guardian App-2", "🔍", layout="wide")
    st.title("🔍 Guardian – Piracy Detection Portal (App-2)")

    st.markdown("""
    Upload a **suspected leaked video**.  
    This system will:
    - Extract hidden audio watermark  
    - Recover encrypted User ID  
    - Identify the original downloader  
    """)

    leaked = st.file_uploader(
        "Upload Suspected Video",
        type=["mp4", "mkv", "mov"],
        key="leak_upload"
    )

    if leaked and st.button("Analyse Watermark", key="detect_btn"):
        with st.spinner("Extracting watermark & analysing..."):
            uid = detect_watermark(leaked.read())

        if uid is None:
            st.success("✅ No valid watermark detected")
            return

        user = lookup_user(uid)

        if not user:
            st.warning("⚠️ Watermark found, but user not in database")
            return

        username, email, phone = user

        st.error("🚨 PIRACY CONFIRMED")
        st.markdown(f"""
        ### 🔴 Leak Source Identified
        - **User ID:** `{uid}`
        - **Username:** `{username}`
        - **Email:** `{email}`
        - **Phone:** `{phone}`
        """)

if __name__ == "__main__":
    main()