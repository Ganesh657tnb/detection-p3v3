import streamlit as st
import sqlite3, tempfile, subprocess, wave, hashlib
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

DB_NAME = "guardian.db"
SECRET_KEY = b"SixteenByteKey!!"

WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN_NONCE = 64
BIT_LEN_DATA = 64
TOTAL_BITS = BIT_LEN_NONCE + BIT_LEN_DATA
FIXED_SEED = 9999

# ================= PN =================
def fixed_pn(n):
    np.random.seed(FIXED_SEED)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

def derived_pn(n, nonce):
    seed_material = hashlib.sha256(SECRET_KEY + nonce).digest()
    seed = int.from_bytes(seed_material[:4], "big")
    np.random.seed(seed)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

# ================= EXTRACTION =================
def extract_segment(segment):
    spb = len(segment) // TOTAL_BITS

    # Extract nonce
    pn1 = fixed_pn(len(segment))
    nonce_bits = ""
    for i in range(BIT_LEN_NONCE):
        seg = segment[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn1[i*spb:(i+1)*spb])
        nonce_bits += "1" if corr > 0 else "0"

    nonce = int(nonce_bits,2).to_bytes(8,'big')

    # Extract ciphertext
    pn2 = derived_pn(len(segment), nonce)
    cipher_bits = ""
    for i in range(BIT_LEN_DATA):
        idx = i + BIT_LEN_NONCE
        seg = segment[idx*spb:(idx+1)*spb]
        corr = np.sum(seg * pn2[idx*spb:(idx+1)*spb])
        cipher_bits += "1" if corr > 0 else "0"

    ciphertext = int(cipher_bits,2).to_bytes(8,'big')

    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)

    try:
        uid = cipher.decrypt(ciphertext).decode()
        return str(int(uid))
    except:
        return None

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

    for start,dur in WM_SEGMENTS:
        s = int(start*sr)
        e = int((start+dur)*sr)
        if e <= len(audio):
            uid = extract_segment(audio[s:e])
            if uid:
                return uid

    return None

def get_user(uid):
    conn = sqlite3.connect(DB_NAME)
    user = conn.execute(
        "SELECT id,username,email,phone FROM users WHERE id=?",
        (int(uid),)
    ).fetchone()
    conn.close()
    return user

# ================= STREAMLIT =================
def main():
    st.set_page_config("Guardian App-2","🔍",layout="wide")
    st.title("🔍 Guardian – Watermark Detection")

    f = st.file_uploader("Upload Suspected Video", type=["mp4","mov","mkv"])

    if f and st.button("Analyse"):
        with st.spinner("Detecting watermark..."):
            uid = detect_watermark(f.read())

        if uid is None:
            st.success("✅ No watermark detected")
        else:
            user = get_user(uid)
            if user:
                st.error("🚨 WATERMARK FOUND")
                st.write(f"User ID: {user[0]}")
                st.write(f"Username: {user[1]}")
                st.write(f"Email: {user[2]}")
                st.write(f"Phone: {user[3]}")
            else:
                st.warning("Watermark detected but user not in database.")

if __name__ == "__main__":
    main()
