import streamlit as st
import sqlite3, tempfile, subprocess, wave, hashlib
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

DB_NAME = "guardian.db"
SECRET_KEY = b"SixteenByteKey!!"
WM_SEGMENTS = [(10,3), (40,3), (70,3)]
BIT_LEN = 128

# ================= PN =================
def pn_sequence(n, nonce):
    seed_material = hashlib.sha256(SECRET_KEY + nonce).digest()
    seed = int.from_bytes(seed_material[:4], "big")
    np.random.seed(seed)
    return (np.random.randint(0,2,n)*2 - 1).astype(np.float32)

# ================= EXTRACT =================
def extract_bits(segment, nonce):
    pn = pn_sequence(len(segment), nonce)
    spb = len(segment) // BIT_LEN

    if spb < 200:
        return None

    bits = ""
    for i in range(BIT_LEN):
        seg = segment[i*spb:(i+1)*spb]
        corr = np.sum(seg * pn[i*spb:(i+1)*spb])
        bits += "1" if corr > 0 else "0"

    return bits

# ================= DETECT =================
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
        s = int(start * sr)
        e = int((start+dur) * sr)
        if e <= len(audio):
            segment = audio[s:e]

            # brute try extraction
            for guess in range(3):
                nonce_guess = segment[:8].astype(np.int8).tobytes()[:8]
                bits = extract_bits(segment, nonce_guess)
                if bits:
                    data = int(bits, 2).to_bytes(len(bits)//8, 'big')
                    nonce = data[:8]
                    ciphertext = data[8:]

                    ctr = Counter.new(64, prefix=nonce)
                    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=ctr)

                    try:
                        uid = cipher.decrypt(ciphertext).decode()
                        return str(int(uid))
                    except:
                        continue

    return None

# ================= USER LOOKUP =================
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

    f = st.file_uploader("Upload suspected video", type=["mp4","mkv","mov"])

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
                st.warning("Watermark found but user not in database.")

if __name__ == "__main__":
    main()
