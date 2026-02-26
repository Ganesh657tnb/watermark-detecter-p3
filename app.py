import os
import streamlit as st
import tempfile
import subprocess
import numpy as np
import wave
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# --- Configuration ---
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'webm', 'mkv'}
SECRET_KEY = "ThisIsASecretKeyForAES256!!!!!" # MUST MATCH THE EMBEDDER KEY

# --- Utility Functions ---

def decrypt_data(bit_string):
    """Converts bits back to bytes and decrypts using AES-256."""
    try:
        key = SECRET_KEY.ljust(32)[:32].encode()
        # Bits to Bytes conversion
        byte_list = [int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8)]
        full_data = bytes(byte_list)
        iv = full_data[:16]
        ct = full_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return None

def generate_pn_sequence(duration_samples):
    np.random.seed(42) # MUST MATCH THE EMBEDDER SEED
    return (np.random.randint(0, 2, duration_samples) * 2 - 1).astype(np.float64)

def extract_audio_ffmpeg(video_path, output_wav_path):
    subprocess.run([
        "ffmpeg", "-y", "-i", video_path,
        "-vn", "-acodec", "pcm_s16le",
        output_wav_path
    ], check=True, capture_output=True)

# --- Updated Forensic Extraction Logic ---

def extract_watermark_v2(input_wav):
    """Scans for encrypted segments across the audio file."""
    try:
        with wave.open(input_wav, "rb") as wav:
            params = wav.getparams()
            frames = wav.readframes(params.nframes)
            audio = np.frombuffer(frames, dtype=np.int16).astype(np.float64)
            sample_rate = params.framerate
    except Exception as e:
        return f"Error reading file: {e}"

    # 1. Setup Parameters (Must match v2.0 Embedder)
    segment_len = 5 * sample_rate # 5-second chunks
    # AES-256 bit length for "USER_XXX" is typically 256 bits (32 bytes * 8)
    # We'll calculate the exact length of an encrypted string "USER_000"
    dummy_encrypted = "0" * 256 # Minimum length check
    bit_len = 256 
    
    total_samples = len(audio)
    pn = generate_pn_sequence(total_samples)
    
    # 2. Segment Scanning (The Trim-Proof Logic)
    # Scan every 5-second segment to find a valid watermark
    num_segments = total_samples // segment_len
    
    for s in range(min(num_segments, 10)): # Scanning first 10 segments (approx 50 seconds)
        start_idx = s * segment_len
        sf = segment_len // bit_len
        extracted_bits = ""
        
        for i in range(bit_len):
            b_start = start_idx + (i * sf)
            b_end = start_idx + ((i + 1) * sf)
            
            # Correlation with PN Code
            correlation = np.sum(audio[b_start:b_end] * pn[b_start:b_end])
            extracted_bits += "1" if correlation > 0 else "0"
        
        # 3. Attempt Decryption
        decrypted_id = decrypt_data(extracted_bits)
        if decrypted_id and "USER_" in decrypted_id:
            return decrypted_id # Found him!

    return "No valid encrypted watermark detected."

# --- Streamlit UI ---

def main():
    st.set_page_config(page_title="Forensic Detector v2.0", layout="wide")
    st.title("🛡️ Forensic Watermark Detector (Encrypted)")
    
    uploaded_file = st.file_uploader("Upload Pirated Video", type=list(ALLOWED_EXTENSIONS))

    if uploaded_file:
        if st.button("Start Forensic Analysis"):
            with tempfile.TemporaryDirectory() as tmp:
                video_path = os.path.join(tmp, "leak.mp4")
                with open(video_path, "wb") as f:
                    f.write(uploaded_file.read())
                
                audio_wav = os.path.join(tmp, "leak.wav")
                
                with st.spinner("Extracting audio..."):
                    extract_audio_ffmpeg(video_path, audio_wav)
                
                with st.spinner("Scanning for encrypted DSSS bits..."):
                    result = extract_watermark_v2(audio_wav)
                
                if "USER_" in result:
                    st.error(f"🚨 **PIRATER IDENTIFIED!**")
                    st.markdown(f"### Found ID: `{result}`")
                    st.balloons()
                else:
                    st.warning(f"Result: {result}")

if __name__ == "__main__":
    main()