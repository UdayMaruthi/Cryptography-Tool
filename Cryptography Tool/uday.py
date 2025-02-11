import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet
import os
import time

st.set_page_config(page_title="CRYPTOGRAPHY TOOL", layout="wide")

# Apply custom styling
st.markdown(
    """
    <style>
    body {
        background-color: #2E2E2E;
        color: white;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 12px;
        font-size: 16px;
        padding: 10px 20px;
        transition: background-color 0.3s, color 0.3s;
    }
    .stButton>button:hover {
        background-color: #45a049;
        color: white;
    }
    .info-box {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px;
        margin: 20px;
        border-radius: 15px;
        width: 400px;
        height: 250px;
        font-size: 16px;
        font-weight: bold;
        color: white;
        text-align: center;
        border: 2px solid transparent;
        opacity: 0;
        transition: transform 2s ease-in-out, opacity 2s ease-in-out, border-color 0.8s ease-in-out;
        overflow: hidden;
    }
    .encrypt {
        border-color: #FF5733;
        transform: translateX(-100%);
    }
    .decrypt {
        border-color: #33A1FF;
        transform: translateX(100%);
    }
    .hash {
        border-color: #FFC300;
        transform: translateY(-100%);
    }
    .encrypt-hash {
        border-color: #8D33FF;
        transform: translateY(100%);
    }
    @keyframes slide-in-left {
        0% { opacity: 0; transform: translateX(-100%); }
        100% { opacity: 1; transform: translateX(0); }
    }
    @keyframes slide-in-right {
        0% { opacity: 0; transform: translateX(100%); }
        100% { opacity: 1; transform: translateX(0); }
    }
    @keyframes slide-in-up {
        0% { opacity: 0; transform: translateY(20px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    @keyframes slide-in-down {
        0% { opacity: 0; transform: translateY(-20px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    .slide-animation-left {
        animation: slide-in-left 2s ease-in-out forwards;
    }
    .slide-animation-right {
        animation: slide-in-right 2s ease-in-out forwards;
    }
    .slide-animation-left {
        animation: slide-in-right 2s ease-in-out forwards;
    }
    .slide-animation-left {
        animation: slide-in-left 2s ease-in-out forwards;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Sidebar for selecting mode
st.sidebar.header("Cryptographic Operations")
option = st.sidebar.selectbox("Choose an option", ["Select Operation", "Encrypt", "Decrypt", "Generate Hash", "Encrypt & Hash"])

# Display info boxes only if no operation is selected
if option == "Select Operation":
    st.markdown("<h1 style='text-align:center; color:#4CAF50;'>🔐 Cryptography Tool</h1>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            '<div class="info-box encrypt slide-animation-left">🔑 <b>Encryption:</b> This is the process of converting plaintext (readable data) into ciphertext (unreadable data) using an encryption algorithm and a key. The purpose of encryption is to ensure that only authorized parties can access the original information.</div>',
            unsafe_allow_html=True)

        st.markdown(
            '<div class="info-box hash slide-animation-right">🔢 <b>Generating Hashing :</b> A hash function takes an input (or message) and returns a fixed-size string of bytes. The output, typically a hash value, is unique to the input data. Hash functions are commonly used for data integrity checks, password storage, and digital signatures.</div>',
            unsafe_allow_html=True)

    with col2:
        st.markdown(
            '<div class="info-box decrypt slide-animation-right">🔓 <b>Decryption:</b> This is the reverse process of encryption. It involves converting ciphertext back into plaintext using a decryption algorithm and the appropriate key. Decryption allows authorized parties to access the original information.</div>',
            unsafe_allow_html=True)

        st.markdown(
            '<div class="info-box encrypt-hash slide-animation-left">🛡️ <b>Encrypt & Hash:</b> This involves taking a hash value and encrypting it using an encryption algorithm and a key. This can be used to add an additional layer of security, ensuring that even if the hash value is intercepted, it cannot be understood without the decryption key.</div>',
            unsafe_allow_html=True)

# Ensure session state keys exist
if "encrypt_key" not in st.session_state:
    st.session_state["encrypt_key"] = ""
if "decrypt_key" not in st.session_state:
    st.session_state["decrypt_key"] = ""


def derive_key(user_key):
    return base64.urlsafe_b64encode(hashlib.sha256(user_key.encode()).digest())


def encrypt_data(data, key):
    cipher = Fernet(derive_key(key))
    return cipher.encrypt(data)

def decrypt_data(data, key):
    cipher = Fernet(derive_key(key))
    return cipher.decrypt(data)

def hash_data(data):
    return hashlib.sha256(data).hexdigest()

# Handling selected operations
if option == "Encrypt":
    st.header("🔑 Encrypt a File")
    file = st.file_uploader("Upload File", type=["txt", "png", "jpg", "mp3", "wav", "mp4"])
    encrypt_key = st.text_input("Enter Secret Key", type="password", key="encrypt_key")

    if st.button("Encrypt File") and file and encrypt_key:
        with st.spinner("Encrypting... 🛡️"):
            time.sleep(2)
            encrypted_data = encrypt_data(file.read(), encrypt_key)
            enc_filename = f"encrypted_{file.name}"
            st.download_button("Download Encrypted File", encrypted_data, file_name=enc_filename)
            st.success("Encryption Complete! 🎉")

elif option == "Decrypt":
    st.header("🔓 Decrypt a File")
    file = st.file_uploader("Upload Encrypted File", type=["txt", "png", "jpg", "mp3", "wav", "mp4"])
    decrypt_key = st.text_input("Enter Decryption Key", type="password", key="decrypt_key")

    if st.button("Decrypt File") and file and decrypt_key:
        with st.spinner("Decrypting... 🔓"):
            time.sleep(2)
            try:
                decrypted_data = decrypt_data(file.read(), decrypt_key)
                dec_filename = f"decrypted_{file.name}"
                st.download_button("Download Decrypted File", decrypted_data, file_name=dec_filename)
                st.success("Decryption Complete! 🎉")
            except:
                st.error("❌ Incorrect Key! Decryption failed.")

elif option == "Generate Hash":
    st.header("🔢 Generate Hash")
    file = st.file_uploader("Upload File", type=["txt", "png", "jpg", "mp3", "wav", "mp4"])

    if st.button("Generate Hash") and file:
        with st.spinner("Generating Hash... 🧮"):
            time.sleep(1)
            hash_code = hash_data(file.read())
            st.text_area("Generated Hash", hash_code, height=100)
            st.success("Hash Generation Complete! 🎉")

elif option == "Encrypt & Hash":
    st.header("🔐 Encrypt & Generate Hash")
    file = st.file_uploader("Upload File", type=["txt", "png", "jpg", "mp3", "wav", "mp4"])
    encrypt_key = st.text_input("Enter Secret Key", type="password", key="encrypt_key")

    if st.button("Encrypt & Hash") and file and encrypt_key:
        with st.spinner("Encrypting & Hashing... 🛡️🔢"):
            time.sleep(2)
            encrypted_data = encrypt_data(file.read(), encrypt_key)
            hash_code = hash_data(encrypted_data)
            enc_filename = f"encrypted_{file.name}"
            st.download_button("Download Encrypted File", encrypted_data, file_name=enc_filename)
            st.text_area("Generated Hash", hash_code, height=100)
            st.success("Encryption & Hash Generation Complete! 🎉")

# Hide info boxes when an operation is selected
if option != "Select Operation":
    st.markdown(
        """
        <style>
        .info-box {
            display: none;
        }
        </style>
        """, unsafe_allow_html=True
    )
