import streamlit as st
import json
import hashlib
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Utility functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)[:32]

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['hashed_passkey'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# App UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Lockout check
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("Too many failed attempts! Reauthorization required.")

# --- HOME PAGE ---
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to Secure Data Encryption System")
    st.write("This is a simple app to encrypt and decrypt your sensitive data.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data"):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Stored Data"):
            change_page("Retrieve Data")

    st.info(f"🔐 Currently Storing {len(st.session_state.stored_data)} Items")

# --- STORE DATA PAGE ---
elif st.session_state.current_page == "Store Data":
    st.subheader("📥 Store Data Securely")
    user_data = st.text_area("Enter your data here")
    passkey = st.text_input("Enter your password here", type="password")
    confirm_passkey = st.text_input("Confirm your password", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("❌ Passkeys do not match")
            else:
                data_id = generate_data_id()
                encrypted_text = encrypt_data(user_data, passkey)
                hashed_passkey = hash_passkey(passkey)

                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "hashed_passkey": hashed_passkey
                }

                st.success("✅ Data stored successfully!")
                st.code(data_id, language="text")
                st.info("Save this Data ID! You'll need it to retrieve your data.")
        else:
            st.error("❗ All fields are required")

# --- RETRIEVE DATA PAGE ---
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("📤 Retrieve Data Securely")
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter your Data ID")
    passkey = st.text_input("Enter your password", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success("✅ Data decrypted successfully")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"Incorrect password! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("Data ID not found")

            if st.session_state.failed_attempts >= 3:
                st.warning("Too many failed attempts! Redirecting to login page.")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("Both fields are required!")

# --- LOGIN PAGE ---
elif st.session_state.current_page == "Login":
    st.subheader("🔐 Reauthorization Required")

    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"Please wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("Reauthorized successfully!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("Invalid password")

        st.markdown("---")
        st.markdown("_Secure Data Encryption System_")

