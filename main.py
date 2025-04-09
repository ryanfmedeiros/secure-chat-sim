import customtkinter as ctk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import threading
import time
from datetime import datetime

# --- Crypto Utils ---
def generate_rsa_keypair():
    return RSA.generate(2048)

def rsa_encrypt(public_key, data):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(private_key, ciphertext):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

def aes_encrypt(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(aes_key, encrypted):
    raw = base64.b64decode(encrypted)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# --- Attacker Logic ---
def simulate_dos_attack():
    log_a("[ALERT] DoS attack started: flooding channel")
    log_b("[ALERT] DoS attack started: flooding channel")

    def flood():
        for i in range(20):
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_a(f"[!!] Attacker floods A at {timestamp}")
            log_b(f"[!!] Attacker floods B at {timestamp}")
            handle_message_from_b("FLOOD_DATA")
            handle_message_from_a("FLOOD_DATA")
            time.sleep(0.1)

        log_a("[ALERT] DoS attack ended")
        log_b("[ALERT] DoS attack ended")

    threading.Thread(target=flood).start()

def impersonate_a():
    msg = attacker_entry.get()
    if user_a_aes:
        encrypted = aes_encrypt(user_a_aes, msg)
        log_b("[!!] Attacker impersonates A ➝ B: " + msg)
        handle_message_from_a(encrypted)
    else:
        log_b("[ALERT] Cannot impersonate A ➝ B: AES key not established")

def impersonate_b():
    msg = attacker_entry.get()
    if user_b_aes:
        encrypted = aes_encrypt(user_b_aes, msg)
        log_a("[!!] Attacker impersonates B ➝ A: " + msg)
        handle_message_from_b(encrypted)
    else:
        log_a("[ALERT] Cannot impersonate B ➝ A: AES key not established")

# --- Initial Setup ---
user_a_rsa = generate_rsa_keypair()
user_b_rsa = generate_rsa_keypair()
user_a_pub = user_a_rsa.publickey()
user_b_pub = user_b_rsa.publickey()
user_a_aes = None
user_b_aes = None

# --- GUI Setup ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
window = ctk.CTk()
window.title("Secure Chat with Hybrid Encryption")
window.geometry("1000x800")

# --- Layout ---
main_frame = ctk.CTkFrame(window)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

chat_frame_a = ctk.CTkFrame(main_frame)
chat_frame_b = ctk.CTkFrame(main_frame)
chat_frame_a.grid(row=0, column=0, padx=10, sticky="nsew")
chat_frame_b.grid(row=0, column=1, padx=10, sticky="nsew")
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.rowconfigure(0, weight=1)

chat_log_a = ctk.CTkTextbox(chat_frame_a, width=400, height=400)
chat_log_b = ctk.CTkTextbox(chat_frame_b, width=400, height=400)
chat_log_a.pack(pady=10)
chat_log_b.pack(pady=10)

entry_a = ctk.CTkEntry(chat_frame_a, width=300)
btn_a = ctk.CTkButton(chat_frame_a, text="Send from A", command=lambda: send_from_a())
entry_a.pack(side="left", padx=5, pady=5)
btn_a.pack(side="right", padx=5)

entry_b = ctk.CTkEntry(chat_frame_b, width=300)
btn_b = ctk.CTkButton(chat_frame_b, text="Send from B", command=lambda: send_from_b())
entry_b.pack(side="left", padx=5, pady=5)
btn_b.pack(side="right", padx=5)

attack_frame = ctk.CTkFrame(window)
attack_frame.pack(pady=10)
btn_dos = ctk.CTkButton(attack_frame, text="DoS Attack", command=simulate_dos_attack)
btn_dos.pack(side="left", padx=10)

# --- Impersonation Controls ---
impersonation_frame = ctk.CTkFrame(window)
impersonation_frame.pack(pady=10)
attacker_entry = ctk.CTkEntry(impersonation_frame, width=400, placeholder_text="Attacker message...")
attacker_entry.pack(side="left", padx=5)
btn_impersonate_a = ctk.CTkButton(impersonation_frame, text="Impersonate A ➝ B", command=impersonate_a)
btn_impersonate_b = ctk.CTkButton(impersonation_frame, text="Impersonate B ➝ A", command=impersonate_b)
btn_impersonate_a.pack(side="left", padx=5)
btn_impersonate_b.pack(side="left", padx=5)

# --- Tamper Toggle ---
tamper_frame = ctk.CTkFrame(window)
tamper_frame.pack(pady=10)
tamper_enabled = ctk.BooleanVar()
tamper_checkbox = ctk.CTkCheckBox(tamper_frame, text="Enable Message Tampering", variable=tamper_enabled)
tamper_input = ctk.CTkEntry(tamper_frame, width=400, placeholder_text="Tampered message to inject")
tamper_checkbox.pack(side="left", padx=5)
tamper_input.pack(side="left", padx=5)

# --- Eavesdropper Log ---
eavesdropper_log = ctk.CTkTextbox(window, height=150)
eavesdropper_log.pack(padx=10, pady=10, fill="both")

def eavesdrop_log(message):
    eavesdropper_log.insert("end", "[EAVESDROP] " + message + "\n")
    eavesdropper_log.see("end")

# --- Communication States ---
a_waiting_for_pub = False
b_waiting_for_pub = False
a_ready = False
b_ready = False

# --- Logging ---
def log_a(message):
    chat_log_a.insert("end", message + "\n")
    chat_log_a.see("end")

def log_b(message):
    chat_log_b.insert("end", message + "\n")
    chat_log_b.see("end")

# --- Message Handlers ---
def send_from_a():
    global a_waiting_for_pub
    msg = entry_a.get()
    entry_a.delete(0, 'end')

    if not user_b_aes and not a_waiting_for_pub:
        a_waiting_for_pub = True
        log_a("A sends initial plaintext message")
        handle_message_from_a(msg)
    elif msg == "SEND_KEY":
        encoded_key = user_a_pub.export_key()
        log_a("A sends RSA public key")
        handle_message_from_a(encoded_key, public_key=True)
    elif user_a_aes:
        encrypted = aes_encrypt(user_a_aes, msg)
        log_a("A sends (encrypted): " + encrypted)
        handle_message_from_a(encrypted)
    else:
        log_a("A sends: " + msg)
        handle_message_from_a(msg)

def send_from_b():
    global b_waiting_for_pub
    msg = entry_b.get()
    entry_b.delete(0, 'end')

    if not user_a_aes and not b_waiting_for_pub:
        b_waiting_for_pub = True
        log_b("B sends RSA public key")
        handle_message_from_b(user_b_pub.export_key(), public_key=True)
    elif msg == "SEND_KEY":
        encoded_key = user_b_pub.export_key()
        log_b("B sends RSA public key")
        handle_message_from_b(encoded_key, public_key=True)
    elif user_b_aes:
        encrypted = aes_encrypt(user_b_aes, msg)
        log_b("B sends (encrypted): " + encrypted)
        handle_message_from_b(encrypted)
    else:
        log_b("B sends: " + msg)
        handle_message_from_b(msg)

# --- Simulated Network ---
def handle_message_from_a(data, public_key=False):
    global user_b_aes
    if not public_key:
        eavesdrop_log(f"A -> B: {data}")
    if public_key:
        try:
            key = RSA.import_key(data)
            aes_key = get_random_bytes(16)
            encrypted_aes = rsa_encrypt(key, aes_key)
            user_b_aes = aes_key
            log_b("B receives A's public key and sends AES key")
            handle_message_from_b(encrypted_aes)
        except Exception as e:
            log_b(f"[ERROR] B failed to process public key: {e}")
    elif isinstance(data, bytes):
        try:
            aes_key = rsa_decrypt(user_b_rsa, data)
            user_b_aes = aes_key
            log_b("B receives and stores AES key")
        except Exception as e:
            log_b(f"[ERROR] B failed to decrypt AES key: {e}")
    elif user_b_aes:
        try:
            if tamper_enabled.get():
                tampered = tamper_input.get()
                if tampered:
                    data = aes_encrypt(user_a_aes, tampered)
                    log_b("[!!] Message from A was tampered by attacker")
            decrypted = aes_decrypt(user_b_aes, data)
            log_b("B receives (decrypted): " + decrypted)
        except:
            log_b("B: Decryption failed")
    else:
        log_b("B receives: " + str(data))

def handle_message_from_b(data, public_key=False):
    global user_a_aes
    if not public_key:
        eavesdrop_log(f"B -> A: {data}")
    if public_key:
        try:
            key = RSA.import_key(data)
            aes_key = get_random_bytes(16)
            encrypted_aes = rsa_encrypt(key, aes_key)
            user_a_aes = aes_key
            log_a("A receives B's public key and sends AES key")
            handle_message_from_a(encrypted_aes)
        except Exception as e:
            log_a(f"[ERROR] A failed to process public key: {e}")
    elif isinstance(data, bytes):
        try:
            aes_key = rsa_decrypt(user_a_rsa, data)
            user_a_aes = aes_key
            log_a("A receives and stores AES key")
        except Exception as e:
            log_a(f"[ERROR] A failed to decrypt AES key: {e}")
    elif user_a_aes:
        try:
            if tamper_enabled.get():
                tampered = tamper_input.get()
                if tampered:
                    data = aes_encrypt(user_b_aes, tampered)
                    log_a("[!!] Message from B was tampered by attacker")
            decrypted = aes_decrypt(user_a_aes, data)
            log_a("A receives (decrypted): " + decrypted)
        except:
            log_a("A: Decryption failed")
    else:
        log_a("A receives: " + str(data))

window.mainloop()
