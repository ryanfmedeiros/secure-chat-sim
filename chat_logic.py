# chat_logic.py
import encryption
from datetime import datetime

# Injected from main
log_a = None
log_b = None
eavesdrop_log = None
tamper_enabled = None
tamper_input = None
user_a_rsa = None
user_b_rsa = None
user_a_pub = None
user_b_pub = None
user_a_aes = None
user_b_aes = None

# References injected from main
handle_message_from_a_ref = None
handle_message_from_b_ref = None

def send_from_a(entry_a):
    global user_a_pub, user_b_aes, user_a_aes
    msg = entry_a.get()
    entry_a.delete(0, 'end')

    if not user_b_aes:
        log_a("A sends initial plaintext message")
        handle_message_from_a(msg)
    elif msg == "SEND_KEY":
        encoded_key = user_a_pub.export_key()
        log_a("A sends RSA public key")
        handle_message_from_a(encoded_key, public_key=True)
    elif user_a_aes:
        encrypted = encryption.aes_encrypt(user_a_aes, msg)
        log_a("A sends (encrypted): " + encrypted)
        handle_message_from_a(encrypted)
    else:
        log_a("A sends: " + msg)
        handle_message_from_a(msg)

def send_from_b(entry_b):
    global user_b_pub, user_a_aes, user_b_aes
    msg = entry_b.get()
    entry_b.delete(0, 'end')

    if not user_a_aes:
        log_b("B sends RSA public key")
        handle_message_from_b(user_b_pub.export_key(), public_key=True)
    elif msg == "SEND_KEY":
        encoded_key = user_b_pub.export_key()
        log_b("B sends RSA public key")
        handle_message_from_b(encoded_key, public_key=True)
    elif user_b_aes:
        encrypted = encryption.aes_encrypt(user_b_aes, msg)
        log_b("B sends (encrypted): " + encrypted)
        handle_message_from_b(encrypted)
    else:
        log_b("B sends: " + msg)
        handle_message_from_b(msg)

def handle_message_from_a(data, public_key=False):
    global user_b_aes, user_b_rsa, user_a_aes

    if not public_key:
        eavesdrop_log(f"A -> B: {data}")

    if public_key:
        try:
            key = encryption.RSA.import_key(data)
            aes_key = encryption.get_random_bytes(16)
            encrypted_aes = encryption.rsa_encrypt(key, aes_key)
            user_b_aes = aes_key
            log_b("B receives A's public key and sends AES key")
            handle_message_from_b_ref(encrypted_aes)
        except Exception as e:
            log_b(f"[ERROR] B failed to process public key: {e}")
    elif isinstance(data, bytes):
        try:
            aes_key = encryption.rsa_decrypt(user_b_rsa, data)
            user_b_aes = aes_key
            log_b("B receives and stores AES key")
        except Exception as e:
            log_b(f"[ERROR] B failed to decrypt AES key: {e}")
    elif user_b_aes:
        try:
            if tamper_enabled.get():
                tampered = tamper_input.get()
                if tampered:
                    data = encryption.aes_encrypt(user_a_aes, tampered)
                    log_b("[!!] Message from A was tampered by attacker")
            decrypted = encryption.aes_decrypt(user_b_aes, data)
            log_b("B receives (decrypted): " + decrypted)
        except:
            log_b("B: Decryption failed")
    else:
        log_b("B receives: " + str(data))

def handle_message_from_b(data, public_key=False):
    global user_a_aes, user_a_rsa, user_b_aes

    if not public_key:
        eavesdrop_log(f"B -> A: {data}")

    if public_key:
        try:
            key = encryption.RSA.import_key(data)
            aes_key = encryption.get_random_bytes(16)
            encrypted_aes = encryption.rsa_encrypt(key, aes_key)
            user_a_aes = aes_key
            log_a("A receives B's public key and sends AES key")
            handle_message_from_a_ref(encrypted_aes)
        except Exception as e:
            log_a(f"[ERROR] A failed to process public key: {e}")
    elif isinstance(data, bytes):
        try:
            aes_key = encryption.rsa_decrypt(user_a_rsa, data)
            user_a_aes = aes_key
            log_a("A receives and stores AES key")
        except Exception as e:
            log_a(f"[ERROR] A failed to decrypt AES key: {e}")
    elif user_a_aes:
        try:
            if tamper_enabled.get():
                tampered = tamper_input.get()
                if tampered:
                    data = encryption.aes_encrypt(user_b_aes, tampered)
                    log_a("[!!] Message from B was tampered by attacker")
            decrypted = encryption.aes_decrypt(user_a_aes, data)
            log_a("A receives (decrypted): " + decrypted)
        except:
            log_a("A: Decryption failed")
    else:
        log_a("A receives: " + str(data))
