# attacker_sim.py
import threading
import time
from datetime import datetime
import encryption

# These will be set from main.py
log_a = None
log_b = None
handle_message_from_a = None
handle_message_from_b = None
attacker_entry = None
get_user_a_aes = None
get_user_b_aes = None

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
    aes_key = get_user_a_aes()
    if aes_key:
        encrypted = encryption.aes_encrypt(aes_key, msg)
        log_b("[!!] Attacker impersonates A ➝ B: " + msg)
        handle_message_from_a(encrypted)
    else:
        log_b("[ALERT] Cannot impersonate A ➝ B: AES key not established")

def impersonate_b():
    msg = attacker_entry.get()
    aes_key = get_user_b_aes()
    if aes_key:
        encrypted = encryption.aes_encrypt(aes_key, msg)
        log_a("[!!] Attacker impersonates B ➝ A: " + msg)
        handle_message_from_b(encrypted)
    else:
        log_a("[ALERT] Cannot impersonate B ➝ A: AES key not established")
