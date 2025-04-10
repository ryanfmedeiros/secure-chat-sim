import customtkinter as ctk
import encryption
import attacker_sim
import chat_logic

# --- RSA Key Generation ---
user_a_rsa = encryption.generate_rsa_keypair()
user_b_rsa = encryption.generate_rsa_keypair()
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

# --- Layout Frames ---
main_frame = ctk.CTkFrame(window)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

chat_frame_a = ctk.CTkFrame(main_frame)
chat_frame_b = ctk.CTkFrame(main_frame)
chat_frame_a.grid(row=0, column=0, padx=10, sticky="nsew")
chat_frame_b.grid(row=0, column=1, padx=10, sticky="nsew")
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.rowconfigure(0, weight=1)

# --- Chatboxes ---
chat_log_a = ctk.CTkTextbox(chat_frame_a, width=400, height=400)
chat_log_b = ctk.CTkTextbox(chat_frame_b, width=400, height=400)
chat_log_a.configure(state="disabled")
chat_log_b.configure(state="disabled")
chat_log_a.pack(pady=10)
chat_log_b.pack(pady=10)

entry_a = ctk.CTkEntry(chat_frame_a, width=300)
entry_b = ctk.CTkEntry(chat_frame_b, width=300)

# --- Tamper Controls ---
tamper_frame = ctk.CTkFrame(window)
tamper_frame.pack(pady=10)
tamper_enabled = ctk.BooleanVar()
tamper_checkbox = ctk.CTkCheckBox(tamper_frame, text="Enable Message Tampering", variable=tamper_enabled)
tamper_input = ctk.CTkEntry(tamper_frame, width=400, placeholder_text="Tampered message to inject")
tamper_checkbox.pack(side="left", padx=5)
tamper_input.pack(side="left", padx=5)

# --- Eavesdropping Log ---
eavesdropper_log = ctk.CTkTextbox(window, height=150)
eavesdropper_log.pack(padx=10, pady=10, fill="both")

# --- Logging Functions ---
def log_a(message):
    chat_log_a.configure(state="normal")
    chat_log_a.insert("end", message + "\n")
    chat_log_a.configure(state="disabled")
    chat_log_a.see("end")

def log_b(message):
    chat_log_b.configure(state="normal")
    chat_log_b.insert("end", message + "\n")
    chat_log_b.configure(state="disabled")
    chat_log_b.see("end")

def eavesdrop_log(message):
    eavesdropper_log.insert("end", "[EAVESDROP] " + message + "\n")
    eavesdropper_log.see("end")

# --- Inject Chat Logic Globals ---
chat_logic.log_a = log_a
chat_logic.log_b = log_b
chat_logic.eavesdrop_log = eavesdrop_log
chat_logic.tamper_enabled = tamper_enabled
chat_logic.tamper_input = tamper_input
chat_logic.user_a_rsa = user_a_rsa
chat_logic.user_b_rsa = user_b_rsa
chat_logic.user_a_pub = user_a_pub
chat_logic.user_b_pub = user_b_pub
chat_logic.user_a_aes = user_a_aes
chat_logic.user_b_aes = user_b_aes

# --- Inject Cross References for Public Key Flow ---
chat_logic.handle_message_from_a_ref = chat_logic.handle_message_from_a
chat_logic.handle_message_from_b_ref = chat_logic.handle_message_from_b

# --- Buttons ---
btn_a = ctk.CTkButton(
    chat_frame_a,
    text="Send from A",
    command=lambda: chat_logic.send_from_a(entry_a)
)
btn_b = ctk.CTkButton(
    chat_frame_b,
    text="Send from B",
    command=lambda: chat_logic.send_from_b(entry_b)
)
entry_a.pack(side="left", padx=5, pady=5)
btn_a.pack(side="right", padx=5)
entry_b.pack(side="left", padx=5, pady=5)
btn_b.pack(side="right", padx=5)

# --- Attack Panel ---
attack_frame = ctk.CTkFrame(window)
attack_frame.pack(pady=10)
btn_dos = ctk.CTkButton(attack_frame, text="DoS Attack", command=attacker_sim.simulate_dos_attack)
btn_dos.pack(side="left", padx=10)

# --- Impersonation Panel ---
impersonation_frame = ctk.CTkFrame(window)
impersonation_frame.pack(pady=10)
attacker_entry = ctk.CTkEntry(impersonation_frame, width=400, placeholder_text="Attacker message...")
attacker_entry.pack(side="left", padx=5)
btn_impersonate_a = ctk.CTkButton(impersonation_frame, text="Impersonate A ➝ B", command=attacker_sim.impersonate_a)
btn_impersonate_b = ctk.CTkButton(impersonation_frame, text="Impersonate B ➝ A", command=attacker_sim.impersonate_b)
btn_impersonate_a.pack(side="left", padx=5)
btn_impersonate_b.pack(side="left", padx=5)

# --- Inject Attacker Logic Dependencies ---
attacker_sim.log_a = log_a
attacker_sim.log_b = log_b
attacker_sim.attacker_entry = attacker_entry
attacker_sim.get_user_a_aes = lambda: chat_logic.user_a_aes
attacker_sim.get_user_b_aes = lambda: chat_logic.user_b_aes
attacker_sim.handle_message_from_a = chat_logic.handle_message_from_a
attacker_sim.handle_message_from_b = chat_logic.handle_message_from_b

# --- Run App ---
window.mainloop()
