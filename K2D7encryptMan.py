import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ----------------- CRYPTOGRAPHIC MATRIX ENGINE -----------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100_000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(plaintext_str: str, password: str) -> bytes:
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext_str.encode('utf-8')) + encryptor.finalize()
    return salt + iv + encryptor.tag + ciphertext

def decrypt_data(file_bytes: bytes, password: str) -> str:
    if len(file_bytes) < 48:
        raise ValueError("Invalid structural layout.")
    salt, iv, tag, ciphertext = file_bytes[:16], file_bytes[16:32], file_bytes[32:48], file_bytes[48:]
    key = derive_key(password, salt)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

# ----------------- DESKTOP INTERFACE WINDOW -----------------
class K2D7encryptMan:
    def __init__(self, root):
        self.root = root
        self.root.title("K2D7encryptMan - Secure Note Hub")
        self.root.geometry("1000x650")
        
        self.storage_dir = os.path.join(os.getcwd(), "K2D7encryptMan")
        os.makedirs(self.storage_dir, exist_ok=True)

        # Settings variables
        self.theme_var = tk.StringVar(value="Dark Mode")
        self.autolock_var = tk.StringVar(value="5 min")
        self.font_size_var = tk.StringVar(value="Normal")
        
        self.timer, self.pwd, self.current_file, self.raw_data, self.unlocked = None, None, None, None, False

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True)
        self.tab1, self.tab2 = ttk.Frame(self.nb), ttk.Frame(self.nb)
        self.nb.add(self.tab1, text=" Workspace "), self.nb.add(self.tab2, text=" Settings ")

        # Workspace Tab Layout
        self.split = ttk.PanedWindow(self.tab1, orient=tk.HORIZONTAL)
        self.split.pack(fill=tk.BOTH, expand=True)
        
        # Left Panel (Sidebar)
        self.left = ttk.Frame(self.split, width=220, relief=tk.SUNKEN)
        self.split.add(self.left, weight=1)
        self.listbox = tk.Listbox(self.left, bd=0)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)
        
        ttk.Button(self.left, text="New File", command=self.new_file).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(self.left, text="Refresh", command=self.refresh).pack(fill=tk.X, padx=5, pady=2)

        # Right Panel (Main Content & Action Dock)
        self.right = ttk.Frame(self.split)
        self.split.add(self.right, weight=4)

        # Text canvas setup
        self.text = tk.Text(self.right, undo=True, font=("Consolas", 14), wrap=tk.WORD, bd=0)
        self.text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 50))
        self.text.bind("<Key>", self.reset_timer)
        self.text.bind("<Button-1>", self.reset_timer)

        # Control panel overlay frame pinned down at the bottom margin
        self.action_frame = ttk.Frame(self.right)
        self.action_frame.place(relx=0.0, rely=1.0, relwidth=1.0, height=45, anchor="sw")

        self.btn_unlock = tk.Button(self.action_frame, text="🔓 Unlock File", bg="#28a745", fg="white", font=("Arial", 10, "bold"), command=self.decrypt, state=tk.DISABLED, bd=0)
        self.btn_unlock.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 2), pady=5)

        self.btn_save = tk.Button(self.action_frame, text="💾 Save Changes (Ctrl+S)", bg="#007bff", fg="white", font=("Arial", 10, "bold"), command=self.save, state=tk.DISABLED, bd=0)
        self.btn_save.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(2, 5), pady=5)

        # --- Settings Tab Layout ---
        
        # 1. Display Settings
        self.lf_disp = ttk.LabelFrame(self.tab2, text=" Display Settings ", padding=15)
        self.lf_disp.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(self.lf_disp, text="Theme Profile:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Combobox(self.lf_disp, textvariable=self.theme_var, values=["Dark Mode", "Light Mode"], state="readonly", width=15).pack(side=tk.LEFT, padx=(0, 30))
        self.theme_var.trace_add("write", lambda *a: self.update_view_preferences())

        ttk.Label(self.lf_disp, text="Text Font Size:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Combobox(self.lf_disp, textvariable=self.font_size_var, values=["Small", "Normal", "Large"], state="readonly", width=12).pack(side=tk.LEFT)
        self.font_size_var.trace_add("write", lambda *a: self.update_view_preferences())

        # 2. Security Settings
        self.lf_sec = ttk.LabelFrame(self.tab2, text=" Security Settings ", padding=15)
        self.lf_sec.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(self.lf_sec, text="Auto-Lock Inactivity Timeout:").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Combobox(self.lf_sec, textvariable=self.autolock_var, values=["Off", "1 min", "5 min", "10 min", "30 min", "1 hour"], state="readonly").pack(side=tk.LEFT)
        self.autolock_var.trace_add("write", lambda *a: self.reset_timer())

        self.root.bind("<Control-s>", lambda e: self.save())
        self.refresh(); self.update_view_preferences(); self.reset_timer()

    def update_view_preferences(self):
        """Updates theme colors and text font sizing simultaneously."""
        # 1. Handle Colors
        d = self.theme_var.get() == "Dark Mode"
        bg_color = "#1e1e1e" if d else "white"
        fg_color = "#00ff66" if d else "black"
        cursor_color = "white" if d else "black"
        
        self.listbox.config(bg="#252526" if d else "white", fg="#d4d4d4" if d else "black")

        # 2. Handle Text Font Scale Layout
        font_map = {"Small": 10, "Normal": 14, "Large": 18}
        selected_size = font_map.get(self.font_size_var.get(), 14)

        # Apply settings configuration matrix directly
        self.text.config(
            bg=bg_color, 
            fg=fg_color, 
            insertbackground=cursor_color,
            font=("Consolas", selected_size)
        )

    def refresh(self):
        self.listbox.delete(0, tk.END)
        for f in sorted(os.listdir(self.storage_dir)):
            if f.endswith('.k2d7'): self.listbox.insert(tk.END, f)

    def new_file(self):
        self.text.delete(1.0, tk.END)
        self.current_file, self.raw_data, self.pwd, self.unlocked = None, None, None, False
        self.btn_unlock.config(state=tk.DISABLED); self.btn_save.config(state=tk.NORMAL)

    def on_select(self, e):
        sel = self.listbox.curselection()
        if not sel: return
        self.current_file = os.path.join(self.storage_dir, self.listbox.get(sel))
        with open(self.current_file, 'rb') as f: self.raw_data = f.read()
        self.unlocked, self.pwd = False, None
        b64 = base64.b64encode(self.raw_data).decode('utf-8')
        self.text.delete(1.0, tk.END)
        self.text.insert(tk.END, "--- ENCRYPTED DATA CONTAINER DATA STREAM ---\n\n" + "\n".join(b64[i:i+64] for i in range(0, len(b64), 64)))
        self.btn_unlock.config(state=tk.NORMAL); self.btn_save.config(state=tk.DISABLED)

    def decrypt(self):
        p = simpledialog.askstring("Auth Manager", "Enter Decryption Password Key:", show="*")
        if not p: return
        try:
            txt = decrypt_data(self.raw_data, p)
            self.text.delete(1.0, tk.END); self.text.insert(tk.END, txt)
            self.pwd, self.unlocked = p, True
            self.btn_unlock.config(state=tk.DISABLED); self.btn_save.config(state=tk.NORMAL)
        except Exception: messagebox.showerror("Access Denied", "Incorrect validation password sequence.")

    def save(self):
        if not self.unlocked:
            path = filedialog.asksaveasfilename(initialdir=self.storage_dir, defaultextension=".k2d7", filetypes=[("K2D7 Vault Files", "*.k2d7")])
            if not path: return
            p = simpledialog.askstring("Key Registration", "Assign Master Node Password:", show="*")
            if not p: return
            self.current_file, self.pwd, self.unlocked = path, p, True
        
        blob = encrypt_data(self.text.get(1.0, tk.END), self.pwd)
        with open(self.current_file, 'wb') as f: f.write(blob)
        messagebox.showinfo("Encrypted Node Saved", "Changes safely committed directly to storage directory.")
        self.refresh(); self.new_file()

    def reset_timer(self, e=None):
        if self.timer: self.root.after_cancel(self.timer)
        v = self.autolock_var.get()
        if v == "Off": return
        m = {"1 min":1, "5 min":5, "10 min":10, "30 min":30, "1 hour":60}[v]
        self.timer = self.root.after(m * 60 * 1000, self.lock)

    def lock(self):
        if self.unlocked: self.new_file(); messagebox.showwarning("Auto-Lock Triggered", "Session validation expired due to idleness.")

if __name__ == "__main__":
    root = tk.Tk()
    app = K2D7encryptMan(root)
    root.mainloop()
