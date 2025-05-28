import customtkinter as ctk
import base64
from tkinter import messagebox, filedialog
import random
import string
import hashlib
import secrets
import os
import json
from datetime import datetime
import threading
import time

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CryptoApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("🔐 Advanced Crypto Suite")
        self.app.geometry("900x700")
        self.app.resizable(True, True)
        
        # Color scheme
        self.colors = {
            'primary': "#1e293b",
            'secondary': "#334155",
            'accent': "#3b82f6",
            'success': "#10b981",
            'warning': "#f59e0b",
            'danger': "#ef4444",
            'text': "#f8fafc"
        }
        
        # Variables
        self.mode = ctk.StringVar(value="Encrypt")
        self.encryption_method = ctk.StringVar(value="Vigenère Cipher")
        self.theme_mode = ctk.StringVar(value="Dark")
        
        # Animation variables
        self.gradient_colors = ["#1e293b", "#334155", "#475569", "#64748b"]
        self.bg_index = 0
        
        # History for operations
        self.operation_history = []
        
        self.setup_gui()
        self.animate_background()
        
    def setup_gui(self):
        # Main container with padding
        main_container = ctk.CTkFrame(self.app, corner_radius=0, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header with animated title
        self.create_header(main_container)
        
        # Main content area with tabs
        self.create_main_content(main_container)
        
        # Status bar
        self.create_status_bar(main_container)
        
    def create_header(self, parent):
        header_frame = ctk.CTkFrame(parent, height=80, corner_radius=15, 
                                   fg_color=self.colors['primary'])
        header_frame.pack(fill="x", pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Title with gradient effect
        title_label = ctk.CTkLabel(header_frame, 
                                  text="🔐 ADVANCED CRYPTO SUITE", 
                                  font=ctk.CTkFont(size=28, weight="bold"),
                                  text_color=self.colors['text'])
        title_label.pack(pady=20)
        
        # Theme toggle button
        theme_btn = ctk.CTkButton(header_frame, text="🌙", width=40, height=30,
                                 command=self.toggle_theme,
                                 fg_color=self.colors['accent'])
        theme_btn.place(relx=0.95, rely=0.5, anchor="center")
        
    def create_main_content(self, parent):
        # Create tabview
        self.tabview = ctk.CTkTabview(parent, corner_radius=15)
        self.tabview.pack(fill="both", expand=True)
        
        # Add tabs
        self.encryption_tab = self.tabview.add("🔒 Encryption")
        self.tools_tab = self.tabview.add("🛠️ Tools")
        self.history_tab = self.tabview.add("📜 History")
        self.settings_tab = self.tabview.add("⚙️ Settings")
        
        self.setup_encryption_tab()
        self.setup_tools_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
    def setup_encryption_tab(self):
        # Scrollable frame for encryption content
        scroll_frame = ctk.CTkScrollableFrame(self.encryption_tab, corner_radius=10)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Input section with modern design
        input_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                  fg_color=self.colors['secondary'])
        input_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(input_frame, text="📝 Message Input", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        # Message input with character counter
        self.msg_textbox = ctk.CTkTextbox(input_frame, height=100, 
                                         corner_radius=10, wrap="word")
        self.msg_textbox.pack(fill="x", padx=15, pady=(0, 10))
        self.msg_textbox.bind("<KeyRelease>", self.update_char_count)
        
        self.char_count_label = ctk.CTkLabel(input_frame, text="Characters: 0", 
                                            text_color="gray")
        self.char_count_label.pack(pady=(0, 15))
        
        # Key section with strength indicator
        key_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                fg_color=self.colors['secondary'])
        key_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(key_frame, text="🔑 Encryption Key", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        key_input_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        key_input_frame.pack(fill="x", padx=15)
        
        self.key_entry = ctk.CTkEntry(key_input_frame, height=40, 
                                     placeholder_text="Enter your secret key",
                                     corner_radius=10)
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.key_entry.bind("<KeyRelease>", self.update_strength)
        
        self.generate_key_btn = ctk.CTkButton(key_input_frame, text="🎲 Generate", 
                                            width=100, height=40,
                                            command=self.generate_secure_key,
                                            fg_color=self.colors['success'])
        self.generate_key_btn.pack(side="right")
        
        # Key strength with visual indicator
        strength_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        strength_frame.pack(fill="x", padx=15, pady=10)
        
        self.key_strength_label = ctk.CTkLabel(strength_frame, text="Key Strength:", 
                                              font=ctk.CTkFont(weight="bold"))
        self.key_strength_label.pack(side="left")
        
        self.strength_progress = ctk.CTkProgressBar(strength_frame, width=200, height=10)
        self.strength_progress.pack(side="right", padx=(10, 0))
        self.strength_progress.set(0)
        
        # Method selection
        method_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                   fg_color=self.colors['secondary'])
        method_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(method_frame, text="🔧 Encryption Method", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        methods = ["Vigenère Cipher", "Caesar Cipher", "XOR Cipher", "Base64 Encoding"]
        self.method_menu = ctk.CTkOptionMenu(method_frame, values=methods, 
                                           variable=self.encryption_method,
                                           height=40, corner_radius=10)
        self.method_menu.pack(padx=15, pady=(0, 15))
        
        # Operation buttons
        operation_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                      fg_color=self.colors['secondary'])
        operation_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(operation_frame, text="⚡ Operations", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        btn_container = ctk.CTkFrame(operation_frame, fg_color="transparent")
        btn_container.pack(padx=15, pady=(0, 15))
        
        # Mode selection
        mode_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
        mode_frame.pack(fill="x", pady=(0, 10))
        
        self.encrypt_radio = ctk.CTkRadioButton(mode_frame, text="🔒 Encrypt", 
                                               variable=self.mode, value="Encrypt")
        self.encrypt_radio.pack(side="left", padx=(0, 20))
        
        self.decrypt_radio = ctk.CTkRadioButton(mode_frame, text="🔓 Decrypt", 
                                               variable=self.mode, value="Decrypt")
        self.decrypt_radio.pack(side="left")
        
        # Action buttons
        button_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        self.process_btn = ctk.CTkButton(button_frame, text="🚀 Process", 
                                        height=45, corner_radius=10,
                                        command=self.process_message,
                                        fg_color=self.colors['accent'],
                                        font=ctk.CTkFont(size=14, weight="bold"))
        self.process_btn.pack(side="left", padx=(0, 10))
        
        self.copy_btn = ctk.CTkButton(button_frame, text="📋 Copy Result", 
                                     height=45, corner_radius=10,
                                     command=self.copy_result,
                                     fg_color=self.colors['success'])
        self.copy_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = ctk.CTkButton(button_frame, text="🗑️ Clear", 
                                      height=45, corner_radius=10,
                                      command=self.clear_fields,
                                      fg_color=self.colors['warning'])
        self.clear_btn.pack(side="left")
        
        # Output section
        output_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                   fg_color=self.colors['secondary'])
        output_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(output_frame, text="📤 Result", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        self.output_textbox = ctk.CTkTextbox(output_frame, height=100, 
                                            corner_radius=10, wrap="word")
        self.output_textbox.pack(fill="x", padx=15, pady=(0, 15))
        
    def setup_tools_tab(self):
        tools_scroll = ctk.CTkScrollableFrame(self.tools_tab, corner_radius=10)
        tools_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Hash Generator
        hash_frame = ctk.CTkFrame(tools_scroll, corner_radius=15, 
                                 fg_color=self.colors['secondary'])
        hash_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(hash_frame, text="🔗 Hash Generator", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        self.hash_entry = ctk.CTkEntry(hash_frame, height=40, 
                                      placeholder_text="Enter text to hash")
        self.hash_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        hash_methods = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        self.hash_method = ctk.CTkOptionMenu(hash_frame, values=hash_methods)
        self.hash_method.pack(padx=15, pady=(0, 10))
        
        ctk.CTkButton(hash_frame, text="Generate Hash", 
                     command=self.generate_hash,
                     fg_color=self.colors['accent']).pack(pady=(0, 10))
        
        self.hash_output = ctk.CTkTextbox(hash_frame, height=60)
        self.hash_output.pack(fill="x", padx=15, pady=(0, 15))
        
        # File Encryption
        file_frame = ctk.CTkFrame(tools_scroll, corner_radius=15, 
                                 fg_color=self.colors['secondary'])
        file_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(file_frame, text="📁 File Encryption", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        file_btn_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_btn_frame.pack(padx=15, pady=(0, 15))
        
        ctk.CTkButton(file_btn_frame, text="📂 Select File", 
                     command=self.select_file,
                     fg_color=self.colors['accent']).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(file_btn_frame, text="🔒 Encrypt File", 
                     command=self.encrypt_file,
                     fg_color=self.colors['success']).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(file_btn_frame, text="🔓 Decrypt File", 
                     command=self.decrypt_file,
                     fg_color=self.colors['warning']).pack(side="left")
        
        self.file_status = ctk.CTkLabel(file_frame, text="No file selected", 
                                       text_color="gray")
        self.file_status.pack(pady=(0, 15))
        
    def setup_history_tab(self):
        history_scroll = ctk.CTkScrollableFrame(self.history_tab, corner_radius=10)
        history_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        # History header
        header_frame = ctk.CTkFrame(history_scroll, corner_radius=15, 
                                   fg_color=self.colors['secondary'])
        header_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(header_frame, text="📜 Operation History", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
        
        # History list
        self.history_frame = ctk.CTkFrame(history_scroll, corner_radius=15, 
                                         fg_color=self.colors['secondary'])
        self.history_frame.pack(fill="both", expand=True)
        
        self.update_history_display()
        
    def setup_settings_tab(self):
        settings_scroll = ctk.CTkScrollableFrame(self.settings_tab, corner_radius=10)
        settings_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Appearance settings
        appearance_frame = ctk.CTkFrame(settings_scroll, corner_radius=15, 
                                       fg_color=self.colors['secondary'])
        appearance_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(appearance_frame, text="🎨 Appearance", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        theme_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        theme_frame.pack(padx=15, pady=(0, 15))
        
        ctk.CTkLabel(theme_frame, text="Theme:").pack(side="left", padx=(0, 10))
        
        theme_menu = ctk.CTkOptionMenu(theme_frame, values=["Dark", "Light"], 
                                      variable=self.theme_mode,
                                      command=self.change_theme)
        theme_menu.pack(side="left")
        
        # Security settings
        security_frame = ctk.CTkFrame(settings_scroll, corner_radius=15, 
                                     fg_color=self.colors['secondary'])
        security_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(security_frame, text="🔐 Security", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        self.auto_clear_var = ctk.BooleanVar(value=False)
        auto_clear_check = ctk.CTkCheckBox(security_frame, 
                                          text="Auto-clear sensitive data",
                                          variable=self.auto_clear_var)
        auto_clear_check.pack(padx=15, pady=(0, 15))
        
    def create_status_bar(self, parent):
        self.status_frame = ctk.CTkFrame(parent, height=30, corner_radius=10, 
                                        fg_color=self.colors['primary'])
        self.status_frame.pack(fill="x", pady=(10, 0))
        self.status_frame.pack_propagate(False)
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", 
                                        font=ctk.CTkFont(size=12))
        self.status_label.pack(side="left", padx=10, pady=5)
        
        time_label = ctk.CTkLabel(self.status_frame, 
                                 text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                 font=ctk.CTkFont(size=12))
        time_label.pack(side="right", padx=10, pady=5)
        
    # Encryption methods
    def vigenere_encode(self, key, msg):
        enc = []
        for i in range(len(msg)):
            key_char = key[i % len(key)]
            enc_char = chr((ord(msg[i]) + ord(key_char)) % 256)
            enc.append(enc_char)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()
    
    def vigenere_decode(self, key, code):
        try:
            dec = []
            enc = base64.urlsafe_b64decode(code).decode()
            for i in range(len(enc)):
                key_char = key[i % len(key)]
                dec_char = chr((256 + ord(enc[i]) - ord(key_char)) % 256)
                dec.append(dec_char)
            return "".join(dec)
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    def caesar_encode(self, key, msg):
        shift = sum(ord(c) for c in key) % 26
        result = ""
        for char in msg:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return base64.urlsafe_b64encode(result.encode()).decode()
    
    def caesar_decode(self, key, code):
        try:
            shift = sum(ord(c) for c in key) % 26
            msg = base64.urlsafe_b64decode(code).decode()
            result = ""
            for char in msg:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    result += char
            return result
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    def xor_encode(self, key, msg):
        result = []
        for i, char in enumerate(msg):
            key_char = key[i % len(key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        return base64.urlsafe_b64encode("".join(result).encode()).decode()
    
    def xor_decode(self, key, code):
        try:
            enc = base64.urlsafe_b64decode(code).decode()
            result = []
            for i, char in enumerate(enc):
                key_char = key[i % len(key)]
                result.append(chr(ord(char) ^ ord(key_char)))
            return "".join(result)
        except Exception as e:
            return f"Decryption failed: {str(e)}"
    
    # GUI event handlers
    def update_char_count(self, event=None):
        text = self.msg_textbox.get("1.0", "end-1c")
        count = len(text)
        self.char_count_label.configure(text=f"Characters: {count}")
        
    def update_strength(self, event=None):
        key = self.key_entry.get()
        strength, score = self.evaluate_key_strength(key)
        
        colors = {"Weak": "red", "Medium": "orange", "Strong": "green", "Very Strong": "darkgreen"}
        self.key_strength_label.configure(text=f"Key Strength: {strength}", 
                                         text_color=colors.get(strength, "gray"))
        self.strength_progress.set(score)
        
    def evaluate_key_strength(self, key):
        if len(key) == 0:
            return "None", 0.0
        
        score = 0
        # Length factor
        if len(key) >= 8:
            score += 0.3
        elif len(key) >= 6:
            score += 0.2
        elif len(key) >= 4:
            score += 0.1
            
        # Character variety
        has_lower = any(c.islower() for c in key)
        has_upper = any(c.isupper() for c in key)
        has_digit = any(c.isdigit() for c in key)
        has_special = any(c in string.punctuation for c in key)
        
        variety_score = sum([has_lower, has_upper, has_digit, has_special]) * 0.15
        score += variety_score
        
        # Entropy factor
        if len(set(key)) / len(key) > 0.8:
            score += 0.1
            
        score = min(score, 1.0)
        
        if score < 0.3:
            return "Weak", score
        elif score < 0.6:
            return "Medium", score
        elif score < 0.8:
            return "Strong", score
        else:
            return "Very Strong", score
    
    def generate_secure_key(self):
        # Generate a cryptographically secure random key
        length = random.randint(12, 20)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        key = ''.join(secrets.choice(chars) for _ in range(length))
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key)
        self.update_strength()
        self.update_status("Secure key generated")
        
    def process_message(self):
        msg = self.msg_textbox.get("1.0", "end-1c")
        key = self.key_entry.get()
        operation = self.mode.get()
        method = self.encryption_method.get()
        
        if not msg or not key:
            messagebox.showwarning("Input Error", "Please enter both message and key.")
            return
            
        try:
            if method == "Vigenère Cipher":
                if operation == "Encrypt":
                    result = self.vigenere_encode(key, msg)
                else:
                    result = self.vigenere_decode(key, msg)
            elif method == "Caesar Cipher":
                if operation == "Encrypt":
                    result = self.caesar_encode(key, msg)
                else:
                    result = self.caesar_decode(key, msg)
            elif method == "XOR Cipher":
                if operation == "Encrypt":
                    result = self.xor_encode(key, msg)
                else:
                    result = self.xor_decode(key, msg)
            elif method == "Base64 Encoding":
                if operation == "Encrypt":
                    result = base64.urlsafe_b64encode(msg.encode()).decode()
                else:
                    try:
                        result = base64.urlsafe_b64decode(msg).decode()
                    except Exception as e:
                        result = f"Decoding failed: {str(e)}"
            
            self.output_textbox.delete("1.0", "end")
            self.output_textbox.insert("1.0", result)
            
            # Add to history
            self.add_to_history(operation, method, msg[:50] + "..." if len(msg) > 50 else msg)
            self.update_status(f"{operation} completed successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
            self.update_status("Operation failed")
    
    def copy_result(self):
        result = self.output_textbox.get("1.0", "end-1c")
        if result:
            self.app.clipboard_clear()
            self.app.clipboard_append(result)
            self.update_status("Result copied to clipboard")
        else:
            messagebox.showinfo("Info", "No result to copy")
    
    def clear_fields(self):
        self.msg_textbox.delete("1.0", "end")
        self.key_entry.delete(0, "end")
        self.output_textbox.delete("1.0", "end")
        self.char_count_label.configure(text="Characters: 0")
        self.key_strength_label.configure(text="Key Strength:")
        self.strength_progress.set(0)
        self.update_status("Fields cleared")
    
    def generate_hash(self):
        text = self.hash_entry.get()
        method = self.hash_method.get()
        
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash.")
            return
        
        try:
            if method == "MD5":
                hash_obj = hashlib.md5(text.encode())
            elif method == "SHA-1":
                hash_obj = hashlib.sha1(text.encode())
            elif method == "SHA-256":
                hash_obj = hashlib.sha256(text.encode())
            elif method == "SHA-512":
                hash_obj = hashlib.sha512(text.encode())
            
            result = hash_obj.hexdigest()
            self.hash_output.delete("1.0", "end")
            self.hash_output.insert("1.0", result)
            self.update_status(f"{method} hash generated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Hash generation failed: {str(e)}")
    
    def select_file(self):
        self.selected_file = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if self.selected_file:
            filename = os.path.basename(self.selected_file)
            self.file_status.configure(text=f"Selected: {filename}")
            self.update_status(f"File selected: {filename}")
    
    def encrypt_file(self):
        if not hasattr(self, 'selected_file') or not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("No Key", "Please enter an encryption key.")
            return
        
        try:
            with open(self.selected_file, 'rb') as f:
                file_data = f.read()
            
            # Simple XOR encryption for files
            encrypted_data = bytearray()
            for i, byte in enumerate(file_data):
                key_byte = ord(key[i % len(key)])
                encrypted_data.append(byte ^ key_byte)
            
            # Save encrypted file
            encrypted_filename = self.selected_file + ".encrypted"
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)
            
            messagebox.showinfo("Success", f"File encrypted and saved as:\n{encrypted_filename}")
            self.update_status("File encrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")
    
    def decrypt_file(self):
        if not hasattr(self, 'selected_file') or not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("No Key", "Please enter the decryption key.")
            return
        
        try:
            with open(self.selected_file, 'rb') as f:
                encrypted_data = f.read()
            
            # XOR decryption (same as encryption)
            decrypted_data = bytearray()
            for i, byte in enumerate(encrypted_data):
                key_byte = ord(key[i % len(key)])
                decrypted_data.append(byte ^ key_byte)
            
            # Save decrypted file
            if self.selected_file.endswith('.encrypted'):
                decrypted_filename = self.selected_file[:-10]  # Remove .encrypted
            else:
                decrypted_filename = self.selected_file + ".decrypted"
            
            with open(decrypted_filename, 'wb') as f:
                f.write(decrypted_data)
            
            messagebox.showinfo("Success", f"File decrypted and saved as:\n{decrypted_filename}")
            self.update_status("File decrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")
    
    def add_to_history(self, operation, method, message_preview):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry = {
            'timestamp': timestamp,
            'operation': operation,
            'method': method,
            'message': message_preview
        }
        self.operation_history.append(history_entry)
        self.update_history_display()
        
        # Keep only last 50 entries
        if len(self.operation_history) > 50:
            self.operation_history = self.operation_history[-50:]
    
    def update_history_display(self):
        # Clear existing history display
        for widget in self.history_frame.winfo_children():
            widget.destroy()
        
        if not self.operation_history:
            no_history_label = ctk.CTkLabel(self.history_frame, 
                                           text="No operations performed yet",
                                           text_color="gray")
            no_history_label.pack(pady=20)
            return
        
        # Display recent operations
        for i, entry in enumerate(reversed(self.operation_history[-10:])):  # Show last 10
            entry_frame = ctk.CTkFrame(self.history_frame, corner_radius=10,
                                      fg_color=self.colors['primary'])
            entry_frame.pack(fill="x", padx=10, pady=5)
            
            # Time and operation
            header_text = f"🕒 {entry['timestamp']} - {entry['operation']} ({entry['method']})"
            header_label = ctk.CTkLabel(entry_frame, text=header_text,
                                       font=ctk.CTkFont(size=12, weight="bold"))
            header_label.pack(anchor="w", padx=10, pady=(5, 0))
            
            # Message preview
            message_label = ctk.CTkLabel(entry_frame, text=f"Message: {entry['message']}",
                                        text_color="gray", font=ctk.CTkFont(size=11))
            message_label.pack(anchor="w", padx=10, pady=(0, 5))
    
    def toggle_theme(self):
        current = ctk.get_appearance_mode()
        new_mode = "light" if current == "dark" else "dark"
        ctk.set_appearance_mode(new_mode)
        self.theme_mode.set("Light" if new_mode == "light" else "Dark")
        self.update_status(f"Theme changed to {new_mode}")
    
    def change_theme(self, value):
        mode = "light" if value == "Light" else "dark"
        ctk.set_appearance_mode(mode)
        self.update_status(f"Theme changed to {mode}")
    
    def update_status(self, message):
        self.status_label.configure(text=message)
        # Auto-clear status after 3 seconds
        self.app.after(3000, lambda: self.status_label.configure(text="Ready"))
    
    def animate_background(self):
        # Subtle background animation
        try:
            self.app.configure(fg_color=self.gradient_colors[self.bg_index])
            self.bg_index = (self.bg_index + 1) % len(self.gradient_colors)
            self.app.after(5000, self.animate_background)  # Change every 5 seconds
        except:
            pass  # Handle potential errors during animation
    
    def on_closing(self):
        # Auto-clear sensitive data if enabled
        if self.auto_clear_var.get():
            self.clear_fields()
        
        # Save settings
        self.save_settings()
        self.app.destroy()
    
    def save_settings(self):
        settings = {
            'theme': self.theme_mode.get(),
            'auto_clear': self.auto_clear_var.get(),
            'encryption_method': self.encryption_method.get()
        }
        try:
            with open('crypto_settings.json', 'w') as f:
                json.dump(settings, f)
        except:
            pass  # Fail silently if can't save settings
    
    def load_settings(self):
        try:
            with open('crypto_settings.json', 'r') as f:
                settings = json.load(f)
            
            self.theme_mode.set(settings.get('theme', 'Dark'))
            self.auto_clear_var.set(settings.get('auto_clear', False))
            self.encryption_method.set(settings.get('encryption_method', 'Vigenère Cipher'))
            
            # Apply theme
            mode = "light" if self.theme_mode.get() == "Light" else "dark"
            ctk.set_appearance_mode(mode)
        except:
            pass  # Use defaults if can't load settings
    
    def run(self):
        self.load_settings()
        self.app.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.app.mainloop()

# Additional utility functions for enhanced features
def create_splash_screen():
    """Create an animated splash screen"""
    splash = ctk.CTkToplevel()
    splash.title("Loading...")
    splash.geometry("400x300")
    splash.resizable(False, False)
    
    # Center the splash screen
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() // 2) - (400 // 2)
    y = (splash.winfo_screenheight() // 2) - (300 // 2)
    splash.geometry(f"400x300+{x}+{y}")
    
    # Remove window decorations
    splash.overrideredirect(True)
    
    # Splash content
    main_frame = ctk.CTkFrame(splash, corner_radius=20)
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Logo/Title
    title_label = ctk.CTkLabel(main_frame, text="🔐", font=ctk.CTkFont(size=60))
    title_label.pack(pady=(40, 10))
    
    app_title = ctk.CTkLabel(main_frame, text="Advanced Crypto Suite", 
                            font=ctk.CTkFont(size=24, weight="bold"))
    app_title.pack(pady=10)
    
    subtitle = ctk.CTkLabel(main_frame, text="Secure • Fast • Beautiful", 
                           font=ctk.CTkFont(size=14), text_color="gray")
    subtitle.pack(pady=5)
    
    # Progress bar
    progress = ctk.CTkProgressBar(main_frame, width=300)
    progress.pack(pady=(30, 10))
    progress.set(0)
    
    status_label = ctk.CTkLabel(main_frame, text="Initializing...", 
                               font=ctk.CTkFont(size=12), text_color="gray")
    status_label.pack(pady=5)
    
    # Animate progress
    def update_progress(value=0):
        if value <= 1.0:
            progress.set(value)
            if value < 0.3:
                status_label.configure(text="Loading encryption modules...")
            elif value < 0.6:
                status_label.configure(text="Setting up security features...")
            elif value < 0.9:
                status_label.configure(text="Preparing interface...")
            else:
                status_label.configure(text="Almost ready...")
            
            splash.after(50, lambda: update_progress(value + 0.02))
        else:
            splash.after(500, splash.destroy)
    
    update_progress()
    splash.after(2500, splash.destroy)  # Auto-close after animation
    
    return splash

def create_about_dialog(parent):
    """Create an about dialog with app information"""
    about = ctk.CTkToplevel(parent)
    about.title("About Advanced Crypto Suite")
    about.geometry("450x350")
    about.resizable(False, False)
    about.transient(parent)
    about.grab_set()
    
    # Center the dialog
    about.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
    y = parent.winfo_y() + (parent.winfo_height() // 2) - (350 // 2)
    about.geometry(f"450x350+{x}+{y}")
    
    main_frame = ctk.CTkFrame(about, corner_radius=15)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    # App icon and title
    icon_label = ctk.CTkLabel(main_frame, text="🔐", font=ctk.CTkFont(size=48))
    icon_label.pack(pady=(20, 10))
    
    title_label = ctk.CTkLabel(main_frame, text="Advanced Crypto Suite", 
                              font=ctk.CTkFont(size=20, weight="bold"))
    title_label.pack(pady=5)
    
    version_label = ctk.CTkLabel(main_frame, text="Version 2.0.0", 
                                font=ctk.CTkFont(size=12), text_color="gray")
    version_label.pack(pady=2)
    
    # Description
    desc_text = """A comprehensive encryption and decryption tool with modern GUI.
    
Features:
• Multiple encryption algorithms
• File encryption/decryption
• Hash generation
• Operation history
• Secure key generation
• Beautiful modern interface"""
    
    desc_label = ctk.CTkLabel(main_frame, text=desc_text, 
                             font=ctk.CTkFont(size=12), justify="left")
    desc_label.pack(pady=20, padx=20)
    
    # Close button
    close_btn = ctk.CTkButton(main_frame, text="Close", width=100,
                             command=about.destroy)
    close_btn.pack(pady=(0, 20))

# Run the application
if __name__ == "__main__":
    # Show splash screen
    splash = create_splash_screen()
    splash.mainloop()
    
    # Run main application
    app = CryptoApp()
    app.run()