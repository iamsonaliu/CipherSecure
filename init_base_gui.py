import customtkinter as ctk
from tkinter import messagebox, filedialog
import json
from datetime import datetime

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
        
        # History for operations
        self.operation_history = []
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main container with padding
        main_container = ctk.CTkFrame(self.app, corner_radius=0, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header
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
        
        # Title
        title_label = ctk.CTkLabel(header_frame, 
                                  text="🔐 ADVANCED CRYPTO SUITE", 
                                  font=ctk.CTkFont(size=28, weight="bold"),
                                  text_color=self.colors['text'])
        title_label.pack(pady=20)
        
    def create_main_content(self, parent):
        # Create tabview
        self.tabview = ctk.CTkTabview(parent, corner_radius=15)
        self.tabview.pack(fill="both", expand=True)
        
        # Add tabs
        self.encryption_tab = self.tabview.add("🔒 Encryption")
        self.tools_tab = self.tabview.add("🛠 Tools")
        self.history_tab = self.tabview.add("📜 History")
        self.settings_tab = self.tabview.add("⚙ Settings")
        
        self.setup_encryption_tab()
        self.setup_tools_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
    def setup_encryption_tab(self):
        # Scrollable frame for encryption content
        scroll_frame = ctk.CTkScrollableFrame(self.encryption_tab, corner_radius=10)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ctk.CTkFrame(scroll_frame, corner_radius=15, 
                                  fg_color=self.colors['secondary'])
        input_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(input_frame, text="📝 Message Input", 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(15, 10))
        
        self.msg_textbox = ctk.CTkTextbox(input_frame, height=100, 
                                         corner_radius=10, wrap="word")
        self.msg_textbox.pack(fill="x", padx=15, pady=(0, 10))
        
        self.char_count_label = ctk.CTkLabel(input_frame, text="Characters: 0", 
                                            text_color="gray")
        self.char_count_label.pack(pady=(0, 15))
        
        # Key section
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
                                        fg_color=self.colors['accent'],
                                        font=ctk.CTkFont(size=14, weight="bold"))
        self.process_btn.pack(side="left", padx=(0, 10))
        
        self.copy_btn = ctk.CTkButton(button_frame, text="📋 Copy Result", 
                                     height=45, corner_radius=10,
                                     fg_color=self.colors['success'])
        self.copy_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = ctk.CTkButton(button_frame, text="🗑 Clear", 
                                      height=45, corner_radius=10,
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
                     fg_color=self.colors['accent']).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(file_btn_frame, text="🔒 Encrypt File", 
                     fg_color=self.colors['success']).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(file_btn_frame, text="🔓 Decrypt File", 
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
                                      variable=self.theme_mode)
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
        except:
            pass  # Use defaults if can't load settings
    
    def run(self):
        self.load_settings()
        self.app.mainloop()