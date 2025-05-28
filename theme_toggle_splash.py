import customtkinter as ctk
import time
from datetime import datetime

class ThemeAndSplashHandler:
    def __init__(self, app):
        self.app = app
        self.gradient_colors = ["#1e293b", "#334155", "#475569", "#64748b"]
        self.bg_index = 0
        self.setup_theme_gui()
        self.animate_background()

    def setup_theme_gui(self):
        header_frame = self.app.encryption_tab.winfo_children()[0]  # Header frame
        theme_btn = ctk.CTkButton(header_frame, text="🌙", width=40, height=30,
                                 command=self.toggle_theme,
                                 fg_color=self.app.colors['accent'])
        theme_btn.place(relx=0.95, rely=0.5, anchor="center")
        
    def toggle_theme(self):
        current = ctk.get_appearance_mode()
        new_mode = "light" if current == "dark" else "dark"
        ctk.set_appearance_mode(new_mode)
        self.app.theme_mode.set("Light" if new_mode == "light" else "Dark")
        self.app.update_status(f"Theme changed to {new_mode}")
    
    def change_theme(self, value):
        mode = "light" if value == "Light" else "dark"
        ctk.set_appearance_mode(mode)
        self.app.update_status(f"Theme changed to {mode}")
    
    def animate_background(self):
        try:
            self.app.app.configure(fg_color=self.gradient_colors[self.bg_index])
            self.bg_index = (self.bg_index + 1) % len(self.gradient_colors)
            self.app.app.after(5000, self.animate_background)
        except:
            pass
    
    def create_splash_screen(self):
        splash = ctk.CTkToplevel()
        splash.title("Loading...")
        splash.geometry("400x300")
        splash.resizable(False, False)
        
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() // 2) - (400 // 2)
        y = (splash.winfo_screenheight() // 2) - (300 // 2)
        splash.geometry(f"400x300+{x}+{y}")
        
        splash.overrideredirect(True)
        
        main_frame = ctk.CTkFrame(splash, corner_radius=20)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        title_label = ctk.CTkLabel(main_frame, text="🔐", font=ctk.CTkFont(size=60))
        title_label.pack(pady=(40, 10))
        
        app_title = ctk.CTkLabel(main_frame, text="Advanced Crypto Suite", 
                                font=ctk.CTkFont(size=24, weight="bold"))
        app_title.pack(pady=10)
        
        subtitle = ctk.CTkLabel(main_frame, text="Secure • Fast • Beautiful", 
                               font=ctk.CTkFont(size=14), text_color="gray")
        subtitle.pack(pady=5)
        
        progress = ctk.CTkProgressBar(main_frame, width=300)
        progress.pack(pady=(30, 10))
        progress.set(0)
        
        status_label = ctk.CTkLabel(main_frame, text="Initializing...", 
                                   font=ctk.CTkFont(size=12), text_color="gray")
        status_label.pack(pady=5)
        
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
        splash.after(2500, splash.destroy)
        return splash
    
    def create_about_dialog(self):
        about = ctk.CTkToplevel(self.app.app)
        about.title("About Advanced Crypto Suite")
        about.geometry("450x350")
        about.resizable(False, False)
        about.transient(self.app.app)
        about.grab_set()
        
        about.update_idletasks()
        x = self.app.app.winfo_x() + (self.app.app.winfo_width() // 2) - (450 // 2)
        y = self.app.app.winfo_y() + (self.app.app.winfo_height() // 2) - (350 // 2)
        about.geometry(f"450x350+{x}+{y}")
        
        main_frame = ctk.CTkFrame(about, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        icon_label = ctk.CTkLabel(main_frame, text="🔐", font=ctk.CTkFont(size=48))
        icon_label.pack(pady=(20, 10))
        
        title_label = ctk.CTkLabel(main_frame, text="Advanced Crypto Suite", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=5)
        
        version_label = ctk.CTkLabel(main_frame, text="Version 2.0.0", 
                                    font=ctk.CTkFont(size=12), text_color="gray")
        version_label.pack(pady=2)
        
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
        
        close_btn = ctk.CTkButton(main_frame, text="Close", width=100,
                                 command=about.destroy)
        close_btn.pack(pady=(0, 20))