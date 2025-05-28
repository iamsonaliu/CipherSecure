import customtkinter as ctk
import random
import string
import secrets

class KeyHandler:
    def __init__(self, app):
        self.app = app
        self.setup_key_gui()
        self.app.key_entry.bind("<KeyRelease>", self.update_strength)
        self.app.generate_key_btn.configure(command=self.generate_secure_key)

    def setup_key_gui(self):
        key_frame = self.app.encryption_tab.winfo_children()[1]  # Key section frame
        key_input_frame = key_frame.winfo_children()[1]
        
        self.app.generate_key_btn = ctk.CTkButton(key_input_frame, text="🎲 Generate", 
                                                width=100, height=40,
                                                fg_color=self.app.colors['success'])
        self.app.generate_key_btn.pack(side="right")
        
        strength_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        strength_frame.pack(fill="x", padx=15, pady=10)
        
        self.app.key_strength_label = ctk.CTkLabel(strength_frame, text="Key Strength:", 
                                                 font=ctk.CTkFont(weight="bold"))
        self.app.key_strength_label.pack(side="left")
        
        self.app.strength_progress = ctk.CTkProgressBar(strength_frame, width=200, height=10)
        self.app.strength_progress.pack(side="right", padx=(10, 0))
        self.app.strength_progress.set(0)
        
    def update_strength(self, event=None):
        key = self.app.key_entry.get()
        strength, score = self.evaluate_key_strength(key)
        
        colors = {"Weak": "red", "Medium": "orange", "Strong": "green", "Very Strong": "darkgreen"}
        self.app.key_strength_label.configure(text=f"Key Strength: {strength}", 
                                            text_color=colors.get(strength, "gray"))
        self.app.strength_progress.set(score)
        
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
        length = random.randint(12, 20)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        key = ''.join(secrets.choice(chars) for _ in range(length))
        self.app.key_entry.delete(0, "end")
        self.app.key_entry.insert(0, key)
        self.update_strength()
        self.app.update_status("Secure key generated")