import customtkinter as ctk
import base64
from tkinter import messagebox
import random
import string
import pyperclip
from datetime import datetime

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class CyberSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security Suite")
        # Remove fixed geometry and resizable constraints for dynamic sizing
        # self.root.geometry("700x500")
        # self.root.resizable(False, False)
        self.current_frame = None
        
        # Theme settings
        self.theme = "dark"
        self.themes = {
            "dark": {
                "bg": "#2C3E50",  # Midnight blue
                "frame": "#34495E",  # Slate blue
                "border": "#3498DB",  # Bright sky blue
                "text": "#ECF0F1",  # Soft off-white
                "entry": "#5D6D7E",  # Muted blue-gray
            },
            "light": {
                "bg": "#E8ECEF",  # Light gray-blue
                "frame": "#D5DBDB",  # Lighter gray
                "border": "#2980B9",  # Slightly darker sky blue
                "text": "#2C3E50",  # Midnight blue for contrast
                "entry": "#BDC3C7",  # Light silver
            }
        }
        
        # Character counter variable
        self.char_count = ctk.StringVar(value="Characters: 0")
        
        # Status message variable
        self.status_message = ctk.StringVar(value="Ready")
        
        # Current time variable
        self.current_time = ctk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        self.setup_status_bar()
        self.update_time()
        self.show_login_page()

    def setup_status_bar(self):
        # Status bar at the bottom
        status_frame = ctk.CTkFrame(self.root, height=30, corner_radius=0, fg_color="transparent")
        status_frame.pack(side="bottom", fill="x")
        status_frame.pack_propagate(False)

        # Status message on the left
        status_label = ctk.CTkLabel(
            status_frame,
            textvariable=self.status_message,
            font=ctk.CTkFont(size=12),
            text_color=self.themes[self.theme]["text"]
        )
        status_label.pack(side="left", padx=10)

        # Current time on the right
        time_label = ctk.CTkLabel(
            status_frame,
            textvariable=self.current_time,
            font=ctk.CTkFont(size=12),
            text_color=self.themes[self.theme]["text"]
        )
        time_label.pack(side="right", padx=10)

    def update_time(self):
        # Update the current time every second
        self.current_time.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self.update_time)

    def update_status(self, message):
        # Update the status message and auto-clear after 3 seconds
        self.status_message.set(message)
        self.root.after(3000, lambda: self.status_message.set("Ready"))

    def toggle_theme(self):
        # Toggle between light and dark themes
        self.theme = "light" if self.theme == "dark" else "dark"
        self.root.configure(fg_color=self.themes[self.theme]["bg"])
        # Refresh the current page to apply the new theme
        if self.current_frame.winfo_children()[0].cget("text") == "Cyber Security Suite Login":
            self.show_login_page()
        else:
            self.show_main_page()
        self.update_status(f"Theme switched to {self.theme.title()} mode")

    # Login Page
    def show_login_page(self):
        if self.current_frame:
            self.current_frame.destroy()
        self._show_login_page()
        # Future improvement: Add a compatible page transition animation here

    def _show_login_page(self):
        self.current_frame = ctk.CTkFrame(
            self.root,
            corner_radius=20,
            fg_color=self.themes[self.theme]["frame"],
            border_width=2,
            border_color=self.themes[self.theme]["border"]
        )
        self.current_frame.pack(padx=40, pady=40, fill="both", expand=True)

        # Theme toggle button
        theme_btn = ctk.CTkButton(
            self.current_frame,
            text="🌙 Toggle Theme",
            width=150,
            height=30,
            corner_radius=10,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#9B59B6",  # Purple for theme toggle
            hover_color="#8E44AD",
            command=self.toggle_theme
        )
        theme_btn.pack(anchor="ne", padx=10, pady=10)

        # Title
        title_label = ctk.CTkLabel(
            self.current_frame,
            text="Cyber Security Suite Login",
            font=ctk.CTkFont(family="Helvetica", size=24, weight="bold"),
            text_color=self.themes[self.theme]["text"]
        )
        title_label.pack(pady=(10, 30))
        title_label.bind("<Enter>", lambda e: title_label.configure(text_color="#3498DB"))
        title_label.bind("<Leave>", lambda e: title_label.configure(text_color=self.themes[self.theme]["text"]))

        # Username Entry
        self.username_entry = ctk.CTkEntry(
            self.current_frame,
            width=300,
            placeholder_text="Enter Username",
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"]
        )
        self.username_entry.pack(pady=10)
        self.username_entry.bind("<Enter>", lambda e: self.username_entry.configure(border_color="#3498DB"))
        self.username_entry.bind("<Leave>", lambda e: self.username_entry.configure(border_color="gray"))

        # Password Entry
        self.password_entry = ctk.CTkEntry(
            self.current_frame,
            width=300,
            placeholder_text="Enter Password",
            show="•",
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"]
        )
        self.password_entry.pack(pady=10)
        self.password_entry.bind("<Enter>", lambda e: self.password_entry.configure(border_color="#3498DB"))
        self.password_entry.bind("<Leave>", lambda e: self.password_entry.configure(border_color="gray"))

        # Login Button
        ctk.CTkButton(
            self.current_frame,
            text="Login",
            width=200,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#1E90FF",
            hover_color="#104E8B",
            command=self.verify_login
        ).pack(pady=20)

        # Bind Enter key to login
        self.password_entry.bind("<Return>", lambda event: self.verify_login())

    # Verify Login
    def verify_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "cyberpbl" and password == "2027":
            self.show_main_page()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password!")

    # Main Page
    def show_main_page(self):
        if self.current_frame:
            self.current_frame.destroy()
        self._show_main_page()
        # Future improvement: Add a compatible page transition animation here

    def _show_main_page(self):
        self.current_frame = ctk.CTkFrame(
            self.root,
            corner_radius=20,
            fg_color=self.themes[self.theme]["frame"],
            border_width=2,
            border_color=self.themes[self.theme]["border"]
        )
        self.current_frame.pack(padx=40, pady=40, fill="both", expand=True)

        # Theme toggle button
        theme_btn = ctk.CTkButton(
            self.current_frame,
            text="🌙 Toggle Theme",
            width=150,
            height=30,
            corner_radius=10,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#9B59B6",
            hover_color="#8E44AD",
            command=self.toggle_theme
        )
        theme_btn.pack(anchor="ne", padx=10, pady=10)

        # Title
        title_label = ctk.CTkLabel(
            self.current_frame,
            text="Encryption-Decryption Suite",
            font=ctk.CTkFont(family="Helvetica", size=24, weight="bold"),
            text_color=self.themes[self.theme]["text"]
        )
        title_label.pack(pady=(0, 20))
        title_label.bind("<Enter>", lambda e: title_label.configure(text_color="#3498DB"))
        title_label.bind("<Leave>", lambda e: title_label.configure(text_color=self.themes[self.theme]["text"]))

        # Message Entry
        self.msg_entry = ctk.CTkEntry(
            self.current_frame,
            width=500,
            placeholder_text="Enter your message here",
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"]
        )
        self.msg_entry.pack(pady=5)
        self.msg_entry.bind("<KeyRelease>", self.update_char_count)
        self.msg_entry.bind("<Enter>", lambda e: self.msg_entry.configure(border_color="#3498DB"))
        self.msg_entry.bind("<Leave>", lambda e: self.msg_entry.configure(border_color="gray"))

        # Character Counter
        char_count_label = ctk.CTkLabel(
            self.current_frame,
            textvariable=self.char_count,
            font=ctk.CTkFont(size=12),
            text_color=self.themes[self.theme]["text"]
        )
        char_count_label.pack(pady=5)

        # Key Entry
        self.key_entry = ctk.CTkEntry(
            self.current_frame,
            width=500,
            placeholder_text="Enter secret key",
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"]
        )
        self.key_entry.pack(pady=5)
        self.key_entry.bind("<KeyRelease>", self.update_strength)
        self.key_entry.bind("<Enter>", lambda e: self.key_entry.configure(border_color="#3498DB"))
        self.key_entry.bind("<Leave>", lambda e: self.key_entry.configure(border_color="gray"))

        # Key Strength Label
        self.key_strength_label = ctk.CTkLabel(
            self.current_frame,
            text="Key Strength:",
            font=ctk.CTkFont(size=12),
            text_color=self.themes[self.theme]["text"]
        )
        self.key_strength_label.pack(pady=5)

        # Operation Mode
        self.mode = ctk.StringVar()
        mode_menu = ctk.CTkOptionMenu(
            self.current_frame,
            values=["Encrypt", "Decrypt"],
            variable=self.mode,
            width=200,
            height=40,
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"],
            dropdown_fg_color=self.themes[self.theme]["entry"],
            dropdown_text_color=self.themes[self.theme]["text"]
        )
        mode_menu.pack(pady=5)

        # Output Entry
        self.output_entry = ctk.CTkEntry(
            self.current_frame,
            width=500,
            placeholder_text="Result will appear here",
            corner_radius=10,
            font=ctk.CTkFont(size=14),
            fg_color=self.themes[self.theme]["entry"],
            text_color=self.themes[self.theme]["text"]
        )
        self.output_entry.pack(pady=5)
        self.output_entry.bind("<Enter>", lambda e: self.output_entry.configure(border_color="#3498DB"))
        self.output_entry.bind("<Leave>", lambda e: self.output_entry.configure(border_color="gray"))

        # Button Frame
        btn_frame = ctk.CTkFrame(self.current_frame, fg_color="transparent")
        btn_frame.pack(pady=20)

        # Buttons with increased width
        ctk.CTkButton(
            btn_frame,
            text="Process",
            width=150,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1E90FF",
            hover_color="#104E8B",
            command=self.show_result
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Generate Key",
            width=150,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#32CD32",
            hover_color="#228B22",
            command=self.generate_random_key
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Copy Output",
            width=150,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#FFD700",
            hover_color="#FFA500",
            command=self.copy_to_clipboard
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Reset",
            width=150,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#FFA500",
            hover_color="#e69500",
            command=self.reset_fields
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Logout",
            width=150,
            height=40,
            corner_radius=15,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#FF4500",
            hover_color="#8B0000",
            command=self.show_login_page
        ).pack(side="left", padx=5)

    # Encryption
    def encode(self, key, msg):
        enc = []
        for i in range(len(msg)):
            list_key = key[i % len(key)]
            list_enc = chr((ord(msg[i]) + ord(list_key)) % 256)
            enc.append(list_enc)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    # Decryption
    def decode(self, key, code):
        try:
            dec = []
            enc = base64.urlsafe_b64decode(code).decode()
            for i in range(len(enc)):
                list_key = key[i % len(key)]
                list_dec = chr((256 + ord(enc[i]) - ord(list_key)) % 256)
                dec.append(list_dec)
            return "".join(dec)
        except:
            return "Invalid decryption"

    # Evaluate key strength
    def evaluate_strength(self, k):
        if len(k) < 4:
            return "Weak", "red"
        elif any(c in string.punctuation for c in k) and len(k) >= 8:
            return "Strong", "green"
        elif len(k) >= 6:
            return "Medium", "yellow"
        else:
            return "Weak", "red"

    # Generate random key
    def generate_random_key(self):
        length = random.randint(8, 12)
        characters = string.ascii_letters + string.digits + string.punctuation
        random_key = ''.join(random.choice(characters) for _ in range(length))
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, random_key)
        self.update_strength()
        self.update_status("Secure key generated")

    # Copy output to clipboard
    def copy_to_clipboard(self):
        output = self.output_entry.get()
        if output:
            pyperclip.copy(output)
            messagebox.showinfo("Success", "Output copied to clipboard!")
            self.update_status("Output copied to clipboard")
        else:
            messagebox.showwarning("Copy Error", "No output to copy!")

    # Live update of key strength
    def update_strength(self, *args):
        k = self.key_entry.get()
        strength, color = self.evaluate_strength(k)
        self.key_strength_label.configure(text=f"Key Strength: {strength}", text_color=color)

    # Update character count
    def update_char_count(self, *args):
        text = self.msg_entry.get()
        self.char_count.set(f"Characters: {len(text)}")

    # Show Result
    def show_result(self):
        msg = self.msg_entry.get()
        k = self.key_entry.get()
        operation = self.mode.get()

        if not msg or not k:
            messagebox.showwarning("Input Error", "Please enter both message and key.")
            return
        if operation == "Encrypt":
            self.output_entry.delete(0, "end")
            self.output_entry.insert(0, self.encode(k, msg))
            self.update_status("Encryption completed")
        elif operation == "Decrypt":
            self.output_entry.delete(0, "end")
            self.output_entry.insert(0, self.decode(k, msg))
            self.update_status("Decryption completed")
        else:
            messagebox.showinfo("Choose Operation", "Please select Encrypt or Decrypt.")

    # Reset
    def reset_fields(self):
        self.msg_entry.delete(0, "end")
        self.key_entry.delete(0, "end")
        self.output_entry.delete(0, "end")
        self.mode.set("")
        self.char_count.set("Characters: 0")
        self.key_strength_label.configure(text="Key Strength:", text_color=self.themes[self.theme]["text"])
        self.update_status("Fields cleared")

if __name__ == "__main__":
    app = ctk.CTk()
    CyberSecurityApp(app)
    app.mainloop()