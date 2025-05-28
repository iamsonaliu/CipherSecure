import base64
import hashlib
import os
from tkinter import messagebox

class EncryptionHandler:
    def __init__(self, app):
        self.app = app

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
    
    def process_message(self):
        msg = self.app.msg_textbox.get("1.0", "end-1c")
        key = self.app.key_entry.get()
        operation = self.app.mode.get()
        method = self.app.encryption_method.get()
        
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
            
            self.app.output_textbox.delete("1.0", "end")
            self.app.output_textbox.insert("1.0", result)
            
            self.app.add_to_history(operation, method, msg[:50] + "..." if len(msg) > 50 else msg)
            self.app.update_status(f"{operation} completed successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
            self.app.update_status("Operation failed")
    
    def generate_hash(self):
        text = self.app.hash_entry.get()
        method = self.app.hash_method.get()
        
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
            self.app.hash_output.delete("1.0", "end")
            self.app.hash_output.insert("1.0", result)
            self.app.update_status(f"{method} hash generated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Hash generation failed: {str(e)}")
    
    def select_file(self):
        self.app.selected_file = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if self.app.selected_file:
            filename = os.path.basename(self.app.selected_file)
            self.app.file_status.configure(text=f"Selected: {filename}")
            self.app.update_status(f"File selected: {filename}")
    
    def encrypt_file(self):
        if not hasattr(self.app, 'selected_file') or not self.app.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        
        key = self.app.key_entry.get()
        if not key:
            messagebox.showwarning("No Key", "Please enter an encryption key.")
            return
        
        try:
            with open(self.app.selected_file, 'rb') as f:
                file_data = f.read()
            
            # Simple XOR encryption for files
            encrypted_data = bytearray()
            for i, byte in enumerate(file_data):
                key_byte = ord(key[i % len(key)])
                encrypted_data.append(byte ^ key_byte)
            
            # Save encrypted file
            encrypted_filename = self.app.selected_file + ".encrypted"
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)
            
            messagebox.showinfo("Success", f"File encrypted and saved as:\n{encrypted_filename}")
            self.app.update_status("File encrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")
    
    def decrypt_file(self):
        if not hasattr(self.app, 'selected_file') or not self.app.selected_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        
        key = self.app.key_entry.get()
        if not key:
            messagebox.showwarning("No Key", "Please enter the decryption key.")
            return
        
        try:
            with open(self.app.selected_file, 'rb') as f:
                encrypted_data = f.read()
            
            # XOR decryption (same as encryption)
            decrypted_data = bytearray()
            for i, byte in enumerate(encrypted_data):
                key_byte = ord(key[i % len(key)])
                decrypted_data.append(byte ^ key_byte)
            
            # Save decrypted file
            if self.app.selected_file.endswith('.encrypted'):
                decrypted_filename = self.app.selected_file[:-10]  # Remove .encrypted
            else:
                decrypted_filename = self.app.selected_file + ".decrypted"
            
            with open(decrypted_filename, 'wb') as f:
                f.write(decrypted_data)
            
            messagebox.showinfo("Success", f"File decrypted and saved as:\n{decrypted_filename}")
            self.app.update_status("File decrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")