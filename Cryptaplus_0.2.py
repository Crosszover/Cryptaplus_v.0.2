import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256

def get_hashed_key(key):
    hasher = SHA256.new()
    hasher.update(key.encode('utf-8'))
    return hasher.digest()

def encrypt_message():
    message = message_text.get("1.0", tk.END).strip()
    key = key_entry.get()
    if not message or not key:
        messagebox.showwarning("Advertencia", "Por favor, introduce tanto el mensaje como la clave.")
        return

    hashed_key = get_hashed_key(key)
    cipher = AES.new(hashed_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    encrypted_message = iv + ct

    message_text.delete("1.0", tk.END)
    message_text.insert(tk.END, encrypted_message)
    result_label.config(text="Mensaje Encriptado")

def decrypt_message():
    encrypted_message = message_text.get("1.0", tk.END).strip()
    key = key_entry.get()
    if not encrypted_message or not key:
        messagebox.showwarning("Advertencia", "Por favor, introduce tanto el mensaje encriptado como la clave.")
        return

    try:
        hashed_key = get_hashed_key(key)
        iv = b64decode(encrypted_message[:24])
        ct = b64decode(encrypted_message[24:])
        cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        decrypted_message = pt.decode('utf-8')
    except (ValueError, KeyError):
        messagebox.showerror("Error", "Clave incorrecta o mensaje corrupto")
        return

    message_text.delete("1.0", tk.END)
    message_text.insert(tk.END, decrypted_message)
    result_label.config(text="Mensaje Desencriptado")

def clear_fields():
    message_text.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)
    result_label.config(text="Mensaje Encriptado/Desencriptado ")

def show_context_menu(event, widget):
    context_menu.entryconfigure("Copiar", command=lambda: widget.event_generate("<<Copy>>"))
    context_menu.entryconfigure("Cortar", command=lambda: widget.event_generate("<<Cut>>"))
    context_menu.entryconfigure("Pegar", command=lambda: widget.event_generate("<<Paste>>"))
    context_menu.tk_popup(event.x_root, event.y_root)

# Configuración de la ventana principal
root = tk.Tk()
root.title("Encriptador y Desencriptador de Mensajes")

# Crear y colocar los widgets
tk.Label(root, text="Mensaje:").grid(row=0, column=0, padx=10, pady=10)
message_text = tk.Text(root, width=60, height=10)
message_text.grid(row=0, column=1, padx=10, pady=10)
message_text.bind("<Button-3>", lambda event: show_context_menu(event, message_text))

tk.Label(root, text="Clave:").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=50, show="*")
key_entry.grid(row=1, column=1, padx=10, pady=10)
key_entry.bind("<Button-3>", lambda event: show_context_menu(event, key_entry))

button_frame = tk.Frame(root)
button_frame.grid(row=2, column=0, columnspan=2, pady=10)

encrypt_button = tk.Button(button_frame, text="Encriptar", command=encrypt_message)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(button_frame, text="Desencriptar", command=decrypt_message)
decrypt_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Limpiar Campos", command=clear_fields)
clear_button.pack(side=tk.LEFT, padx=5)

result_label = tk.Label(root, text="Mensaje Encriptado/Desencriptado ")
result_label.grid(row=3, columnspan=2, padx=10, pady=10)

# Crear el menú contextual
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copiar")
context_menu.add_command(label="Cortar")
context_menu.add_command(label="Pegar")

# Iniciar el bucle principal de la interfaz
root.mainloop()
