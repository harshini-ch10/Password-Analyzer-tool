import tkinter as tk
from tkinter import messagebox, filedialog
import math
import string
import random
import csv

# Function to calculate password strength using entropy
def calculate_entropy(password):
    pool = 0

    # Check what types of characters are in the password
    if any(c in string.ascii_lowercase for c in password):
        pool += len(string.ascii_lowercase)
    if any(c in string.ascii_uppercase for c in password):
        pool += len(string.ascii_uppercase)
    if any(c in string.digits for c in password):
        pool += len(string.digits)
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    # If password is empty or has no known characters
    if pool == 0:
        return 0.0

    # Entropy formula
    entropy = math.log2(pool) * len(password)
    return round(entropy, 2)

# Function to rate password based on entropy
def rate_password(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"

# Generating a strong random password
def generate_strong_password(length=16):
    all_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(all_chars) for _ in range(length))

# Analyzing the password the user typed
def analyze_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Please enter a password.")
        return

    entropy = calculate_entropy(password)
    strength = rate_password(entropy)

    entropy_label.config(text=f"Entropy: {entropy} bits")
    strength_label.config(text=f"Strength: {strength}")

    # Suggesting a better password if current one is weak
    if strength in ["Very Weak", "Weak"]:
        suggestion = generate_strong_password()
        suggestion_label.config(text=f"Suggested Password: {suggestion}")
    else:
        suggestion_label.config(text="")

# Button to generate a new strong password
def generate_password():
    strong_pass = generate_strong_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, strong_pass)
    analyze_password()

# Showing/hiding password when eye icon is clicked
def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text='👁️‍🗨️')
    else:
        password_entry.config(show='*')
        toggle_button.config(text='👁️')

# Scanning passwords from a CSV file
def scan_csv_passwords():
    file_path = filedialog.askopenfilename(title="Select CSV File", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return

    weak_passwords.delete(0, tk.END)

    try:
        with open(file_path, newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            found_weak = False
            for row in reader:
                site = row.get('name') or row.get('site') or "Unknown"
                username = row.get('username', '')
                password = row.get('password', '')

                entropy = calculate_entropy(password)
                strength = rate_password(entropy)

                if strength in ["Very Weak", "Weak"]:
                    found_weak = True
                    line = f"{site} | {username} | {strength} ({entropy} bits)"
                    weak_passwords.insert(tk.END, line)

            if not found_weak:
                weak_passwords.insert(tk.END, "No weak passwords found.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not read file:\n{e}")

# Creating the main window
root = tk.Tk()
root.title("Password Analyzer Tool")
root.geometry("520x520")
root.resizable(False, False)

# --- Layout ---

# Labelling and password entry with eye icon
tk.Label(root, text="Enter Password:").pack(pady=(20, 5))
entry_frame = tk.Frame(root)
entry_frame.pack()

password_entry = tk.Entry(entry_frame, width=35, show="*")
password_entry.pack(side=tk.LEFT)

toggle_button = tk.Button(entry_frame, text="👁️", command=toggle_password_visibility)
toggle_button.pack(side=tk.LEFT, padx=5)

# Analyzing button
tk.Button(root, text="Analyze", command=analyze_password).pack(pady=10)

# Showing results
entropy_label = tk.Label(root, text="Entropy: ")
entropy_label.pack()
strength_label = tk.Label(root, text="Strength: ")
strength_label.pack()
suggestion_label = tk.Label(root, text="", fg="blue", wraplength=400)
suggestion_label.pack(pady=10)

# Generating strong password
tk.Button(root, text="Generate Strong Password", command=generate_password).pack(pady=10)

# Section to scan passwords from CSV
tk.Label(root, text="Scan Saved Passwords (CSV):").pack(pady=(15, 5))
tk.Button(root, text="Upload CSV and Scan", command=scan_csv_passwords).pack(pady=5)

# Listbox to show weak passwords
weak_passwords = tk.Listbox(root, width=70, height=8)
weak_passwords.pack(pady=10)

# Starting the app
root.mainloop()

