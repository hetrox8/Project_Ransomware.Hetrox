import os
import getpass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define encryption key length (in bytes)
KEY_LENGTH_BYTES = 32  # 256 bits

def generate_encryption_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, encryption_key):
    with open(file_path, 'rb') as f:
        content = f.read()

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(content) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_content)

    return iv

def send_email_with_key(email_address, decryption_key):
    sender_email = "your_email@gmail.com"  # Replace with your email address
    receiver_email = email_address
    password = getpass.getpass("Enter your email password: ")  # Prompt for email password

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Decryption Key"

    body = "Here is your decryption key: " + decryption_key.decode()
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

    print("Decryption key sent to email successfully.")

# Prompt user for password
password = getpass.getpass("Enter encryption password: ")
salt = os.urandom(16)  # Generate a random salt
encryption_key = generate_encryption_key(password, salt)

# Encrypt file
file_to_encrypt = 'example.txt'
iv = encrypt_file(file_to_encrypt, encryption_key)
print("File encrypted successfully.")

# Prompt user for email address
email_address = input("Enter your email address: ")

# Send email with decryption key
send_email_with_key(email_address, encryption_key)

# Prompt user for decryption password
decryption_password = getpass.getpass("Enter decryption password: ")
decryption_key = generate_encryption_key(decryption_password, salt)

# Decrypt file
encrypted_file_to_decrypt = 'example.txt.enc'
decrypt_file(encrypted_file_to_decrypt, decryption_key)
print("File decrypted successfully.")
