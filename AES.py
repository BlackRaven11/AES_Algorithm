from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag

def decrypt_aes(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode()

# Generate a random AES key
key = get_random_bytes(16)

# Plaintext message to encrypt
message = "hello"

# Encrypt the message using AES
nonce, ciphertext, tag = encrypt_aes(key, message)

# Decrypt the ciphertext using AES
decrypted_message = decrypt_aes(key, nonce, ciphertext, tag)

# Print the results
print("Plaintext message:", message)
print("AES Key:", key)
print("Ciphertext:", ciphertext)
print("Tag:", tag)
print("Nonce:", nonce)
print("Decrypted message:", decrypted_message)