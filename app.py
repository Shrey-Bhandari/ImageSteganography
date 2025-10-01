from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES Encryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)  # EAX mode ensures confidentiality + integrity
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag

# AES Decryption
def decrypt_message(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

if __name__ == "__main__":
    key = get_random_bytes(16)  # AES-128 key
    message = "Hello Boss, AES is working!"

    # Encrypt
    nonce, ciphertext, tag = encrypt_message(message, key)
    print("Ciphertext:", ciphertext)

    # Decrypt
    recovered = decrypt_message(nonce, ciphertext, tag, key)
    print("Recovered:", recovered)
