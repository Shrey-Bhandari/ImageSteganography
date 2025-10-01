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

# Binary conversion
def to_binary(data):
    """Convert bytes to binary string"""
    return ''.join(format(byte, '08b') for byte in data)

def from_binary(binary_str):
    """Convert binary string back to bytes"""
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

if __name__ == "__main__":
    sample = b"Hi"
    binary = to_binary(sample)
    print("Binary:", binary)
    
    restored = from_binary(binary)
    print("Restored:", restored.decode())
