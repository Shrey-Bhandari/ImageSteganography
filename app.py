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

#LSB Image Encoding
from PIL import Image
import numpy as np

def encode_image(image_path, data, output_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    arr = np.array(img)

    binary_data = to_binary(data)
    data_len = len(binary_data)

    # capacity = pixels * 3 (RGB channels)
    capacity = arr.size  
    if data_len > capacity:
        raise ValueError("Data too large to hide in this image!")

    idx = 0
    for row in arr:
        for pixel in row:
            for n in range(3):
                if idx < data_len:
                    pixel[n] = np.uint8((int(pixel[n]) & ~1) | int(binary_data[idx]))
                    idx += 1

    stego = Image.fromarray(arr.astype(np.uint8))
    stego.save(output_path)
    print(f"Data hidden in {output_path}")

#LSB Image Decoding
def decode_image(image_path, length):
    img = Image.open(image_path)
    arr = np.array(img)

    binary_data = ""
    idx = 0
    for row in arr:
        for pixel in row:
            for n in range(3):
                if idx < length * 8:  # only extract required length
                    binary_data += str(pixel[n] & 1)
                    idx += 1
    return from_binary(binary_data)

#Full Workflow Demo
if __name__ == "__main__":
    key = get_random_bytes(16)
    message = "Confidential: Cybersecurity PBL!"

    # 1. Encrypt
    nonce, ciphertext, tag = encrypt_message(message, key)
    print("Ciphertext:", ciphertext)

    # 2. Hide ciphertext in image
    encode_image("test.png", ciphertext, "stego.png")

    # 3. Extract ciphertext
    extracted = decode_image("stego.png", len(ciphertext))

    # 4. Decrypt
    recovered = decrypt_message(nonce, extracted, tag, key)
    print("Recovered Message:", recovered)
