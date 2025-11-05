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
import io

def encode_image(input_img, data, output):
    """
    input_img: can be a file path (str) or a file-like object
    output: can be a file path (str) or a file-like object
    """
    if isinstance(input_img, (str, bytes)):
        img = Image.open(input_img)
    else:
        img = Image.open(input_img)
    
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
    
    if isinstance(output, (str, bytes)):
        stego.save(output, 'PNG')
    else:
        stego.save(output, format='PNG')

#LSB Image Decoding
def decode_image(input_img, length):
    """
    input_img: can be a file path (str) or a file-like object
    """
    if isinstance(input_img, (str, bytes)):
        img = Image.open(input_img)
    else:
        img = Image.open(input_img)
    
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

# Image Comparison
def compare_images(original_path, stego_path, limit=50):
    """
    Compare original and stego images, print which pixels changed (LSB differences).
    limit = max number of changes to print (to avoid flooding console).
    """
    orig = Image.open(original_path).convert("RGB")
    stego = Image.open(stego_path).convert("RGB")

    arr_orig = np.array(orig)
    arr_stego = np.array(stego)

    changes = []
    total_changed = 0

    for i in range(arr_orig.shape[0]):
        for j in range(arr_orig.shape[1]):
            for c in range(3):  # R, G, B
                if arr_orig[i, j, c] != arr_stego[i, j, c]:
                    total_changed += 1
                    if len(changes) < limit:
                        changes.append(
                            f"Pixel({i},{j}) Channel[{c}] "
                            f"Orig={arr_orig[i,j,c]} "
                            f"Stego={arr_stego[i,j,c]}"
                        )

    print(f"\n🔍 Total pixels changed: {total_changed}")
    for line in changes:
        print(line)
    if total_changed > limit:
        print(f"... and {total_changed - limit} more changes not shown.")
        
#Full Workflow Demo
if __name__ == "__main__":
    key = get_random_bytes(16)
    message = "Kavya's hidden love"

    # 1. Encrypt
    nonce, ciphertext, tag = encrypt_message(message, key)
    print("Ciphertext:", ciphertext)

    # 2. Hide ciphertext in image
    encode_image("test2.jpg", ciphertext, "stego2.png")

    # 3. Extract ciphertext
    extracted = decode_image("stego2.png", len(ciphertext))

    # 4. Decrypt
    recovered = decrypt_message(nonce, extracted, tag, key)
    print("Recovered Message:", recovered)
    
    # 5. Debug view – see pixel differences
    compare_images("test2.jpg", "stego2.png")
    