from PIL import Image

def get_capacity(image_path, bits_per_channel=1):
    """Calculate maximum embedding capacity (in bytes) of an image."""
    img = Image.open(image_path)
    width, height = img.size
    channels = len(img.getbands())  # e.g., ('R','G','B') → 3
    capacity_bits = width * height * channels * bits_per_channel
    return capacity_bits // 8  # bytes

def check_message_fit(image_path, message: bytes, bits_per_channel=1):
    """Check if message fits inside image capacity."""
    capacity = get_capacity(image_path, bits_per_channel)
    message_size = len(message)
    can_embed = message_size <= capacity

    print(f"Message size   : {message_size} bytes")
    print(f"Max capacity   : {capacity} bytes")
    print(f"Can embed      : {can_embed}")

    return can_embed, capacity, message_size

if __name__ == "__main__":
    msg = "Confidential: Cybersecurity PBL!".encode("utf-8")
    image_path = "test.png"  # change this to your image path

    check_message_fit(image_path, msg)

# Capacity (bytes) = (Width x Height x Channels x Bits per Channel) / 8