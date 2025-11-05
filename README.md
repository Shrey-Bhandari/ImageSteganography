# 🔐 Image Steganography with AES

**Project Goal:** Secure text communication by combining **AES encryption** (confidentiality) with **Image Steganography (LSB method)** (secrecy).

---

## 📖 Introduction

Cybersecurity requires both **protection** and **concealment** of information.

- **AES Encryption** ensures the plaintext is transformed into unreadable ciphertext.
- **Steganography (LSB)** hides this ciphertext inside an image without visible distortion.

This double-layered approach ensures:

1. **Confidentiality** – Encrypted data cannot be read without the AES key.
2. **Secrecy** – Attackers cannot even detect the presence of a hidden message.

---

## 🚀 Workflow

1. **Encryption Phase**

   - Input plaintext → AES encryption → Ciphertext.

2. **Embedding Phase**

   - Ciphertext bits are embedded in the **Least Significant Bits (LSB)** of the cover image.
   - Output: **Stego Image** (looks identical to the cover image).

3. **Extraction Phase**

   - Receiver extracts ciphertext bits from the stego image.

4. **Decryption Phase**

   - Ciphertext → AES decryption → Original plaintext.

**Result:** Confidential message securely hidden and recovered.

---

## ⚙️ Features

- AES-128 encryption for strong confidentiality.
- LSB-based steganography for secrecy.
- Automatic **capacity check** (ensures image is large enough).
- Length-header embedding (receiver does not need prior ciphertext length).
- Debug mode to view **pixel-level changes** between cover and stego images.

---

## 🛠️ Tech Stack

- **Language:** Python 3.10+
- **Libraries:**

  - `pycryptodome` → AES encryption/decryption
  - `Pillow` → Image processing
  - `numpy` → Pixel matrix manipulation

---

## 📂 Project Structure

```
ImageSteganography/
│── app.py             # Main application (AES + Steganography)
│── Size.py            # To check image size
│── test.png           # Example cover image (add your own PNG)
│── stego.png          # Output stego image after embedding
│── README.md          # Project documentation
```

---

## ▶️ How to Run

1. **Clone Repo**

   ```bash
   git clone https://github.com/your-username/ImageSteganography.git
   cd ImageSteganography
   ```

2. **Install Dependencies**

   ```bash
   pip install pycryptodome pillow numpy
   ```

3. **Add a Cover Image**

   - Place a PNG image in the project folder (e.g., `test.png`).
   - Ensure it is large enough (512×512 recommended).

4. **Run App**

# Image Steganography Chat

A small demo web chat that combines AES encryption with image steganography. Text messages are encrypted with a per-room AES key and the ciphertext is hidden inside a user-provided base image using LSB (least-significant bit) steganography. Messages are sent as images over WebSocket; recipients decode the image to extract the ciphertext, then verify and decrypt it using the room key.

---

## Table of contents

- [Project overview](#project-overview)
- [Features](#features)
- [Tech stack](#tech-stack)
- [Repository structure](#repository-structure)
- [How it works (high-level)](#how-it-works-high-level)
- [Installation](#installation)
- [Running the app (development)](#running-the-app-development)
- [API & Socket.IO events](#api--socketio-events)
- [Data formats & contracts](#data-formats--contracts)
- [Testing the crypto primitives](#testing-the-crypto-primitives)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Possible improvements / next steps](#possible-improvements--next-steps)
- [License & contribution](#license--contribution)

---

## Project overview

This project demonstrates secure real-time messaging by encrypting messages using AES (EAX mode) and embedding the encrypted bytes into user-provided images via LSB steganography. Each room gets a random symmetric key. Users upload a base image which is used to hide their outgoing messages. The app is designed for learning and prototyping — not production use.

## Features

- Real-time messaging using Flask-SocketIO and eventlet
- Per-room AES-EAX encryption (confidentiality + integrity)
- LSB steganography to hide ciphertext in images (Pillow + numpy)
- Upload custom base images per user
- Decode button to extract and decrypt messages
- Room member list and system join/leave notifications

## Tech stack

- Python 3.8+
- Flask
- Flask-SocketIO (async_mode=eventlet)
- eventlet
- Pillow (PIL)
- NumPy
- PyCryptodome

## Repository structure

```
ImageSteganography/
├─ app.py                  # Crypto & steganography functions
├─ chat_app.py             # Flask + Socket.IO server & room logic
├─ templates/
│  └─ index.html          # Frontend UI + Socket.IO client
├─ static/
│  └─ style.css           # CSS styling
├─ requirements.txt
└─ README.md               # (this file)
```

## How it works (high-level)

1. User joins a room via the web UI, uploading a base image.
2. Server resizes and stores the user's base image.
3. When a user sends a message:
   - Server encrypts the plaintext with the room key via `encrypt_message` (AES-EAX) → returns (nonce, ciphertext, tag).
   - Server uses `encode_image` to hide `ciphertext` bytes in the user's image (LSB).
   - Server base64-encodes the resulting stego image and emits it along with nonce, tag and length=len(ciphertext)
4. When a client requests decode (via /decode POST):
   - Server base64-decodes the image, calls `decode_image(input_buffer, length)` to get ciphertext bytes
   - Then calls `decrypt_message(nonce, ciphertext, tag, room_key)` to recover the plaintext message

## Installation

1. Create and activate a virtual environment (recommended):

```cmd
python -m venv .venv
.venv\\Scripts\\activate
```

2. Install dependencies:

```cmd
pip install -r requirements.txt
```

## Running the app (development)

Start the server:

```cmd
python chat_app.py
```

Server prints a link like `http://localhost:5000` — open that in 2 different browser windows (normal + incognito) to simulate multiple users.

Quick test:

- In window A join room `00000` as `Alice` and upload a base image.
- In window B join room `00000` as `Bob` with a different base image.
- Send messages and click "👁️ Decode" on incoming images to reveal messages.

## Quick crypto test

You can test the encryption/decryption primitives using `app.py` demo:

```cmd
python app.py
```

The demo in `app.py` will:

- generate a random key
- encrypt a sample message
- embed it into `test2.jpg` (change to an existing file if needed)
- extract and decrypt the message and print the result.

Or run a small script:

```python
from app import encrypt_message, decrypt_message
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
nonce, ciphertext, tag = encrypt_message("hello world", key)
recovered = decrypt_message(nonce, ciphertext, tag, key)
print("Recovered:", recovered)
```

## API / Socket.IO events

Socket.IO events:

- Client -> Server:
  - `join` { username, room, baseImage } — join or create a room with base image (data URL string).
  - `message` { room, message, username } — request to send message (server encrypts + encodes + emits).
- Server -> Client:
  - `message` { username, image_url, nonce, tag, length } — contains stego image with required metadata.
  - `room_update` { members: [ ... ] } — updated user list for the room.
  - `error` { message } — error messages.

HTTP endpoints:

- `GET /` — serves the UI (`templates/index.html`).
- `POST /decode` — JSON body: { image: "<base64>", nonce: "<base64>", tag: "<base64>", length: <int>, room: "<roomId>" }
  - Returns `{ success: true, message: "..." }` on success or `{ success: false, error: "..." }` on failure.

## Data formats & contracts

- `encrypt_message(message: str, key: bytes) -> (nonce: bytes, ciphertext: bytes, tag: bytes)`
- `decode_image(input_img, length: int) -> bytes` — extracts `length` bytes from LSB of image.
- `encode_image(input_img, data: bytes, output)` — hides bytes into image LSBs and writes PNG to `output`.
- `decode_image(input_img, length: int) -> bytes` — extracts bytes from image LSB
- Socket payload includes:
  - `image_url`: "data:image/png;base64,{imageBase64}"
  - `nonce`, `tag`: base64-encoded
  - `length`: integer (number of ciphertext bytes)

Capacity note: `encode_image` uses the image pixel count to determine capacity. In `app.py` the capacity in bits is `arr.size` (height*width*3), so the maximum number of bytes that can be hidden ≈ arr.size // 8. Ensure base images are large enough for ciphertext size.

## Troubleshooting

- "1 RLock(s) were not greened" at startup:
  - This is an eventlet monkey-patching informational warning if monkey_patch runs after imports. The repo calls `eventlet.monkey_patch()` near the top of `chat_app.py` (should avoid the warning). If you still see it, ensure you start Python fresh and that no other imported modules triggered sockets before monkey patch.
- Connection refused at `http://localhost:5000`:
  - Confirm the server started successfully and printed the port.
  - Ensure port 5000 is not blocked; the server attempts port 5001 if 5000 is taken.
- Duplicate welcome messages or duplicate user list entries:
  - The server now deduplicates members and emits the system welcome message only once. If you still see duplicates, clear cache / use incognito windows and ensure each client uses unique username.
- "Data too large to hide in this image":
  - Use larger base images (more pixels). The available bytes ≈ (width _ height _ 3) // 8.

## Security notes & production concerns

- Room keys are stored in server memory and are ephemeral. This is fine for demos, but not production-safe.
- No authentication is provided — anyone can join a room if they know the room ID and a username.
- Use TLS (HTTPS/WSS) for production to protect transport-layer metadata and to protect users from MITM; run behind a proper web server and add authentication/authorization.
- The images contain ciphertext; anyone who can intercept the image and knows the room key can read messages. Keep keys secret and consider key exchange or user authentication if you want higher security.

## Development notes

- `app.py` contains the LSB encode/decode algorithms using `numpy` + `Pillow`.
- `chat_app.py` handles user sessions, emits Socket.IO events, and performs encryption + steganography workflow.
- UI in `templates/index.html` decodes by sending the image and metadata to `/decode` so the server performs decode + decrypt (this prevents client JS having to implement AES).

## Next steps / potential improvements

- Add authentication and persistent room storage (e.g., Redis) for multi-process deployments.
- Move key management to a secure key-exchange protocol (per-user keys or ephemeral symmetric keys via Diffie-Hellman).
- Allow client-side decryption (if you want end-to-end secrecy) by sending the key to the client in a secure manner (requires secure key distribution).
- Add chunking for long messages (split ciphertext across multiple images).
- Display timestamps and avatars in chat UI.

## Contribution & license

Add your preferred license (e.g., MIT) and contribution instructions here.

---

If you'd like, I can:

- (A) Generate a `README.md` file in the repo with this content (I can write it now), or
- (B) Trim/simplify sections to match a shorter README style, or
- (C) Add example screenshots and sample curl commands for `/decode`.

Which option do you want next?
