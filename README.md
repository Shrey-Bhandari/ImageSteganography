---

# 🔐 Image Steganography with AES

**Project Goal:** Secure text communication by combining **AES encryption** (confidentiality) with **Image Steganography (LSB method)** (secrecy).

---

## 📖 Introduction

Cybersecurity requires both **protection** and **concealment** of information.

* **AES Encryption** ensures the plaintext is transformed into unreadable ciphertext.
* **Steganography (LSB)** hides this ciphertext inside an image without visible distortion.

This double-layered approach ensures:

1. **Confidentiality** – Encrypted data cannot be read without the AES key.
2. **Secrecy** – Attackers cannot even detect the presence of a hidden message.

---

## 🚀 Workflow

1. **Encryption Phase**

   * Input plaintext → AES encryption → Ciphertext.

2. **Embedding Phase**

   * Ciphertext bits are embedded in the **Least Significant Bits (LSB)** of the cover image.
   * Output: **Stego Image** (looks identical to the cover image).

3. **Extraction Phase**

   * Receiver extracts ciphertext bits from the stego image.

4. **Decryption Phase**

   * Ciphertext → AES decryption → Original plaintext.

**Result:** Confidential message securely hidden and recovered.

---

## ⚙️ Features

* AES-128 encryption for strong confidentiality.
* LSB-based steganography for secrecy.
* Automatic **capacity check** (ensures image is large enough).
* Length-header embedding (receiver does not need prior ciphertext length).
* Debug mode to view **pixel-level changes** between cover and stego images.

---

## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **Libraries:**

  * `pycryptodome` → AES encryption/decryption
  * `Pillow` → Image processing
  * `numpy` → Pixel matrix manipulation

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
   git clone https://github.com/your-username/ImageSteganographyAES.git
   cd ImageSteganographyAES
   ```

2. **Install Dependencies**

   ```bash
   pip install pycryptodome pillow numpy
   ```

3. **Add a Cover Image**

   * Place a PNG image in the project folder (e.g., `test.png`).
   * Ensure it is large enough (512×512 recommended).

4. **Run App**

   ```bash
   python app.py
   ```

5. **Output**

   * `stego.png` → contains hidden ciphertext
   * Console → shows ciphertext + recovered plaintext

---

## 🔍 Example Output

```
Ciphertext length: 32 bytes
Data hidden in stego.png
Recovered Message: Confidential: Cybersecurity PBL!
🔍 Total pixels changed: 36
Pixel(0,0) Channel[0] Orig=120 Stego=121
Pixel(0,0) Channel[1] Orig=65  Stego=64
...
```

---

## 📊 Applications

* Secure communication (military, government, corporate).
* Digital watermarking and copyright protection.
* Covert data transmission in cyber operations.
* Authenticity verification (hidden signatures).

---

## 🔮 Future Scope

* Extend to other media formats: **video, audio, live streams**.
* Improve robustness against **AI-based steganalysis attacks**.
* Support for multiple encryption algorithms (RSA, ECC).

---

## 👨‍💻 Authors

* **Shrey Bhandari**
* **Kavya Dhawale**
* **Amogha Khare**

---
