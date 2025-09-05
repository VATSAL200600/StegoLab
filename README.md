# 🕵️ StegoLab – All-in-One Image Steganography Toolkit

**StegoLab** is a lightweight, all-in-one **image steganography analysis suite** built for **CTFs, cybersecurity challenges, and digital forensics**.  
It automates the use of popular tools like `binwalk`, `steghide`, `stegseek`, `zsteg`, `exiftool`, and more — all in a single interactive interface.  

---

## ✨ Features
- 🔍 Metadata extraction (EXIF, XMP, IPTC, ICC)
- 🧩 Hidden data detection: LSB carving, strings search, zsteg
- 🛠 Automated tool wrapping: `binwalk`, `steghide`, `stegseek`, `exiftool`, `strings`
- 🎨 Visual analysis: RGB channels, grayscale, bit-plane splitting
- 🔧 Image repair: fix corrupted JPEG/PNG/GIF headers

- ⚡ Interactive menu:
  - Run everything at once
  - Choose tools manually
  - Steghide no-password & mini bruteforce
  - Repair headers & re-analyze

---

## 📦 Installation

### Requirements
- Python 3.8+
- Tools: `binwalk`, `steghide`, `stegseek`, `zsteg`, `exiftool`, `strings`

Install dependencies:
```bash
sudo apt install binwalk steghide stegseek zsteg exiftool
pip install -r requirements.txt
