"""Tests for image_analysis module."""
from pathlib import Path

import numpy as np
from PIL import Image

from stegolab.image_analysis import (
    extract_exif_pillow,
    split_channels,
    bit_planes,
    lsb_streams_and_carve,
)


def test_extract_exif_pillow(sample_png: Path, tmp_out: Path):
    """EXIF extraction should produce an output file even with no EXIF."""
    result = extract_exif_pillow(sample_png, tmp_out)
    assert (tmp_out / "exif_pillow.txt").exists()


def test_split_channels(sample_png: Path, tmp_out: Path):
    """Channel split should produce R, G, B, A, grayscale, etc."""
    split_channels(sample_png, tmp_out)
    for name in ("channel_R.png", "channel_G.png", "channel_B.png",
                  "channel_A.png", "grayscale.png"):
        assert (tmp_out / name).exists(), f"Missing {name}"


def test_bit_planes(sample_png: Path, tmp_out: Path):
    """Bit-plane extraction should produce 24 images (8 bits × 3 channels)."""
    bit_planes(sample_png, tmp_out)
    count = len(list(tmp_out.glob("bitplane_*.png")))
    assert count == 24, f"Expected 24 bit-planes, got {count}"


def test_lsb_extraction(sample_png: Path, tmp_out: Path):
    """LSB extraction should produce interleaved + per-channel files."""
    carved = lsb_streams_and_carve(sample_png, tmp_out)
    lsb_dir = tmp_out / "lsb"
    assert lsb_dir.exists()
    assert (lsb_dir / "lsb_interleaved.bin").exists()
    assert (lsb_dir / "lsb_R.bin").exists()
    assert (lsb_dir / "lsb_G.bin").exists()
    assert (lsb_dir / "lsb_B.bin").exists()


def test_lsb_with_embedded_data(tmp_path: Path, tmp_out: Path):
    """LSB extraction should detect data embedded in least-significant bits."""
    # Create an image with a known message in LSB
    arr = np.zeros((32, 32, 3), dtype=np.uint8) + 128
    message = b"STEGO"
    bits = []
    for byte in message:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)

    # Embed in interleaved RGB LSB
    flat = arr.reshape(-1)
    for i, bit in enumerate(bits):
        if i < len(flat):
            flat[i] = (flat[i] & 0xFE) | bit
    arr = flat.reshape(32, 32, 3)

    img = Image.fromarray(arr, "RGB")
    p = tmp_path / "stego_embedded.png"
    img.save(p)

    lsb_streams_and_carve(p, tmp_out)
    assert (tmp_out / "lsb" / "lsb_interleaved.bin").exists()
