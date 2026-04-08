"""Tests for smart_bruteforce module."""
from pathlib import Path
import zipfile

import numpy as np
from PIL import Image

from stegolab.smart_bruteforce import (
    extract_exif_words,
    extract_filename_words,
    extract_binary_strings,
    generate_contextual_wordlist,
    try_crack_zip,
    CTF_COMMON_PASSWORDS,
)


def test_filename_words():
    """Filename word extraction should produce variations."""
    words = extract_filename_words(Path("secret_flag_2024.png"))
    assert "secret_flag_2024" in words
    assert "secret" in words
    assert "flag" in words
    assert "2024" in words
    # Reversed
    assert "4202_galf_terces" in words


def test_exif_words(sample_png: Path):
    """EXIF extraction should return a set (possibly empty for test images)."""
    words = extract_exif_words(sample_png)
    assert isinstance(words, set)


def test_binary_strings(sample_png: Path):
    """Binary string extraction should find PNG header text."""
    words = extract_binary_strings(sample_png)
    assert isinstance(words, set)


def test_contextual_wordlist_generation(sample_png: Path, tmp_out: Path):
    """Wordlist generation should produce a file with CTF common passwords + more."""
    wl_path = generate_contextual_wordlist(sample_png, tmp_out)
    assert wl_path.exists()
    content = wl_path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")
    # Should have at least the CTF common passwords
    assert len(lines) > len(CTF_COMMON_PASSWORDS) - 5  # minus empty ones

    # Check some CTF commons are present
    assert "password" in content
    assert "ctf" in content
    assert "flag" in content


def test_contextual_wordlist_extra_words(sample_png: Path, tmp_out: Path):
    """Extra words should be included in the generated wordlist."""
    wl_path = generate_contextual_wordlist(
        sample_png, tmp_out, extra_words=["my_custom_password"]
    )
    content = wl_path.read_text(encoding="utf-8")
    assert "my_custom_password" in content


def test_crack_unprotected_zip(tmp_path: Path, tmp_out: Path):
    """Should extract an unprotected ZIP without error."""
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        zf.writestr("hidden.txt", "This is hidden content!")

    result = try_crack_zip(zip_path, tmp_out)
    assert result == ""  # Empty string = no password needed
    assert (tmp_out / "zip_extracted" / "hidden.txt").exists()


def test_crack_nonzip(sample_png: Path, tmp_out: Path):
    """Non-ZIP file should return None."""
    result = try_crack_zip(sample_png, tmp_out)
    assert result is None
