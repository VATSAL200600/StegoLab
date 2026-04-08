"""Smart bruteforce — contextual wordlist generation + hash cracking helpers."""
from __future__ import annotations

import re
import string
import zipfile
from pathlib import Path
from typing import List, Optional, Set

from PIL import Image

from .core import ensure_dir, save_text, which, run_cmd


# ──────────────────────── Common CTF passwords ────────────────────────

CTF_COMMON_PASSWORDS: List[str] = [
    "",  # empty password
    "password", "Password", "PASSWORD",
    "ctf", "CTF", "flag", "FLAG",
    "stego", "steganography", "hidden",
    "secret", "Secret", "SECRET",
    "admin", "root", "test", "guest",
    "123", "1234", "12345", "123456",
    "abc", "qwerty", "letmein",
    "pass", "p@ss", "p@ssw0rd",
    "hack", "hacker", "cyber",
    "forensics", "stegano", "crypto",
    "challenge", "solution",
    "2024", "2025", "2026",
]


# ──────────────────────── EXIF-based word extraction ────────────────────────


def extract_exif_words(img_path: Path) -> Set[str]:
    """Pull interesting words from EXIF metadata."""
    words: Set[str] = set()
    try:
        im = Image.open(img_path)
        exif = getattr(im, "_getexif", lambda: None)()
        if exif:
            for key, val in exif.items():
                val_str = str(val)
                # Extract individual words
                for token in re.findall(r"[A-Za-z0-9_@!#$%&]+", val_str):
                    if 2 <= len(token) <= 30:
                        words.add(token)
    except Exception:
        pass
    return words


# ──────────────────────── Filename-based words ────────────────────────


def extract_filename_words(img_path: Path) -> Set[str]:
    """Derive candidate passwords from the filename."""
    words: Set[str] = set()
    stem = img_path.stem

    words.add(stem)
    words.add(stem.lower())
    words.add(stem.upper())
    words.add(stem[::-1])  # reversed

    # Split on common separators
    for part in re.split(r"[-_.\s]+", stem):
        if part:
            words.add(part)
            words.add(part.lower())
            words.add(part.upper())

    return words


# ──────────────────────── Binary strings extraction ────────────────────────


def extract_binary_strings(file_path: Path, min_len: int = 4, max_words: int = 200) -> Set[str]:
    """Extract printable ASCII strings from raw file bytes."""
    words: Set[str] = set()
    try:
        data = file_path.read_bytes()
        current: list[str] = []
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    word = "".join(current)
                    if len(word) <= 30:
                        words.add(word)
                        words.add(word.strip())
                current = []
            if len(words) >= max_words:
                break
    except Exception:
        pass
    return words


# ──────────────────────── Wordlist builder ────────────────────────


def generate_contextual_wordlist(
    file_path: Path,
    outdir: Path,
    extra_words: Optional[List[str]] = None,
) -> Path:
    """Build a smart wordlist from EXIF, filename, binary strings, and CTF commons.

    Returns the path to the generated wordlist file.
    """
    ensure_dir(outdir)
    candidates: Set[str] = set()

    # 1. CTF common passwords
    candidates.update(CTF_COMMON_PASSWORDS)

    # 2. EXIF words
    candidates.update(extract_exif_words(file_path))

    # 3. Filename words
    candidates.update(extract_filename_words(file_path))

    # 4. Binary strings
    candidates.update(extract_binary_strings(file_path))

    # 5. User-provided extra words
    if extra_words:
        candidates.update(extra_words)

    # 6. Generate common mutations
    base_words = list(candidates)[:100]  # Limit base for mutation
    mutations: Set[str] = set()
    for word in base_words:
        if not word:
            continue
        mutations.add(word + "123")
        mutations.add(word + "!")
        mutations.add(word + "1")
        mutations.add(word + "@")
        mutations.add(word.capitalize())
        mutations.add(word + "2024")
        mutations.add(word + "2025")
        mutations.add(word + "2026")
    candidates.update(mutations)

    # Remove empty strings, sort, and deduplicate
    final = sorted(set(w for w in candidates if w))

    wordlist_path = outdir / "contextual_wordlist.txt"
    save_text(wordlist_path, "\n".join(final))
    save_text(
        outdir / "wordlist_info.txt",
        f"Generated {len(final)} candidate passwords.\n"
        f"Sources: CTF commons, EXIF metadata, filename, binary strings, mutations.\n",
    )

    return wordlist_path


# ──────────────────────── ZIP password cracking ────────────────────────


def try_crack_zip(
    zip_path: Path,
    outdir: Path,
    wordlist_path: Optional[Path] = None,
) -> Optional[str]:
    """Attempt to crack a password-protected ZIP using Python's zipfile module.

    Returns the successful password, or None.
    """
    ensure_dir(outdir)
    if not zipfile.is_zipfile(str(zip_path)):
        save_text(outdir / "zip_crack.txt", f"{zip_path.name} is not a valid ZIP file.")
        return None

    try:
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            # Check if encrypted
            encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
            if not encrypted:
                # Not encrypted — extract directly
                zf.extractall(path=str(outdir / "zip_extracted"))
                save_text(outdir / "zip_crack.txt", "ZIP is not password-protected. Extracted.")
                return ""

            # Try passwords
            passwords_to_try: List[str] = list(CTF_COMMON_PASSWORDS)
            if wordlist_path and wordlist_path.exists():
                with wordlist_path.open("r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        pw = line.strip()
                        if pw:
                            passwords_to_try.append(pw)

            for pw in passwords_to_try:
                try:
                    zf.extractall(
                        path=str(outdir / "zip_extracted"),
                        pwd=pw.encode("utf-8"),
                    )
                    save_text(outdir / "zip_crack.txt", f"SUCCESS! Password: {pw}")
                    return pw
                except (RuntimeError, zipfile.BadZipFile):
                    continue

            save_text(
                outdir / "zip_crack.txt",
                f"Failed to crack. Tried {len(passwords_to_try)} passwords.",
            )
    except Exception as exc:
        save_text(outdir / "zip_crack.txt", f"Error: {exc}")

    return None


# ──────────────────────── Hash extraction helper ────────────────────────


def generate_hash_script(
    archive_path: Path,
    outdir: Path,
) -> Path:
    """Generate a helper shell script for john/hashcat cracking."""
    ensure_dir(outdir)
    ext = archive_path.suffix.lower()

    if ext == ".zip":
        tool = "zip2john"
    elif ext in (".rar", ".rar5"):
        tool = "rar2john"
    elif ext in (".7z",):
        tool = "7z2john.pl"
    else:
        tool = "file2john"

    script = f"""#!/bin/bash
# Auto-generated hash extraction + cracking script
# Run this on a Linux machine with John the Ripper installed.

echo "=== Step 1: Extract hash ==="
{tool} "{archive_path.name}" > hash.txt
cat hash.txt

echo ""
echo "=== Step 2: Crack with john ==="
john hash.txt --wordlist=contextual_wordlist.txt

echo ""
echo "=== Step 3: Show results ==="
john --show hash.txt
"""
    script_path = outdir / "crack_helper.sh"
    save_text(script_path, script)
    return script_path
