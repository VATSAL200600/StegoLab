"""Core shared utilities for StegoLab."""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple, List, Dict

from PIL import Image, UnidentifiedImageError


# ──────────────────────── Shell helpers ────────────────────────

def which(cmd: str) -> Optional[str]:
    """Check if an external command is available on PATH."""
    return shutil.which(cmd)


def run_cmd(
    cmd: List[str],
    timeout: int = 120,
    cwd: Optional[Path] = None,
) -> Tuple[int, str]:
    """Run an external command and return (returncode, combined stdout+stderr)."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            text=True,
            cwd=str(cwd) if cwd else None,
        )
        return p.returncode, p.stdout or ""
    except FileNotFoundError:
        return -1, f"[not found] {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        return -1, f"[timeout after {timeout}s] {exc}"


# ──────────────────────── File / Dir helpers ────────────────────────

def save_text(path: Path, content: str) -> None:
    """Write *content* to *path*, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")


def ensure_dir(p: Path) -> None:
    """Create directory (and parents) if it doesn't exist."""
    p.mkdir(parents=True, exist_ok=True)


def imread(path: Path) -> Image.Image:
    """Open and force-load an image via Pillow."""
    im = Image.open(path)
    try:
        im.load()
    except Exception:
        pass
    return im


def try_decode_text(b: bytes, max_preview: int = 2000) -> str:
    """Try decoding bytes with multiple encodings and return a combined preview."""
    outs: List[str] = []
    for enc in ("utf-8", "latin-1", "ascii"):
        try:
            s = b.decode(enc, errors="ignore")
            outs.append(f"--- {enc} preview ---\n{s[:max_preview]}\n")
        except Exception:
            pass
    return "\n".join(outs) if outs else "No decodable preview."


# ──────────────────────── Known file signatures ────────────────────────

SIGNATURES: Dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "zip": b"PK\x03\x04",
    "rar": b"Rar!\x1a\x07",
    "pdf": b"%PDF-",
    "elf": b"\x7fELF",
    "gz":  b"\x1f\x8b",
    "bz2": b"BZh",
    "7z":  b"7z\xbc\xaf\x27\x1c",
}


def detect_file_type(data: bytes) -> Optional[str]:
    """Detect file type by checking magic bytes against known signatures."""
    for name, sig in SIGNATURES.items():
        if data.startswith(sig):
            return name
    return None


def carve_signatures_from_bytes(data: bytes, outdir: Path) -> List[Path]:
    """Scan *data* for known file signatures and carve matching blobs."""
    ensure_dir(outdir)
    carved_files: List[Path] = []
    for name, sig in SIGNATURES.items():
        idx = 0
        found = 0
        while True:
            idx = data.find(sig, idx)
            if idx == -1:
                break
            end = len(data)
            if name == "jpg":
                eidx = data.find(b"\xff\xd9", idx + 2)
                if eidx != -1:
                    end = eidx + 2
            elif name == "png":
                iend = data.find(b"IEND", idx)
                if iend != -1:
                    end = iend + 8
            elif name in ("zip", "rar", "7z"):
                end = min(idx + 5_000_000, len(data))
            outpath = outdir / f"carved_{name}_{found}.bin"
            outpath.write_bytes(data[idx:end])
            carved_files.append(outpath)
            found += 1
            idx = end
        if found:
            save_text(
                outdir / f"carved_{name}_info.txt",
                f"Found {found} instances of {name} signature and carved files.",
            )
    return carved_files
