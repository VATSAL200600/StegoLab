"""Image steganography analysis — built-in + external tool wrappers."""
from __future__ import annotations

from pathlib import Path
from typing import Optional, List, Dict, Any

import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

from .core import (
    which,
    run_cmd,
    save_text,
    ensure_dir,
    imread,
    try_decode_text,
    carve_signatures_from_bytes,
)


# ──────────────────────── Built-in analyses ────────────────────────


def extract_exif_pillow(img_path: Path, outdir: Path) -> Dict[str, Any]:
    """Extract EXIF via Pillow and save to *outdir*."""
    results: Dict[str, Any] = {}
    try:
        im = Image.open(img_path)
        exif = getattr(im, "_getexif", lambda: None)()
        if not exif:
            save_text(outdir / "exif_pillow.txt", "No EXIF found via Pillow.")
        else:
            lines = [f"{k}: {v}" for k, v in exif.items()]
            save_text(outdir / "exif_pillow.txt", "\n".join(lines))
            results = dict(exif)
    except Exception as exc:
        save_text(outdir / "exif_pillow.txt", f"EXIF read error: {exc}")
    return results


def split_channels(img_path: Path, outdir: Path) -> None:
    """Split image into R/G/B/A channels, grayscale, equalized, and inverted."""
    try:
        im = imread(img_path).convert("RGBA")
        r, g, b, a = im.split()
        ensure_dir(outdir)
        r.save(outdir / "channel_R.png")
        g.save(outdir / "channel_G.png")
        b.save(outdir / "channel_B.png")
        a.save(outdir / "channel_A.png")
        ImageOps.grayscale(im).save(outdir / "grayscale.png")
        ImageOps.equalize(ImageOps.grayscale(im)).save(outdir / "grayscale_equalized.png")
        ImageOps.invert(im.convert("RGB")).save(outdir / "inverted.png")
    except Exception as exc:
        save_text(outdir / "split_channels_error.txt", str(exc))


def bit_planes(img_path: Path, outdir: Path) -> None:
    """Extract all 8 bit-planes for each of the R/G/B channels."""
    try:
        im = imread(img_path).convert("RGB")
        arr = np.array(im)
        ensure_dir(outdir)
        for ch_idx, ch in enumerate("RGB"):
            for bit in range(8):
                plane = ((arr[:, :, ch_idx] >> bit) & 1) * 255
                Image.fromarray(plane.astype("uint8")).save(
                    outdir / f"bitplane_{ch}_{bit}.png"
                )
    except Exception as exc:
        save_text(outdir / "bit_planes_error.txt", str(exc))


def lsb_streams_and_carve(img_path: Path, outdir: Path) -> List[Path]:
    """Extract LSB streams (interleaved + per-channel) and carve embedded files."""
    carved: List[Path] = []
    try:
        im = imread(img_path).convert("RGB")
        arr = np.array(im)
        lsb_dir = outdir / "lsb"
        ensure_dir(lsb_dir)

        # Interleaved RGB LSB
        lsb_bits = (arr & 1).reshape(-1, 3).flatten()
        packed = np.packbits(lsb_bits[: (lsb_bits.size // 8) * 8]).tobytes()
        (lsb_dir / "lsb_interleaved.bin").write_bytes(packed)
        save_text(lsb_dir / "lsb_interleaved_preview.txt", try_decode_text(packed))

        # Per-channel
        for i, ch in enumerate("RGB"):
            bits = (arr[:, :, i] & 1).flatten()
            bts = np.packbits(bits[: (bits.size // 8) * 8]).tobytes()
            (lsb_dir / f"lsb_{ch}.bin").write_bytes(bts)
            save_text(lsb_dir / f"lsb_{ch}_preview.txt", try_decode_text(bts))

        # Carve from interleaved stream
        carved = carve_signatures_from_bytes(packed, lsb_dir / "carved")
    except Exception as exc:
        save_text(outdir / "lsb_error.txt", str(exc))
    return carved


# ──────────────────────── External tool wrappers ────────────────────────


def do_strings(img_path: Path, outdir: Path) -> str:
    """Run the `strings` utility."""
    if which("strings"):
        _, output = run_cmd(["strings", "-n", "4", str(img_path)], timeout=60)
        save_text(outdir / "strings" / "strings.txt", output)
        return output
    save_text(outdir / "strings" / "strings_notfound.txt", "strings not available on PATH")
    return ""


def do_binwalk(img_path: Path, outdir: Path) -> str:
    """Run `binwalk` scan + extraction."""
    if not which("binwalk"):
        save_text(outdir / "binwalk" / "binwalk_notfound.txt", "binwalk not on PATH")
        return ""
    try:
        _, output = run_cmd(["binwalk", str(img_path)], timeout=120)
        save_text(outdir / "binwalk" / "binwalk.txt", output)
        _, extract_out = run_cmd(
            ["binwalk", "--dd=.*", "-e", str(img_path)], timeout=240
        )
        save_text(outdir / "binwalk" / "binwalk_extract.txt", extract_out)
        return output
    except Exception as exc:
        save_text(outdir / "binwalk" / "binwalk_error.txt", str(exc))
        return ""


def do_exiftool(img_path: Path, outdir: Path) -> str:
    """Run `exiftool`."""
    if which("exiftool"):
        _, output = run_cmd(["exiftool", str(img_path)], timeout=60)
        save_text(outdir / "exiftool" / "exiftool.txt", output)
        return output
    save_text(outdir / "exiftool" / "exiftool_notfound.txt", "exiftool not on PATH")
    return ""


def do_zsteg(img_path: Path, outdir: Path) -> str:
    """Run `zsteg` (PNG-only)."""
    if img_path.suffix.lower() != ".png":
        save_text(outdir / "zsteg" / "zsteg_skipped.txt", "zsteg skipped (not a PNG)")
        return ""
    if which("zsteg"):
        _, output = run_cmd(["zsteg", "-a", str(img_path)], timeout=180)
        save_text(outdir / "zsteg" / "zsteg.txt", output)
        return output
    save_text(outdir / "zsteg" / "zsteg_notfound.txt", "zsteg not on PATH")
    return ""


def do_stegseek(img_path: Path, outdir: Path) -> str:
    """Run `stegseek`."""
    if which("stegseek"):
        _, output = run_cmd(["stegseek", str(img_path)], timeout=120)
        save_text(outdir / "stegseek" / "stegseek.txt", output)
        return output
    save_text(outdir / "stegseek" / "stegseek_notfound.txt", "stegseek not on PATH")
    return ""


def steghide_attempts(
    img_path: Path,
    outdir: Path,
    wordlist: Optional[Path] = None,
    max_trials: int = 2000,
) -> bool:
    """Try steghide with empty password, then optional wordlist bruteforce.

    Returns True if extraction succeeded.
    """
    if not which("steghide"):
        save_text(outdir / "steghide" / "steghide_notfound.txt", "steghide not on PATH")
        return False

    attempt_dir = outdir / "steghide"
    ensure_dir(attempt_dir)

    # Info
    _, output = run_cmd(["steghide", "info", str(img_path)], timeout=30)
    save_text(attempt_dir / "info.txt", output)

    # Empty password
    _, output = run_cmd(
        [
            "steghide", "extract", "-sf", str(img_path),
            "-xf", str(attempt_dir / "extracted_empty.bin"),
            "-p", "",
        ],
        timeout=30,
    )
    save_text(attempt_dir / "extract_empty.txt", output)
    if "wrote extracted" in output.lower() or "extracted data written" in output.lower():
        save_text(attempt_dir / "success.txt", "Extracted with empty password.")
        return True

    # Wordlist bruteforce
    if wordlist and wordlist.exists():
        count = 0
        with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.strip()
                if not pw:
                    continue
                count += 1
                _, output = run_cmd(
                    [
                        "steghide", "extract", "-sf", str(img_path),
                        "-xf", str(attempt_dir / "extracted_by_pw.bin"),
                        "-p", pw,
                    ],
                    timeout=12,
                )
                if "wrote extracted" in output.lower() or "extracted data written" in output.lower():
                    save_text(
                        attempt_dir / "bruteforce_success.txt",
                        f"SUCCESS password={pw}\n\n{output}",
                    )
                    return True
                if count >= max_trials:
                    break
        save_text(attempt_dir / "bruteforce_done.txt", f"Tried {count} passwords; no success.")
    return False


# ──────────────────────── Repair heuristics ────────────────────────


def repair_image(img_path: Path, outdir: Path) -> List[Path]:
    """Attempt to repair a corrupted image using multiple heuristics."""
    repout = outdir / "repairs"
    ensure_dir(repout)
    data = img_path.read_bytes()
    repaired: List[Path] = []

    # JPEG: SOI → EOI extraction
    soi = data.find(b"\xff\xd8")
    eoi = data.rfind(b"\xff\xd9")
    if soi != -1 and eoi != -1 and eoi > soi:
        candidate = data[soi : eoi + 2]
        p = repout / f"{img_path.stem}_repaired_soi_eoi.jpg"
        p.write_bytes(candidate)
        repaired.append(p)

    # PNG signature
    pngsig = b"\x89PNG\r\n\x1a\n"
    pngi = data.find(pngsig)
    if pngi != -1:
        candidate = data[pngi:]
        p = repout / f"{img_path.stem}_repaired_sig.png"
        p.write_bytes(candidate)
        repaired.append(p)

    # Pillow re-save
    try:
        im = Image.open(img_path)
        im.load()
        for ext in ("png", "jpg", "bmp", "tiff", "webp"):
            outp = repout / f"{img_path.stem}_resaved.{ext}"
            try:
                im.convert("RGB").save(outp)
                repaired.append(outp)
            except Exception:
                pass
    except (UnidentifiedImageError, Exception) as exc:
        save_text(repout / "pillow_open_error.txt", f"Pillow error: {exc}")

    save_text(
        repout / "repair_index.txt",
        "Repaired files:\n" + "\n".join(str(p) for p in repaired),
    )
    return repaired
