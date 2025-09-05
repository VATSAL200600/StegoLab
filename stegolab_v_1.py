#!/usr/bin/env python3
"""StegoLab v3 — cleaned & refactored interactive stego helper

Features:
- Consistent use of pathlib.Path for paths
- Clear variable names (no shadowing of `out`/`outdir`)
- Tool wrappers for: strings, binwalk, exiftool, zsteg, stegseek, steghide
- Built-in analyses: EXIF (Pillow), channel splits, bit-planes, LSB extraction & carving
- Image repair heuristics (JPEG/PNG resave and SOI/EOI extraction)
- Interactive menu + non-interactive flags (--all, --tools)
- Outputs and logs saved under the chosen outdir in organized subfolders
- Safe, limited bruteforce for steghide via provided wordlist (configurable limit)

Usage examples:
  python stego_suite_v3.py image.png -o results_dir
  python stego_suite_v3.py image.jpg -o results --all --bruteforce /path/to/wordlist.txt
  python stego_suite_v3.py image.png --tools strings,binwalk,steghide -o outdir

Note: This script wraps external tools when available. Install them on Kali:
  sudo apt update && sudo apt install -y binwalk steghide exiftool stegseek
  sudo gem install zsteg   # if needed

Author: assistant (refactor of user's v2)
"""
from __future__ import annotations
import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple, List
from PIL import Image, ImageOps, UnidentifiedImageError
import numpy as np

# -------------------- Utilities --------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: List[str], timeout: int = 120, cwd: Optional[Path] = None) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, check=False, text=True, cwd=str(cwd) if cwd else None)
        return p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as e:
        return -1, f"[timeout after {timeout}s] {e}"

def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def imread(path: Path) -> Image.Image:
    im = Image.open(path)
    try:
        im.load()
    except Exception:
        pass
    return im

# -------------------- Built-in analyses --------------------

def extract_exif_pillow(img_path: Path, outdir: Path) -> None:
    try:
        im = Image.open(img_path)
        exif = getattr(im, "_getexif", lambda: None)()
        if not exif:
            save_text(outdir / "exif_pillow.txt", "No EXIF found via Pillow.")
        else:
            lines = [f"{k}: {v}" for k, v in exif.items()]
            save_text(outdir / "exif_pillow.txt", "\n".join(lines))
    except Exception as e:
        save_text(outdir / "exif_pillow.txt", f"EXIF read error: {e}")

def split_channels(img_path: Path, outdir: Path) -> None:
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
    except Exception as e:
        save_text(outdir / "split_channels_error.txt", f"{e}")

def bit_planes(img_path: Path, outdir: Path) -> None:
    try:
        im = imread(img_path).convert("RGB")
        arr = np.array(im)
        ensure_dir(outdir)
        for ch_idx, ch in enumerate("RGB"):
            for bit in range(8):
                plane = ((arr[:, :, ch_idx] >> bit) & 1) * 255
                Image.fromarray(plane.astype("uint8")).save(outdir / f"bitplane_{ch}_{bit}.png")
    except Exception as e:
        save_text(outdir / "bit_planes_error.txt", f"{e}")

def try_decode_text(b: bytes, max_preview: int = 2000) -> str:
    outs = []
    for enc in ("utf-8", "latin-1", "ascii"):
        try:
            s = b.decode(enc, errors="ignore")
            outs.append(f"--- {enc} preview ---\n{s[:max_preview]}\n")
        except Exception:
            pass
    return "\n".join(outs) if outs else "No decodable preview."

# simple carving signatures
SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "zip": b"PK\x03\x04",
    "pdf": b"%PDF-",
    "elf": b"\x7fELF"
}

def carve_signatures_from_bytes(data: bytes, outdir: Path) -> None:
    ensure_dir(outdir)
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
            elif name == "zip":
                end = min(idx + 5_000_000, len(data))
            outpath = outdir / f"carved_{name}_{found}.bin"
            outpath.write_bytes(data[idx:end])
            found += 1
            idx = end
        if found:
            save_text(outdir / f"carved_{name}_info.txt", f"Found {found} instances of {name} signature and carved files.")

def lsb_streams_and_carve(img_path: Path, outdir: Path) -> None:
    try:
        im = imread(img_path).convert("RGB")
        arr = np.array(im)
        lsb_dir = outdir / "lsb"
        ensure_dir(lsb_dir)
        # interleaved RGB LSB
        lsb_bits = (arr & 1).reshape(-1, 3).flatten()
        packed = np.packbits(lsb_bits[: (lsb_bits.size // 8) * 8]).tobytes()
        (lsb_dir / "lsb_interleaved.bin").write_bytes(packed)
        save_text(lsb_dir / "lsb_interleaved_preview.txt", try_decode_text(packed))
        # per channel
        for i, ch in enumerate("RGB"):
            bits = (arr[:, :, i] & 1).flatten()
            bts = np.packbits(bits[: (bits.size // 8) * 8]).tobytes()
            (lsb_dir / f"lsb_{ch}.bin").write_bytes(bts)
            save_text(lsb_dir / f"lsb_{ch}_preview.txt", try_decode_text(bts))
        # carve signatures from interleaved stream
        carve_signatures_from_bytes(packed, lsb_dir / "carved")
    except Exception as e:
        save_text(outdir / "lsb_error.txt", f"{e}")

# -------------------- External tool wrappers --------------------

def do_strings(img_path: Path, outdir: Path) -> None:
    if which("strings"):
        code, output = run_cmd(["strings", "-n", "4", str(img_path)], timeout=60)
        save_text(outdir / "strings" / "strings.txt", output)
    else:
        save_text(outdir / "strings" / "strings_notfound.txt", "strings not available on PATH")

def do_binwalk(img_path: Path, outdir: Path) -> None:
    if not which("binwalk"):
        save_text(outdir / "binwalk" / "binwalk_notfound.txt", "binwalk not on PATH")
        return
    try:
        code, output = run_cmd(["binwalk", str(img_path)], timeout=120)
        save_text(outdir / "binwalk" / "binwalk.txt", output)
        # try extraction; binwalk will create a folder next to the image by default.
        code, output = run_cmd(["binwalk", "--dd=.*", "-e", str(img_path)], timeout=240)
        save_text(outdir / "binwalk" / "binwalk_extract.txt", output)
    except Exception as e:
        save_text(outdir / "binwalk" / "binwalk_error.txt", str(e))

def do_exiftool(img_path: Path, outdir: Path) -> None:
    if which("exiftool"):
        code, output = run_cmd(["exiftool", str(img_path)], timeout=60)
        save_text(outdir / "exiftool" / "exiftool.txt", output)
    else:
        save_text(outdir / "exiftool" / "exiftool_notfound.txt", "exiftool not on PATH")

def do_zsteg(img_path: Path, outdir: Path) -> None:
    if img_path.suffix.lower() != ".png":
        save_text(outdir / "zsteg" / "zsteg_skipped.txt", "zsteg skipped (not a PNG)")
        return
    if which("zsteg"):
        code, output = run_cmd(["zsteg", "-a", str(img_path)], timeout=180)
        save_text(outdir / "zsteg" / "zsteg.txt", output)
    else:
        save_text(outdir / "zsteg" / "zsteg_notfound.txt", "zsteg not on PATH")

def do_stegseek(img_path: Path, outdir: Path) -> None:
    if which("stegseek"):
        code, output = run_cmd(["stegseek", str(img_path)], timeout=120)
        save_text(outdir / "stegseek" / "stegseek.txt", output)
    else:
        save_text(outdir / "stegseek" / "stegseek_notfound.txt", "stegseek not on PATH")

def steghide_attempts(img_path: Path, outdir: Path, wordlist: Optional[Path] = None, max_trials: int = 2000) -> None:
    if not which("steghide"):
        save_text(outdir / "steghide" / "steghide_notfound.txt", "steghide not on PATH")
        return
    attempt_dir = outdir / "steghide"
    ensure_dir(attempt_dir)
    # info
    code, output = run_cmd(["steghide", "info", str(img_path)], timeout=30)
    save_text(attempt_dir / "info.txt", output)
    # try empty password
    code, output = run_cmd(["steghide", "extract", "-sf", str(img_path), "-xf", str(attempt_dir / "extracted_empty.bin"), "-p", ""], timeout=30)
    save_text(attempt_dir / "extract_empty.txt", output)
    if "wrote extracted" in output.lower() or "extracted data written" in output.lower():
        save_text(attempt_dir / "success.txt", "Extracted with empty password. Check extracted_empty.bin")
        return
    # optional wordlist bruteforce (limited)
    if wordlist and wordlist.exists():
        count = 0
        with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if not pw:
                    continue
                count += 1
                code, output = run_cmd(["steghide", "extract", "-sf", str(img_path), "-xf", str(attempt_dir / "extracted_by_pw.bin"), "-p", pw], timeout=12)
                save_text(attempt_dir / f"trial_{count}.txt", output)
                if "wrote extracted" in output.lower() or "extracted data written" in output.lower():
                    save_text(attempt_dir / "bruteforce_success.txt", f"SUCCESS password={pw}\n\n{output}")
                    return
                if count >= max_trials:
                    break
        save_text(attempt_dir / "bruteforce_done.txt", f"Tried {count} passwords; no success.")
    # fallback: scan LSB streams and carve
    lsb_streams_and_carve(img_path, outdir)

# -------------------- Repair heuristics --------------------

def repair_image(img_path: Path, outdir: Path) -> List[Path]:
    repout = outdir / "repairs"
    ensure_dir(repout)
    data = img_path.read_bytes()
    repaired = []
    # JPEG: SOI..EOI extraction
    soi = data.find(b"\xff\xd8")
    eoi = data.rfind(b"\xff\xd9")
    if soi != -1 and eoi != -1 and eoi > soi:
        candidate = data[soi:eoi+2]
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
    # Try to open and resave using Pillow (normalize headers)
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
    except UnidentifiedImageError as e:
        save_text(repout / "pillow_open_error.txt", f"Pillow failed to open original: {e}")
    except Exception as e:
        save_text(repout / "pillow_open_error.txt", f"Pillow open error: {e}")
    save_text(repout / "repair_index.txt", "Repaired files:\n" + "\n".join(str(p) for p in repaired))
    return repaired

# -------------------- Orchestration --------------------

DEFAULT_TOOLS = ["strings", "binwalk", "exiftool", "zsteg", "stegseek", "steghide", "builtin"]

def run_all(img_path: Path, outdir: Path, wordlist: Optional[Path] = None, stegsolve: Optional[Path] = None) -> None:
    # built-ins
    extract_exif_pillow(img_path, outdir / "builtin")
    split_channels(img_path, outdir / "builtin" / "channels")
    bit_planes(img_path, outdir / "builtin" / "bitplanes")
    lsb_streams_and_carve(img_path, outdir / "builtin")
    # tools
    do_strings(img_path, outdir)
    do_binwalk(img_path, outdir)
    do_exiftool(img_path, outdir)
    do_zsteg(img_path, outdir)
    do_stegseek(img_path, outdir)
    # stegsolve: just write a how-to if path provided
    if stegsolve and Path(stegsolve).exists():
        save_text(outdir / "stegsolve" / "stegsolve_howto.txt", f'java -jar "{str(stegsolve)}" "{str(img_path)}"')
    # steghide attempts
    steghide_attempts(img_path, outdir, wordlist)
    save_text(outdir / "REPORT_SUMMARY.txt", f"StegoLab v3 report for {img_path.name} - {time.ctime()}\n\nSee generated folders for details.")

def choose_tools_menu(img_path: Path, outdir: Path, wordlist: Optional[Path] = None, stegsolve: Optional[Path] = None) -> None:
    actions = [
        ("Built-in checks (EXIF, channels, bitplanes, LSB)", "builtin"),
        ("strings", "strings"),
        ("binwalk", "binwalk"),
        ("exiftool", "exiftool"),
        ("zsteg (PNG)", "zsteg"),
        ("stegseek", "stegseek"),
        ("steghide attempts (no-pass + small bruteforce)", "steghide"),
        ("Repair image headers", "repair"),
        ("Exit menu", "exit"),
    ]
    print("\nAvailable actions:")
    for i, (t, _) in enumerate(actions, 1):
        print(f" {i}) {t}")
    sel = input("Your choice (e.g. 1 or 1,3): ").strip()
    if not sel:
        return
    for token in [s.strip() for s in sel.split(",") if s.strip()]:
        try:
            idx = int(token)
        except Exception:
            continue
        if idx < 1 or idx > len(actions):
            continue
        key = actions[idx - 1][1]
        if key == "builtin":
            extract_exif_pillow(img_path, outdir / "builtin")
            split_channels(img_path, outdir / "builtin" / "channels")
            bit_planes(img_path, outdir / "builtin" / "bitplanes")
            lsb_streams_and_carve(img_path, outdir / "builtin")
        elif key == "strings":
            do_strings(img_path, outdir)
        elif key == "binwalk":
            do_binwalk(img_path, outdir)
        elif key == "exiftool":
            do_exiftool(img_path, outdir)
        elif key == "zsteg":
            do_zsteg(img_path, outdir)
        elif key == "stegseek":
            do_stegseek(img_path, outdir)
        elif key == "steghide":
            steghide_attempts(img_path, outdir, wordlist)
        elif key == "repair":
            repaired = repair_image(img_path, outdir)
            if repaired:
                print(" -> Repairs saved. You can analyze repaired files in repairs/ folder.")
        elif key == "exit":
            return

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="StegoLab v3 - interactive stego helper")
    ap.add_argument("image", help="Path to input image")
    ap.add_argument("-o", "--outdir", default="stego_out", help="Output folder")
    ap.add_argument("--all", action="store_true", help="Run everything non-interactively")
    ap.add_argument("--tools", help="Comma-separated list of tools to run (strings,binwalk,exiftool,zsteg,stegseek,steghide)")
    ap.add_argument("--bruteforce", help="Path to a wordlist for steghide bruteforce (optional)")
    ap.add_argument("--stegsolve", help="Path to StegSolve.jar (optional)")
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    img = Path(args.image).expanduser().resolve()
    if not img.exists():
        print("Input not found:", img); sys.exit(1)
    outdir = Path(args.outdir).expanduser().resolve()
    ensure_dir(outdir)
    wordlist = Path(args.bruteforce).expanduser().resolve() if args.bruteforce else None
    stegsolve = Path(args.stegsolve).expanduser().resolve() if args.stegsolve else None
    if args.all:
        run_all(img, outdir, wordlist=wordlist, stegsolve=stegsolve)
        print("Done. See REPORT_SUMMARY.txt in the output folder.")
        return
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",") if t.strip()]
        mapping = {
            "strings": lambda: do_strings(img, outdir),
            "binwalk": lambda: do_binwalk(img, outdir),
            "exiftool": lambda: do_exiftool(img, outdir),
            "zsteg": lambda: do_zsteg(img, outdir),
            "stegseek": lambda: do_stegseek(img, outdir),
            "steghide": lambda: steghide_attempts(img, outdir, wordlist)
        }
        for t in tools:
            fn = mapping.get(t)
            if fn:
                fn()
            else:
                print("Unknown tool:", t)
        print("Done. Check output folder for results.")
        return
    # Interactive loop
    while True:
        print("""\nStegoLab v3 - interactive menu\nChoose an option:\n  1) Run everything (built-ins + external where available)\n  2) Choose tools manually\n  3) Attempt steghide no-password & small bruteforce\n  4) Repair image headers (auto)\n  5) Exit\n""")
        c = input("Choose option (1-5): ").strip()
        if c == "1":
            run_all(img, outdir, wordlist=wordlist, stegsolve=stegsolve)
        elif c == "2":
            choose_tools_menu(img, outdir, wordlist=wordlist, stegsolve=stegsolve)
        elif c == "3":
            steghide_attempts(img, outdir, wordlist)
        elif c == "4":
            repaired = repair_image(img, outdir)
            if repaired:
                print(" -> Repairs saved. You can analyze repaired files in repairs/ folder.")
        elif c in ("5", "q", "quit", "exit"):
            print("Exiting."); break
        else:
            print("Unknown choice. Try again.")


if __name__ == "__main__":
    main()
