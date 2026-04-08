"""Hex anomaly viewer — header validation, trailing data, entropy analysis."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .core import ensure_dir, save_text, SIGNATURES


# ──────────────────────── Magic bytes / header validation ────────────────────────

# Extended header database
FILE_HEADERS: Dict[str, Tuple[bytes, str]] = {
    "JPEG":    (b"\xff\xd8\xff", "JPEG image"),
    "PNG":     (b"\x89PNG\r\n\x1a\n", "PNG image"),
    "GIF87a":  (b"GIF87a", "GIF image (87a)"),
    "GIF89a":  (b"GIF89a", "GIF image (89a)"),
    "BMP":     (b"BM", "BMP image"),
    "TIFF_LE": (b"II\x2a\x00", "TIFF image (little-endian)"),
    "TIFF_BE": (b"MM\x00\x2a", "TIFF image (big-endian)"),
    "WEBP":    (b"RIFF", "RIFF container (possibly WEBP)"),
    "ZIP":     (b"PK\x03\x04", "ZIP archive"),
    "RAR":     (b"Rar!\x1a\x07", "RAR archive"),
    "PDF":     (b"%PDF-", "PDF document"),
    "ELF":     (b"\x7fELF", "ELF executable"),
    "PE":      (b"MZ", "PE/DOS executable"),
    "GZIP":    (b"\x1f\x8b", "GZIP compressed"),
    "BZ2":     (b"BZh", "BZ2 compressed"),
    "7Z":      (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    "WAV":     (b"RIFF", "RIFF container (possibly WAV)"),
    "OGG":     (b"OggS", "OGG container"),
    "PSD":     (b"8BPS", "Photoshop PSD"),
}

# EOF markers for common image formats
EOF_MARKERS: Dict[str, bytes] = {
    "JPEG": b"\xff\xd9",
    "PNG_IEND": b"IEND",
}


def validate_header(data: bytes) -> Tuple[str, str]:
    """Check magic bytes against known file signatures.

    Returns (detected_type, description).
    """
    for name, (sig, desc) in FILE_HEADERS.items():
        if data[:len(sig)] == sig:
            return name, desc
    return "UNKNOWN", "Unrecognized file header"


# ──────────────────────── Trailing data detection ────────────────────────


def find_trailing_data(data: bytes, file_type: str) -> Optional[Tuple[int, int, bytes]]:
    """Find data appended after the EOF marker.

    Returns (eof_offset, trailing_size, first_256_bytes) or None.
    """
    if file_type == "JPEG":
        # JPEG ends with FF D9
        eof = data.rfind(b"\xff\xd9")
        if eof != -1:
            trailing_start = eof + 2
            if trailing_start < len(data):
                trailing = data[trailing_start:]
                return trailing_start, len(trailing), trailing[:256]

    elif file_type in ("PNG", "PNG_IEND"):
        # PNG ends with IEND chunk + CRC (4 bytes)
        iend = data.rfind(b"IEND")
        if iend != -1:
            # IEND chunk: 4 bytes length + 4 bytes "IEND" + 4 bytes CRC
            trailing_start = iend + 4 + 4  # past IEND + CRC
            if trailing_start < len(data):
                trailing = data[trailing_start:]
                if len(trailing) > 0:
                    return trailing_start, len(trailing), trailing[:256]

    elif file_type in ("GIF87a", "GIF89a"):
        # GIF ends with 0x3B
        eof = data.rfind(b"\x3b")
        if eof != -1:
            trailing_start = eof + 1
            if trailing_start < len(data):
                trailing = data[trailing_start:]
                return trailing_start, len(trailing), trailing[:256]

    return None


# ──────────────────────── Appended archive detection ────────────────────────


def scan_for_appended_archives(data: bytes, file_type: str) -> List[Dict[str, object]]:
    """Scan for ZIP/RAR/7z signatures embedded after the image data."""
    archive_sigs = {
        "ZIP": b"PK\x03\x04",
        "RAR": b"Rar!\x1a\x07",
        "7Z":  b"7z\xbc\xaf\x27\x1c",
        "GZIP": b"\x1f\x8b",
    }
    findings: List[Dict[str, object]] = []
    # Skip past the first few bytes (to avoid matching the file's own header)
    start_offset = 16
    for name, sig in archive_sigs.items():
        idx = start_offset
        while True:
            idx = data.find(sig, idx)
            if idx == -1:
                break
            findings.append({
                "type": name,
                "offset": idx,
                "hex_offset": f"0x{idx:08X}",
                "preview": data[idx:idx+32].hex(),
            })
            idx += len(sig)
    return findings


# ──────────────────────── Entropy analysis ────────────────────────


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_map(data: bytes, block_size: int = 1024) -> List[Tuple[int, float]]:
    """Calculate per-block entropy across the file.

    Returns list of (offset, entropy) tuples.
    High entropy (>7.5) suggests encrypted/compressed data.
    Low entropy (<3.0) suggests repetitive/unused data.
    """
    result: List[Tuple[int, float]] = []
    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        result.append((offset, calculate_entropy(block)))
    return result


# ──────────────────────── Hex dump ────────────────────────


def hex_dump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """Generate a formatted hex dump of the given data."""
    lines: List[str] = []
    chunk = data[offset : offset + length]
    for i in range(0, len(chunk), 16):
        row = chunk[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        lines.append(f"{offset + i:08x}  {hex_part:<48}  |{ascii_part}|")
    return "\n".join(lines)


# ──────────────────────── HTML visualization ────────────────────────


def generate_hex_html(
    file_path: Path,
    file_type: str,
    trailing: Optional[Tuple[int, int, bytes]],
    archives: List[Dict[str, object]],
    emap: List[Tuple[int, float]],
    outdir: Path,
) -> Path:
    """Generate a small HTML visualization of the hex analysis."""
    ensure_dir(outdir)

    # Build entropy bars
    max_entropy = 8.0
    entropy_bars = []
    for offset, ent in emap[:200]:  # Limit bars
        pct = (ent / max_entropy) * 100
        color = "#4caf50" if ent < 4 else "#ff9800" if ent < 7 else "#f44336"
        entropy_bars.append(
            f'<div style="display:flex;align-items:center;gap:8px;margin:1px 0">'
            f'<span style="font-family:monospace;font-size:11px;min-width:80px">0x{offset:08X}</span>'
            f'<div style="background:{color};height:12px;width:{pct:.0f}%;min-width:2px;border-radius:2px"></div>'
            f'<span style="font-size:11px">{ent:.2f}</span></div>'
        )

    trailing_section = ""
    if trailing:
        t_offset, t_size, t_preview = trailing
        trailing_section = f"""
        <div style="background:#fff3e0;border:1px solid #ff9800;border-radius:8px;padding:16px;margin:12px 0">
            <h3>⚠️ Trailing Data Detected</h3>
            <p><b>Offset:</b> 0x{t_offset:08X} ({t_offset} bytes)</p>
            <p><b>Size:</b> {t_size} bytes</p>
            <pre style="background:#263238;color:#eeffff;padding:12px;border-radius:4px;overflow-x:auto;font-size:12px">{hex_dump(t_preview, t_offset, 256)}</pre>
        </div>"""

    archives_section = ""
    if archives:
        rows = "".join(
            f"<tr><td>{a['type']}</td><td>{a['hex_offset']}</td><td style='font-family:monospace;font-size:11px'>{a['preview']}</td></tr>"
            for a in archives
        )
        archives_section = f"""
        <div style="background:#fce4ec;border:1px solid #e91e63;border-radius:8px;padding:16px;margin:12px 0">
            <h3>🗄️ Embedded Archives Detected</h3>
            <table style="border-collapse:collapse;width:100%">
                <tr style="background:#e91e63;color:white"><th style="padding:8px">Type</th><th style="padding:8px">Offset</th><th style="padding:8px">Preview (hex)</th></tr>
                {rows}
            </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>StegoLab Hex Analysis — {file_path.name}</title>
<style>body{{font-family:Inter,system-ui,sans-serif;max-width:900px;margin:40px auto;padding:20px;background:#fafafa;color:#333}}
h1{{color:#1a237e}}h2{{color:#283593;border-bottom:2px solid #e8eaf6;padding-bottom:8px}}
pre{{background:#263238;color:#eeffff;padding:16px;border-radius:8px;overflow-x:auto;font-size:12px}}</style>
</head><body>
<h1>🔍 StegoLab — Hex Anomaly Report</h1>
<h2>📄 File: {file_path.name}</h2>
<p><b>Detected type:</b> {file_type}</p>
<p><b>File size:</b> {file_path.stat().st_size:,} bytes</p>

<h2>📋 Header (first 64 bytes)</h2>
<pre>{hex_dump(file_path.read_bytes(), 0, 64)}</pre>

{trailing_section}
{archives_section}

<h2>📊 Entropy Map</h2>
<p><span style="color:#4caf50">■</span> Low (&lt;4) &nbsp;
<span style="color:#ff9800">■</span> Medium (4-7) &nbsp;
<span style="color:#f44336">■</span> High (&gt;7 — likely encrypted/compressed)</p>
<div style="background:white;border:1px solid #ddd;border-radius:8px;padding:16px;max-height:400px;overflow-y:auto">
{"".join(entropy_bars)}
</div>

<p style="margin-top:24px;color:#888;font-size:12px">Generated by StegoLab v4</p>
</body></html>"""

    out_path = outdir / "hex_analysis.html"
    save_text(out_path, html)
    return out_path


# ──────────────────────── Orchestrator ────────────────────────


def run_hex_analysis(file_path: Path, outdir: Path) -> Dict[str, object]:
    """Run full hex anomaly analysis on any file."""
    hex_dir = outdir / "hex"
    ensure_dir(hex_dir)
    data = file_path.read_bytes()

    results: Dict[str, object] = {}

    # 1. Validate header
    file_type, description = validate_header(data)
    results["file_type"] = file_type
    results["description"] = description
    save_text(hex_dir / "header_info.txt", f"Detected: {file_type} — {description}")

    print(f"  [hex] Detected file type: {file_type} ({description})")

    # 2. Check trailing data
    trailing = find_trailing_data(data, file_type)
    results["has_trailing_data"] = trailing is not None
    if trailing:
        t_offset, t_size, t_preview = trailing
        print(f"  [hex] ⚠️  Trailing data found at offset 0x{t_offset:08X} ({t_size} bytes)")
        save_text(
            hex_dir / "trailing_data.txt",
            f"Trailing data at offset 0x{t_offset:08X}\n"
            f"Size: {t_size} bytes\n\n"
            f"Hex dump:\n{hex_dump(t_preview, t_offset, 256)}",
        )
        # Save the raw trailing data
        (hex_dir / "trailing_data.bin").write_bytes(data[t_offset:])
    else:
        save_text(hex_dir / "trailing_data.txt", "✓ No trailing data detected.")

    # 3. Scan for appended archives
    archives = scan_for_appended_archives(data, file_type)
    results["appended_archives"] = archives
    if archives:
        info = "\n".join(
            f"  {a['type']} at {a['hex_offset']}: {a['preview']}"
            for a in archives
        )
        print(f"  [hex] 🗄️  Found {len(archives)} embedded archive(s)")
        save_text(hex_dir / "embedded_archives.txt", f"Found {len(archives)} archive signatures:\n{info}")
    else:
        save_text(hex_dir / "embedded_archives.txt", "✓ No embedded archives found.")

    # 4. Entropy analysis
    emap = entropy_map(data)
    overall_entropy = calculate_entropy(data)
    results["entropy"] = overall_entropy
    results["entropy_map"] = emap
    entropy_text = f"Overall entropy: {overall_entropy:.4f} / 8.0\n\n"
    high_entropy_blocks = [(off, ent) for off, ent in emap if ent > 7.0]
    if high_entropy_blocks:
        entropy_text += f"⚠️  {len(high_entropy_blocks)} blocks with entropy > 7.0 (encrypted/compressed?):\n"
        for off, ent in high_entropy_blocks[:20]:
            entropy_text += f"  0x{off:08X}: {ent:.4f}\n"
    else:
        entropy_text += "✓ No unusually high-entropy blocks.\n"
    save_text(hex_dir / "entropy_analysis.txt", entropy_text)

    # 5. Header + tail hex dumps
    save_text(hex_dir / "hex_header.txt", hex_dump(data, 0, 512))
    save_text(hex_dir / "hex_tail.txt", hex_dump(data, max(0, len(data) - 512), 512))

    # 6. HTML report
    generate_hex_html(file_path, file_type, trailing, archives, emap, hex_dir)

    save_text(hex_dir / "HEX_SUMMARY.txt", f"Hex analysis complete for {file_path.name}")
    return results
