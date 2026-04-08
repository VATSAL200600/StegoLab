"""Batch processing — analyse a directory of files in parallel."""
from __future__ import annotations

import csv
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any

from .core import ensure_dir, save_text


# ──────────────────────── Supported extensions ────────────────────────

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".psd"}
AUDIO_EXTS = {".wav", ".wave", ".au", ".aiff", ".aif"}
PDF_EXTS   = {".pdf"}
ALL_SUPPORTED = IMAGE_EXTS | AUDIO_EXTS | PDF_EXTS


def find_supported_files(directory: Path) -> List[Path]:
    """Recursively find all supported files in a directory."""
    files: List[Path] = []
    for f in sorted(directory.rglob("*")):
        if f.is_file() and f.suffix.lower() in ALL_SUPPORTED:
            files.append(f)
    return files


# ──────────────────────── Single-file analysis (for subprocess) ────────────────────────


def _analyze_single_file(file_path: Path, outdir: Path) -> Dict[str, Any]:
    """Run appropriate analysis on a single file and return a summary dict.

    This function is designed to be called in a subprocess via ProcessPoolExecutor.
    """
    # Import here to avoid circular imports and enable multiprocessing
    result: Dict[str, Any] = {
        "file": file_path.name,
        "path": str(file_path),
        "type": file_path.suffix.lower(),
        "size": file_path.stat().st_size,
        "status": "clean",
        "findings": [],
    }

    file_outdir = outdir / file_path.stem
    ensure_dir(file_outdir)

    try:
        ext = file_path.suffix.lower()

        if ext in IMAGE_EXTS:
            from .image_analysis import (
                extract_exif_pillow, split_channels, bit_planes,
                lsb_streams_and_carve, do_strings, do_binwalk,
            )
            from .hex_viewer import run_hex_analysis
            from .geo_mapper import run_geo_analysis

            extract_exif_pillow(file_path, file_outdir / "builtin")
            split_channels(file_path, file_outdir / "builtin" / "channels")
            bit_planes(file_path, file_outdir / "builtin" / "bitplanes")
            carved = lsb_streams_and_carve(file_path, file_outdir / "builtin")
            if carved:
                result["status"] = "suspicious"
                result["findings"].append(f"LSB carved {len(carved)} file(s)")

            strings_out = do_strings(file_path, file_outdir)
            do_binwalk(file_path, file_outdir)

            hex_result = run_hex_analysis(file_path, file_outdir)
            if hex_result.get("has_trailing_data"):
                result["status"] = "suspicious"
                result["findings"].append("Trailing data detected")
            if hex_result.get("appended_archives"):
                result["status"] = "suspicious"
                result["findings"].append(f"{len(hex_result['appended_archives'])} embedded archive(s)")

            gps = run_geo_analysis(file_path, file_outdir)
            if gps:
                result["findings"].append(f"GPS: {gps['latitude']:.4f}, {gps['longitude']:.4f}")

        elif ext in AUDIO_EXTS:
            from .audio_analysis import run_audio_analysis
            run_audio_analysis(file_path, file_outdir)

        elif ext in PDF_EXTS:
            from .pdf_analysis import run_pdf_analysis, detect_javascript
            run_pdf_analysis(file_path, file_outdir)
            js = detect_javascript(file_path, file_outdir / "pdf")
            if js:
                result["status"] = "suspicious"
                result["findings"].append("JavaScript detected in PDF")

    except Exception as exc:
        result["status"] = "error"
        result["findings"].append(f"Error: {exc}")

    return result


# ──────────────────────── Batch runner ────────────────────────


def run_batch(
    directory: Path,
    outdir: Path,
    max_workers: int = 4,
) -> List[Dict[str, Any]]:
    """Process all supported files in a directory in parallel.

    Returns a list of result dicts (one per file).
    """
    ensure_dir(outdir)
    files = find_supported_files(directory)

    if not files:
        save_text(outdir / "batch_summary.txt", "No supported files found in directory.")
        print(f"  [batch] No supported files found in {directory}")
        return []

    print(f"  [batch] Found {len(files)} file(s) in {directory}")
    results: List[Dict[str, Any]] = []

    # Use ProcessPoolExecutor for parallelism
    # Fall back to sequential if multiprocessing fails
    try:
        with ProcessPoolExecutor(max_workers=min(max_workers, len(files))) as executor:
            future_to_file = {
                executor.submit(_analyze_single_file, f, outdir): f
                for f in files
            }
            for future in as_completed(future_to_file):
                f = future_to_file[future]
                try:
                    result = future.result(timeout=300)
                    results.append(result)
                    status_icon = "⚠️" if result["status"] == "suspicious" else "✅"
                    print(f"  [batch] {status_icon} {f.name}")
                except Exception as exc:
                    results.append({
                        "file": f.name,
                        "path": str(f),
                        "type": f.suffix.lower(),
                        "size": f.stat().st_size,
                        "status": "error",
                        "findings": [str(exc)],
                    })
                    print(f"  [batch] ❌ {f.name}: {exc}")
    except Exception:
        # Fallback to sequential processing
        print("  [batch] Parallel execution failed, running sequentially...")
        for f in files:
            try:
                result = _analyze_single_file(f, outdir)
                results.append(result)
                status_icon = "⚠️" if result["status"] == "suspicious" else "✅"
                print(f"  [batch] {status_icon} {f.name}")
            except Exception as exc:
                results.append({
                    "file": f.name,
                    "path": str(f),
                    "type": f.suffix.lower(),
                    "size": f.stat().st_size,
                    "status": "error",
                    "findings": [str(exc)],
                })

    # Generate CSV summary
    _write_csv_summary(results, outdir)
    # Generate text report
    _write_text_summary(results, outdir)

    return results


# ──────────────────────── Output writers ────────────────────────


def _write_csv_summary(results: List[Dict[str, Any]], outdir: Path) -> Path:
    """Write a CSV summary of batch results."""
    csv_path = outdir / "batch_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Filename", "Type", "Size (bytes)", "Status", "Findings"])
        for r in results:
            writer.writerow([
                r["file"],
                r["type"],
                r["size"],
                r["status"],
                "; ".join(r.get("findings", [])),
            ])
    return csv_path


def _write_text_summary(results: List[Dict[str, Any]], outdir: Path) -> None:
    """Write a human-readable text summary."""
    total = len(results)
    suspicious = sum(1 for r in results if r["status"] == "suspicious")
    errors = sum(1 for r in results if r["status"] == "error")
    clean = total - suspicious - errors

    lines = [
        f"StegoLab v4 — Batch Analysis Report",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"Total files: {total}",
        f"  ✅ Clean:      {clean}",
        f"  ⚠️  Suspicious: {suspicious}",
        f"  ❌ Errors:     {errors}",
        f"",
        f"{'─' * 70}",
    ]

    for r in results:
        icon = {"clean": "✅", "suspicious": "⚠️", "error": "❌"}.get(r["status"], "?")
        lines.append(f"{icon} {r['file']} ({r['size']:,} bytes) — {r['status']}")
        for finding in r.get("findings", []):
            lines.append(f"   → {finding}")

    save_text(outdir / "batch_summary.txt", "\n".join(lines))
