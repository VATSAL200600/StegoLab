"""PDF forensics — stream extraction, JavaScript detection, metadata."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Any, Optional

from .core import ensure_dir, save_text


# ──────────────────────── PDF metadata ────────────────────────


def extract_pdf_metadata(pdf_path: Path, outdir: Path) -> Dict[str, str]:
    """Extract metadata from a PDF file using PyPDF2."""
    ensure_dir(outdir)
    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(str(pdf_path))
        meta = reader.metadata or {}
        info: Dict[str, str] = {}
        for key in (
            "/Title", "/Author", "/Subject", "/Creator",
            "/Producer", "/CreationDate", "/ModDate",
        ):
            val = meta.get(key)
            if val:
                info[key.strip("/")] = str(val)

        info["Pages"] = str(len(reader.pages))

        text = "\n".join(f"{k}: {v}" for k, v in info.items())
        save_text(outdir / "pdf_metadata.txt", text or "No metadata found.")
        return info
    except ImportError:
        save_text(outdir / "pdf_metadata.txt", "PyPDF2 not installed. pip install PyPDF2")
        return {}
    except Exception as exc:
        save_text(outdir / "pdf_metadata.txt", f"Error: {exc}")
        return {}


# ──────────────────────── JavaScript detection ────────────────────────


def detect_javascript(pdf_path: Path, outdir: Path) -> List[str]:
    """Scan PDF for embedded JavaScript — a common malware vector."""
    ensure_dir(outdir)
    js_snippets: List[str] = []
    try:
        data = pdf_path.read_bytes().decode("latin-1", errors="ignore")

        # /JS and /JavaScript patterns
        js_patterns = [
            r"/JS\s*\((.*?)\)",
            r"/JS\s*<([0-9a-fA-F]+)>",
            r"/JavaScript\s",
        ]
        for pattern in js_patterns:
            for match in re.finditer(pattern, data):
                js_snippets.append(f"Pattern: {pattern}\nMatch: {match.group()}\n")

        if js_snippets:
            save_text(
                outdir / "pdf_javascript.txt",
                "⚠️  JavaScript detected in PDF!\n\n" + "\n---\n".join(js_snippets),
            )
        else:
            save_text(outdir / "pdf_javascript.txt", "✓ No JavaScript found.")
    except Exception as exc:
        save_text(outdir / "pdf_javascript.txt", f"Error scanning for JS: {exc}")
    return js_snippets


# ──────────────────────── Embedded file extraction ────────────────────────


def extract_embedded_files(pdf_path: Path, outdir: Path) -> List[Path]:
    """Extract embedded files (attachments) from a PDF."""
    ensure_dir(outdir)
    extracted: List[Path] = []
    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(str(pdf_path))

        # Check for /EmbeddedFiles in the catalog
        if reader.trailer and "/Root" in reader.trailer:
            root = reader.trailer["/Root"]
            names = root.get("/Names", {})
            ef = names.get("/EmbeddedFiles", {})

            if ef:
                save_text(
                    outdir / "embedded_files_info.txt",
                    f"EmbeddedFiles entry found: {ef}",
                )

        # Also try attachments via the attachments property
        for name, data_list in getattr(reader, "attachments", {}).items():
            for i, data in enumerate(data_list):
                out_path = outdir / f"attachment_{i}_{name}"
                out_path.write_bytes(data)
                extracted.append(out_path)

        if not extracted:
            save_text(outdir / "embedded_files.txt", "No embedded files/attachments found.")
        else:
            save_text(
                outdir / "embedded_files.txt",
                f"Extracted {len(extracted)} files:\n"
                + "\n".join(p.name for p in extracted),
            )
    except ImportError:
        save_text(outdir / "embedded_files.txt", "PyPDF2 not installed.")
    except Exception as exc:
        save_text(outdir / "embedded_files.txt", f"Error: {exc}")
    return extracted


# ──────────────────────── Stream extraction ────────────────────────


def extract_streams(pdf_path: Path, outdir: Path) -> int:
    """Extract all decoded streams from a PDF — a common hiding place."""
    stream_dir = outdir / "streams"
    ensure_dir(stream_dir)
    count = 0
    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(str(pdf_path))
        for page_num, page in enumerate(reader.pages):
            # Extract page text
            text = page.extract_text() or ""
            if text.strip():
                save_text(stream_dir / f"page_{page_num}_text.txt", text)
                count += 1

        # Low-level object scan for streams
        raw = pdf_path.read_bytes()
        stream_starts = [m.start() for m in re.finditer(b"stream\r?\n", raw)]
        for i, start in enumerate(stream_starts):
            end = raw.find(b"endstream", start)
            if end == -1:
                continue
            # Skip past "stream\r\n"
            data_start = raw.find(b"\n", start) + 1
            stream_data = raw[data_start:end]
            if len(stream_data) > 10:  # Skip tiny streams
                (stream_dir / f"raw_stream_{i}.bin").write_bytes(stream_data)
                count += 1

        save_text(
            stream_dir / "stream_summary.txt",
            f"Extracted {count} streams/objects from {pdf_path.name}",
        )
    except ImportError:
        save_text(stream_dir / "stream_error.txt", "PyPDF2 not installed.")
    except Exception as exc:
        save_text(stream_dir / "stream_error.txt", f"Error: {exc}")
    return count


# ──────────────────────── Hidden text via whitespace/encoding ────────────────────────


def check_hidden_text(pdf_path: Path, outdir: Path) -> str:
    """Check for text rendered in white-on-white or very small font sizes."""
    ensure_dir(outdir)
    findings: List[str] = []
    try:
        raw = pdf_path.read_bytes().decode("latin-1", errors="ignore")

        # Look for suspiciously small font sizes
        tiny_fonts = re.findall(r"/FontSize\s+(\d+(?:\.\d+)?)", raw)
        for size in tiny_fonts:
            if float(size) < 1.0:
                findings.append(f"⚠️  Very small font size detected: {size}pt")

        # Look for white text color
        white_patterns = [
            r"1\s+1\s+1\s+rg",   # RGB white fill
            r"1\s+g\s",          # Grayscale white
        ]
        for pat in white_patterns:
            if re.search(pat, raw):
                findings.append(f"⚠️  Possible white/invisible text (pattern: {pat})")

        result = "\n".join(findings) if findings else "✓ No hidden text indicators found."
        save_text(outdir / "hidden_text_check.txt", result)
        return result
    except Exception as exc:
        save_text(outdir / "hidden_text_check.txt", f"Error: {exc}")
        return ""


# ──────────────────────── Orchestrator ────────────────────────


def is_pdf_file(path: Path) -> bool:
    """Check if a file is a PDF."""
    if path.suffix.lower() == ".pdf":
        return True
    try:
        return path.read_bytes()[:5] == b"%PDF-"
    except Exception:
        return False


def run_pdf_analysis(pdf_path: Path, outdir: Path) -> None:
    """Run all PDF forensic checks."""
    pdf_dir = outdir / "pdf"
    ensure_dir(pdf_dir)

    print(f"  [pdf] Extracting metadata ...")
    extract_pdf_metadata(pdf_path, pdf_dir)

    print(f"  [pdf] Scanning for JavaScript ...")
    detect_javascript(pdf_path, pdf_dir)

    print(f"  [pdf] Extracting embedded files ...")
    extract_embedded_files(pdf_path, pdf_dir)

    print(f"  [pdf] Extracting streams ...")
    extract_streams(pdf_path, pdf_dir)

    print(f"  [pdf] Checking for hidden text ...")
    check_hidden_text(pdf_path, pdf_dir)

    save_text(pdf_dir / "PDF_SUMMARY.txt", f"PDF analysis complete for {pdf_path.name}")
