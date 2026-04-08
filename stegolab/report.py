"""Self-contained HTML report generation for StegoLab analysis results."""
from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from .core import ensure_dir, save_text


# ──────────────────────── Image embedding helper ────────────────────────


def _img_to_base64(img_path: Path, max_size: int = 500_000) -> str:
    """Read an image file and return a base64-encoded data URI.

    Skip files larger than *max_size* to keep the report manageable.
    """
    if not img_path.exists() or img_path.stat().st_size > max_size:
        return ""
    try:
        data = img_path.read_bytes()
        ext = img_path.suffix.lower().strip(".")
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp"}.get(ext, "image/png")
        return f"data:{mime};base64,{base64.b64encode(data).decode()}"
    except Exception:
        return ""


# ──────────────────────── Scan result folder ────────────────────────


def _scan_results(outdir: Path) -> Dict[str, Dict[str, Any]]:
    """Walk the output directory and categorize findings by tool/module."""
    sections: Dict[str, Dict[str, Any]] = {}

    for subdir in sorted(outdir.iterdir()):
        if not subdir.is_dir():
            continue
        section_name = subdir.name
        files_info: Dict[str, Any] = {"texts": [], "images": [], "status": "clean"}

        for f in sorted(subdir.rglob("*")):
            if f.is_dir():
                continue
            rel = f.relative_to(subdir)
            if f.suffix.lower() in (".txt", ".log"):
                content = f.read_text(encoding="utf-8", errors="ignore")[:4000]
                files_info["texts"].append({"name": str(rel), "content": content})
                # Detect suspicious keywords
                for kw in ("success", "found", "⚠️", "detected", "javascript",
                           "trailing", "embedded", "carved"):
                    if kw.lower() in content.lower():
                        files_info["status"] = "suspicious"
            elif f.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
                b64 = _img_to_base64(f)
                if b64:
                    files_info["images"].append({"name": str(rel), "data": b64})

        if files_info["texts"] or files_info["images"]:
            sections[section_name] = files_info

    return sections


# ──────────────────────── Status badge ────────────────────────


def _badge(status: str) -> str:
    if status == "suspicious":
        return '<span style="background:#ff9800;color:white;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600">⚠️ SUSPICIOUS</span>'
    return '<span style="background:#4caf50;color:white;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600">✅ CLEAN</span>'


# ──────────────────────── HTML generation ────────────────────────


def generate_report(
    file_path: Path,
    outdir: Path,
    extra_info: Optional[Dict[str, str]] = None,
) -> Path:
    """Generate a self-contained HTML report from all analysis results.

    Returns the path to the generated report.html.
    """
    ensure_dir(outdir)
    sections = _scan_results(outdir)

    # Build sections HTML
    sections_html = []
    suspicious_count = sum(1 for s in sections.values() if s["status"] == "suspicious")
    total_count = len(sections)

    for name, info in sections.items():
        # Text files
        text_blocks = []
        for t in info["texts"]:
            text_blocks.append(
                f'<div style="margin:8px 0">'
                f'<div style="font-size:12px;color:#5c6bc0;font-weight:600;margin-bottom:4px">📄 {t["name"]}</div>'
                f'<pre style="background:#263238;color:#eeffff;padding:12px;border-radius:6px;'
                f'overflow-x:auto;font-size:11px;max-height:300px;overflow-y:auto">{t["content"]}</pre></div>'
            )

        # Images
        image_blocks = []
        for img in info["images"][:10]:  # Limit embedded images
            image_blocks.append(
                f'<div style="margin:8px 0;text-align:center">'
                f'<div style="font-size:11px;color:#888;margin-bottom:4px">{img["name"]}</div>'
                f'<img src="{img["data"]}" style="max-width:100%;max-height:300px;border-radius:6px;border:1px solid #e0e0e0"></div>'
            )

        sections_html.append(f"""
        <details style="margin:12px 0;border:1px solid #e0e0e0;border-radius:8px;background:white">
            <summary style="padding:16px;cursor:pointer;font-weight:600;font-size:15px;
                display:flex;align-items:center;justify-content:space-between">
                <span>🔹 {name}</span> {_badge(info["status"])}
            </summary>
            <div style="padding:0 16px 16px">
                {"".join(text_blocks)}
                {"".join(image_blocks)}
            </div>
        </details>""")

    extra_section = ""
    if extra_info:
        rows = "".join(f"<tr><td style='padding:6px 12px;font-weight:600'>{k}</td><td style='padding:6px 12px'>{v}</td></tr>" for k, v in extra_info.items())
        extra_section = f'<table style="margin:16px 0;border-collapse:collapse">{rows}</table>'

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>StegoLab Report — {file_path.name}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;margin:0;padding:0;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh}}
.container{{max-width:900px;margin:0 auto;padding:32px 20px}}
.header{{background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);border-radius:16px;padding:32px;margin-bottom:24px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}}
.header h1{{margin:0 0 8px;color:#1a237e;font-size:28px}}
.header p{{margin:4px 0;color:#555}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:20px 0}}
.stat{{background:white;border-radius:12px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.06)}}
.stat-value{{font-size:32px;font-weight:700;color:#1a237e}}
.stat-label{{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.content{{background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);border-radius:16px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}}
details summary::-webkit-details-marker{{display:none}}
details summary::before{{content:'▶';margin-right:8px;font-size:12px;transition:transform 0.2s}}
details[open] summary::before{{transform:rotate(90deg)}}
pre{{white-space:pre-wrap;word-break:break-all}}
</style></head><body>
<div class="container">
<div class="header">
    <h1>🕵️ StegoLab Analysis Report</h1>
    <p><b>File:</b> {file_path.name} &nbsp;|&nbsp; <b>Size:</b> {file_path.stat().st_size:,} bytes &nbsp;|&nbsp; <b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    {extra_section}
</div>

<div class="dashboard">
    <div class="stat"><div class="stat-value">{total_count}</div><div class="stat-label">Modules Run</div></div>
    <div class="stat"><div class="stat-value" style="color:{'#f44336' if suspicious_count else '#4caf50'}">{suspicious_count}</div><div class="stat-label">Suspicious</div></div>
    <div class="stat"><div class="stat-value" style="color:#4caf50">{total_count - suspicious_count}</div><div class="stat-label">Clean</div></div>
</div>

<div class="content">
    <h2 style="color:#1a237e;margin-top:0">📊 Detailed Results</h2>
    {"".join(sections_html)}
</div>

<p style="text-align:center;color:rgba(255,255,255,0.7);font-size:12px;margin-top:24px">
    Generated by StegoLab v4 — All-in-One Steganography Toolkit
</p>
</div></body></html>"""

    report_path = outdir / "report.html"
    save_text(report_path, html)
    return report_path
