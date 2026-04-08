"""Tests for report module."""
from pathlib import Path

from stegolab.core import save_text, ensure_dir
from stegolab.report import generate_report


def _populate_fake_results(outdir: Path) -> None:
    """Create fake result folders to simulate a completed analysis."""
    # Builtin results
    builtin = outdir / "builtin"
    ensure_dir(builtin)
    save_text(builtin / "exif_pillow.txt", "No EXIF found via Pillow.")

    # Strings
    strings_dir = outdir / "strings"
    ensure_dir(strings_dir)
    save_text(strings_dir / "strings.txt", "IHDR\nIDAT\nsecret_flag_here\ntEXt")

    # Hex
    hex_dir = outdir / "hex"
    ensure_dir(hex_dir)
    save_text(hex_dir / "header_info.txt", "Detected: PNG — PNG image")
    save_text(hex_dir / "trailing_data.txt", "⚠️ Trailing data detected at offset 0x00001234")

    # Steghide
    steg_dir = outdir / "steghide"
    ensure_dir(steg_dir)
    save_text(steg_dir / "info.txt", "steghide not on PATH")


def test_report_generation(sample_png: Path, tmp_out: Path):
    """Report should generate a valid HTML file."""
    _populate_fake_results(tmp_out)
    report_path = generate_report(sample_png, tmp_out)

    assert report_path.exists()
    assert report_path.suffix == ".html"

    content = report_path.read_text(encoding="utf-8")
    assert "StegoLab" in content
    assert "sample.png" in content
    assert "Modules Run" in content


def test_report_suspicious_detection(sample_png: Path, tmp_out: Path):
    """Report should flag sections with suspicious findings."""
    _populate_fake_results(tmp_out)
    report_path = generate_report(sample_png, tmp_out)
    content = report_path.read_text(encoding="utf-8")

    # The hex section should be flagged as suspicious (trailing data detected)
    assert "SUSPICIOUS" in content


def test_report_with_extra_info(sample_png: Path, tmp_out: Path):
    """Report should include extra info table when provided."""
    _populate_fake_results(tmp_out)
    report_path = generate_report(
        sample_png, tmp_out, extra_info={"GPS": "28.6139, 77.2090"}
    )
    content = report_path.read_text(encoding="utf-8")
    assert "28.6139" in content


def test_empty_report(sample_png: Path, tmp_out: Path):
    """Report should still generate even with no result folders."""
    report_path = generate_report(sample_png, tmp_out)
    assert report_path.exists()
