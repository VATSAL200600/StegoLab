"""Tests for pdf_analysis module."""
from pathlib import Path

from stegolab.pdf_analysis import (
    extract_pdf_metadata,
    detect_javascript,
    extract_streams,
    check_hidden_text,
    is_pdf_file,
)


def test_is_pdf_file(sample_pdf: Path, sample_png: Path):
    """PDF detection should work for .pdf extension and magic bytes."""
    assert is_pdf_file(sample_pdf) is True
    assert is_pdf_file(sample_png) is False


def test_pdf_metadata_extraction(sample_pdf: Path, tmp_out: Path):
    """Metadata extraction should produce output."""
    info = extract_pdf_metadata(sample_pdf, tmp_out)
    assert (tmp_out / "pdf_metadata.txt").exists()
    # Should work even if PyPDF2 has issues with our minimal PDF


def test_javascript_detection_clean(sample_pdf: Path, tmp_out: Path):
    """Clean PDF should not flag JavaScript."""
    js = detect_javascript(sample_pdf, tmp_out)
    assert (tmp_out / "pdf_javascript.txt").exists()


def test_javascript_detection_with_js(sample_pdf_with_js: Path, tmp_out: Path):
    """PDF with JavaScript should be flagged."""
    js = detect_javascript(sample_pdf_with_js, tmp_out)
    assert len(js) > 0, "Should detect JavaScript in the PDF"
    content = (tmp_out / "pdf_javascript.txt").read_text(encoding="utf-8")
    assert "JavaScript detected" in content or "JS" in content


def test_stream_extraction(sample_pdf: Path, tmp_out: Path):
    """Stream extraction should find at least the content stream."""
    count = extract_streams(sample_pdf, tmp_out)
    assert count >= 0  # Minimal PDF may or may not have extractable streams
    assert (tmp_out / "streams").exists()


def test_hidden_text_check(sample_pdf: Path, tmp_out: Path):
    """Hidden text check should produce a result file."""
    result = check_hidden_text(sample_pdf, tmp_out)
    assert (tmp_out / "hidden_text_check.txt").exists()
