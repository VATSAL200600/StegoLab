"""Tests for hex_viewer module."""
from pathlib import Path

from stegolab.hex_viewer import (
    validate_header,
    find_trailing_data,
    scan_for_appended_archives,
    calculate_entropy,
    entropy_map,
    hex_dump,
    run_hex_analysis,
)


def test_validate_header_png(sample_png: Path):
    """PNG header should be detected correctly."""
    data = sample_png.read_bytes()
    file_type, desc = validate_header(data)
    assert file_type == "PNG"
    assert "PNG" in desc


def test_validate_header_jpg(sample_jpg: Path):
    """JPEG header should be detected correctly."""
    data = sample_jpg.read_bytes()
    file_type, desc = validate_header(data)
    assert file_type == "JPEG"


def test_validate_header_unknown():
    """Unknown data should return UNKNOWN."""
    file_type, desc = validate_header(b"\x00\x00\x00\x00")
    assert file_type == "UNKNOWN"


def test_trailing_data_detected(sample_png_with_trailing: Path):
    """Trailing data after IEND should be detected."""
    data = sample_png_with_trailing.read_bytes()
    result = find_trailing_data(data, "PNG")
    assert result is not None
    offset, size, preview = result
    assert size > 0
    assert b"SECRET" in preview


def test_no_trailing_data(sample_png: Path):
    """Clean PNG should have no trailing data."""
    data = sample_png.read_bytes()
    result = find_trailing_data(data, "PNG")
    assert result is None


def test_appended_archive_detected(sample_jpg_with_zip: Path):
    """ZIP signature appended to JPEG should be detected."""
    data = sample_jpg_with_zip.read_bytes()
    archives = scan_for_appended_archives(data, "JPEG")
    assert len(archives) > 0
    assert archives[0]["type"] == "ZIP"


def test_entropy_calculation():
    """Entropy of random data should be high, repetitive data should be low."""
    # All same byte → entropy = 0
    assert calculate_entropy(b"\x00" * 100) == 0.0

    # Random data → high entropy
    import os
    random_data = os.urandom(10000)
    ent = calculate_entropy(random_data)
    assert ent > 7.0, f"Random data entropy should be >7.0, got {ent}"


def test_entropy_map(sample_png: Path):
    """Entropy map should return a list of (offset, entropy) tuples."""
    data = sample_png.read_bytes()
    emap = entropy_map(data, block_size=64)
    assert len(emap) > 0
    for offset, ent in emap:
        assert 0.0 <= ent <= 8.0


def test_hex_dump():
    """Hex dump should produce formatted output."""
    data = b"Hello StegoLab!\x00\xff"
    result = hex_dump(data, 0, len(data))
    assert "48 65 6c 6c 6f" in result  # "Hello" in hex
    assert "|Hello" in result  # ASCII representation


def test_full_hex_analysis(sample_png_with_trailing: Path, tmp_out: Path):
    """Full hex analysis should produce HTML report and detect trailing data."""
    results = run_hex_analysis(sample_png_with_trailing, tmp_out)
    assert results["file_type"] == "PNG"
    assert results["has_trailing_data"] is True
    assert (tmp_out / "hex" / "hex_analysis.html").exists()
    assert (tmp_out / "hex" / "trailing_data.bin").exists()
