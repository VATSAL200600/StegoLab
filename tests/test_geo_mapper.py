"""Tests for geo_mapper module."""
from pathlib import Path

import numpy as np
from PIL import Image

from stegolab.geo_mapper import (
    extract_gps,
    generate_map_static,
    _dms_to_decimal,
)


def test_dms_to_decimal():
    """DMS to decimal conversion should be correct."""
    # 40°26'46"N → 40.446111
    result = _dms_to_decimal((40.0, 26.0, 46.0), "N")
    assert abs(result - 40.4461) < 0.001

    # South should be negative
    result = _dms_to_decimal((33.0, 52.0, 10.0), "S")
    assert result < 0


def test_extract_gps_no_gps(sample_png: Path):
    """PNG without GPS should return None."""
    result = extract_gps(sample_png)
    assert result is None


def test_generate_static_map(tmp_out: Path):
    """Static map generation should create an HTML file."""
    coords = {"latitude": 28.6139, "longitude": 77.2090, "altitude": 216.0}
    result = generate_map_static(coords, Path("test.jpg"), tmp_out)
    assert result.exists()
    assert result.suffix == ".html"
    content = result.read_text(encoding="utf-8")
    assert "28.6139" in content
    assert "77.2090" in content
    assert "Google Maps" in content


def test_generate_folium_map(tmp_out: Path):
    """Folium map generation should create an HTML file (if folium installed)."""
    try:
        from stegolab.geo_mapper import generate_map_folium
        coords = {"latitude": 48.8566, "longitude": 2.3522}
        result = generate_map_folium(coords, Path("paris.jpg"), tmp_out)
        if result is not None:
            assert result.exists()
            content = result.read_text(encoding="utf-8")
            assert "leaflet" in content.lower() or "folium" in content.lower()
    except ImportError:
        pass  # OK if folium not installed
