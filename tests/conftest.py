"""Shared test fixtures — synthetic test files, temp directories, etc."""
from __future__ import annotations

import struct
import wave
import io
from pathlib import Path

import numpy as np
import pytest
from PIL import Image


@pytest.fixture
def tmp_out(tmp_path: Path) -> Path:
    """Provide a clean temporary output directory."""
    out = tmp_path / "output"
    out.mkdir()
    return out


@pytest.fixture
def sample_png(tmp_path: Path) -> Path:
    """Create a small 16×16 PNG with known pixel data."""
    img = Image.fromarray(
        np.random.randint(0, 256, (16, 16, 3), dtype=np.uint8), "RGB"
    )
    p = tmp_path / "sample.png"
    img.save(p)
    return p


@pytest.fixture
def sample_jpg(tmp_path: Path) -> Path:
    """Create a small 16×16 JPEG."""
    img = Image.fromarray(
        np.random.randint(0, 256, (16, 16, 3), dtype=np.uint8), "RGB"
    )
    p = tmp_path / "sample.jpg"
    img.save(p)
    return p


@pytest.fixture
def sample_png_with_trailing(tmp_path: Path) -> Path:
    """Create a PNG with trailing data appended after IEND."""
    img = Image.fromarray(
        np.random.randint(0, 256, (16, 16, 3), dtype=np.uint8), "RGB"
    )
    p = tmp_path / "trailing.png"
    img.save(p)
    # Append secret trailing data
    with open(p, "ab") as f:
        f.write(b"SECRET_TRAILING_DATA_HERE_12345")
    return p


@pytest.fixture
def sample_jpg_with_zip(tmp_path: Path) -> Path:
    """Create a JPEG with a ZIP signature appended after EOF."""
    img = Image.fromarray(
        np.random.randint(0, 256, (16, 16, 3), dtype=np.uint8), "RGB"
    )
    p = tmp_path / "zipappended.jpg"
    img.save(p)
    # Append a fake ZIP header
    with open(p, "ab") as f:
        f.write(b"PK\x03\x04FAKE_ZIP_CONTENT_HERE")
    return p


@pytest.fixture
def sample_wav(tmp_path: Path) -> Path:
    """Create a short WAV file with known PCM data."""
    p = tmp_path / "sample.wav"
    n_channels = 1
    sample_width = 2
    framerate = 44100
    n_frames = 4410  # 0.1 seconds

    # Generate a simple sine wave
    t = np.linspace(0, 0.1, n_frames, endpoint=False)
    samples = (np.sin(2 * np.pi * 440 * t) * 32767).astype(np.int16)

    with wave.open(str(p), "wb") as wf:
        wf.setnchannels(n_channels)
        wf.setsampwidth(sample_width)
        wf.setframerate(framerate)
        wf.writeframes(samples.tobytes())

    return p


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    """Create a minimal valid-ish PDF file."""
    p = tmp_path / "sample.pdf"
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj

4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Hello StegoLab) Tj ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000210 00000 n 

trailer
<< /Size 5 /Root 1 0 R /Info << /Author (TestAuthor) /Title (TestDoc) >> >>
startxref
308
%%EOF
"""
    p.write_bytes(pdf_content)
    return p


@pytest.fixture
def sample_pdf_with_js(tmp_path: Path) -> Path:
    """Create a PDF file containing JavaScript patterns."""
    p = tmp_path / "js_sample.pdf"
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

5 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('hello')) >>
endobj

xref
0 6
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF
"""
    p.write_bytes(pdf_content)
    return p
