"""Tests for batch module."""
from pathlib import Path

import numpy as np
from PIL import Image

from stegolab.batch import find_supported_files, ALL_SUPPORTED


def _create_test_dir(tmp_path: Path) -> Path:
    """Create a directory with several test images."""
    batch_dir = tmp_path / "evidence"
    batch_dir.mkdir()

    # Create a few images
    for i, ext in enumerate(["png", "jpg", "bmp"]):
        img = Image.fromarray(
            np.random.randint(0, 256, (8, 8, 3), dtype=np.uint8), "RGB"
        )
        img.save(batch_dir / f"image_{i}.{ext}")

    # Create a non-image file (should be ignored)
    (batch_dir / "readme.txt").write_text("not an image")

    return batch_dir


def test_find_supported_files(tmp_path: Path):
    """Should find image files but not text files."""
    batch_dir = _create_test_dir(tmp_path)
    files = find_supported_files(batch_dir)
    assert len(files) == 3
    assert all(f.suffix.lower() in ALL_SUPPORTED for f in files)


def test_find_supported_files_empty(tmp_path: Path):
    """Empty directory should return no files."""
    empty = tmp_path / "empty"
    empty.mkdir()
    files = find_supported_files(empty)
    assert len(files) == 0


def test_find_supported_files_recursive(tmp_path: Path):
    """Should find files in subdirectories."""
    batch_dir = tmp_path / "evidence"
    batch_dir.mkdir()
    sub = batch_dir / "subdir"
    sub.mkdir()
    img = Image.fromarray(np.random.randint(0, 256, (8, 8, 3), dtype=np.uint8), "RGB")
    img.save(sub / "nested.png")

    files = find_supported_files(batch_dir)
    assert len(files) == 1
    assert files[0].name == "nested.png"
