"""Tests for audio_analysis module."""
from pathlib import Path

from stegolab.audio_analysis import (
    extract_wav_lsb,
    extract_audio_strings,
    is_audio_file,
)


def test_wav_lsb_extraction(sample_wav: Path, tmp_out: Path):
    """WAV LSB extraction should produce output files."""
    extracted = extract_wav_lsb(sample_wav, tmp_out)
    assert isinstance(extracted, bytes)
    assert len(extracted) > 0
    assert (tmp_out / "wav_lsb_raw.bin").exists()
    assert (tmp_out / "wav_lsb_preview.txt").exists()
    assert (tmp_out / "wav_lsb_info.txt").exists()


def test_audio_strings(sample_wav: Path, tmp_out: Path):
    """Audio strings extraction should produce a text file."""
    result = extract_audio_strings(sample_wav, tmp_out)
    assert isinstance(result, str)
    assert (tmp_out / "audio_strings.txt").exists()


def test_is_audio_file():
    """Audio file detection should work for known extensions."""
    assert is_audio_file(Path("test.wav")) is True
    assert is_audio_file(Path("test.wave")) is True
    assert is_audio_file(Path("test.au")) is True
    assert is_audio_file(Path("test.png")) is False
    assert is_audio_file(Path("test.jpg")) is False


def test_spectrogram_generation(sample_wav: Path, tmp_out: Path):
    """Spectrogram should be generated if scipy/matplotlib available."""
    try:
        from stegolab.audio_analysis import generate_spectrogram
        result = generate_spectrogram(sample_wav, tmp_out)
        if result is not None:
            assert result.exists()
            assert result.suffix == ".png"
    except ImportError:
        pass  # OK if scipy not installed
