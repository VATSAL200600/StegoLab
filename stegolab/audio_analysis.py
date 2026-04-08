"""Audio steganography analysis — WAV LSB extraction + spectrogram."""
from __future__ import annotations

import struct
import wave
from pathlib import Path
from typing import List, Optional

import numpy as np

from .core import ensure_dir, save_text, try_decode_text, carve_signatures_from_bytes, which, run_cmd


# ──────────────────────── WAV LSB extraction ────────────────────────


def extract_wav_lsb(wav_path: Path, outdir: Path, bits: int = 1) -> bytes:
    """Extract least-significant *bits* from each PCM sample in a WAV file.

    Returns the raw extracted bytes.
    """
    ensure_dir(outdir)
    try:
        with wave.open(str(wav_path), "rb") as wf:
            n_channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            n_frames = wf.getnframes()
            raw = wf.readframes(n_frames)

        # Determine sample format
        if sample_width == 1:
            dtype = np.uint8
        elif sample_width == 2:
            dtype = np.int16
        else:
            save_text(outdir / "wav_lsb_error.txt", f"Unsupported sample width: {sample_width}")
            return b""

        samples = np.frombuffer(raw, dtype=dtype)
        mask = (1 << bits) - 1
        lsb_vals = (samples & mask).astype(np.uint8)

        # Pack extracted bits
        if bits == 1:
            packed = np.packbits(lsb_vals[: (lsb_vals.size // 8) * 8])
        else:
            # For multi-bit extraction, just store the raw values
            packed = lsb_vals

        extracted = packed.tobytes()
        (outdir / "wav_lsb_raw.bin").write_bytes(extracted)
        save_text(outdir / "wav_lsb_preview.txt", try_decode_text(extracted))

        # Also carve for embedded files
        carve_signatures_from_bytes(extracted, outdir / "carved")

        save_text(
            outdir / "wav_lsb_info.txt",
            f"Channels: {n_channels}\n"
            f"Sample width: {sample_width} bytes\n"
            f"Frames: {n_frames}\n"
            f"Total samples: {samples.size}\n"
            f"LSB bits extracted: {bits}\n"
            f"Extracted bytes: {len(extracted)}\n",
        )
        return extracted
    except Exception as exc:
        save_text(outdir / "wav_lsb_error.txt", f"WAV LSB extraction error: {exc}")
        return b""


# ──────────────────────── Spectrogram generation ────────────────────────


def generate_spectrogram(audio_path: Path, outdir: Path) -> Optional[Path]:
    """Generate a spectrogram image from an audio file using scipy + matplotlib.

    Returns the path to the generated image, or None on failure.
    """
    ensure_dir(outdir)
    try:
        from scipy.io import wavfile
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        sample_rate, data = wavfile.read(str(audio_path))

        # Use mono for spectrogram
        if data.ndim > 1:
            data = data[:, 0]

        fig, axes = plt.subplots(2, 1, figsize=(14, 8))

        # Waveform
        time_axis = np.arange(len(data)) / sample_rate
        axes[0].plot(time_axis, data, linewidth=0.3, color="#2196F3")
        axes[0].set_title("Waveform")
        axes[0].set_xlabel("Time (s)")
        axes[0].set_ylabel("Amplitude")

        # Spectrogram
        axes[1].specgram(data, Fs=sample_rate, NFFT=1024, noverlap=512, cmap="inferno")
        axes[1].set_title("Spectrogram  (look for hidden text / images)")
        axes[1].set_xlabel("Time (s)")
        axes[1].set_ylabel("Frequency (Hz)")

        plt.tight_layout()
        out_path = outdir / "spectrogram.png"
        fig.savefig(str(out_path), dpi=150)
        plt.close(fig)
        return out_path

    except ImportError:
        save_text(
            outdir / "spectrogram_error.txt",
            "scipy and/or matplotlib not installed. Install with: pip install scipy matplotlib",
        )
        return None
    except Exception as exc:
        save_text(outdir / "spectrogram_error.txt", f"Spectrogram error: {exc}")
        return None


# ──────────────────────── Strings scan ────────────────────────


def extract_audio_strings(audio_path: Path, outdir: Path, min_len: int = 6) -> str:
    """Extract printable ASCII strings from raw audio bytes."""
    ensure_dir(outdir)
    data = audio_path.read_bytes()
    strings: list[str] = []
    current: list[str] = []

    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))

    result = "\n".join(strings)
    save_text(outdir / "audio_strings.txt", result or "No printable strings found.")
    return result


# ──────────────────────── Steghide for audio ────────────────────────


def steghide_audio(audio_path: Path, outdir: Path, password: str = "") -> bool:
    """Try steghide extraction on WAV/AU files."""
    if not which("steghide"):
        save_text(outdir / "steghide_audio_notfound.txt", "steghide not on PATH")
        return False

    ensure_dir(outdir)
    _, output = run_cmd(
        [
            "steghide", "extract", "-sf", str(audio_path),
            "-xf", str(outdir / "steghide_audio_extracted.bin"),
            "-p", password,
        ],
        timeout=30,
    )
    save_text(outdir / "steghide_audio.txt", output)
    return "wrote extracted" in output.lower() or "extracted data written" in output.lower()


# ──────────────────────── Orchestrator ────────────────────────


AUDIO_EXTENSIONS = {".wav", ".wave", ".au", ".aiff", ".aif"}


def is_audio_file(path: Path) -> bool:
    """Check if a file is a supported audio format."""
    return path.suffix.lower() in AUDIO_EXTENSIONS


def run_audio_analysis(audio_path: Path, outdir: Path) -> None:
    """Run all audio steganography checks."""
    audio_dir = outdir / "audio"
    ensure_dir(audio_dir)

    print(f"  [audio] Extracting strings from {audio_path.name} ...")
    extract_audio_strings(audio_path, audio_dir)

    if audio_path.suffix.lower() in (".wav", ".wave"):
        print(f"  [audio] Extracting WAV LSB data ...")
        extract_wav_lsb(audio_path, audio_dir / "lsb")

        print(f"  [audio] Generating spectrogram ...")
        generate_spectrogram(audio_path, audio_dir)

    print(f"  [audio] Trying steghide ...")
    steghide_audio(audio_path, audio_dir)

    save_text(audio_dir / "AUDIO_SUMMARY.txt", f"Audio analysis complete for {audio_path.name}")
