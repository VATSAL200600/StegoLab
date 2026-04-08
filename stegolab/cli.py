"""StegoLab v4 — CLI entry-point with all new feature flags."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

from .core import ensure_dir, save_text


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="stegolab",
        description="StegoLab v4 — All-in-One Steganography Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  stegolab image.png -o results              # Interactive menu
  stegolab image.png -o results --all        # Run everything
  stegolab image.png --all --report          # Run everything + HTML report
  stegolab image.png --hex                   # Hex anomaly analysis only
  stegolab image.png --smart-wordlist        # Generate contextual wordlist
  stegolab audio.wav --audio                 # Audio steganography analysis
  stegolab document.pdf --pdf                # PDF forensics
  stegolab --batch ./evidence/ -o results    # Batch process a folder
  stegolab image.png --all --map --report    # Full analysis + GPS map + report
""",
    )
    ap.add_argument("input", nargs="?", help="Path to input file (image/audio/PDF)")
    ap.add_argument("-o", "--outdir", default="stego_out", help="Output folder (default: stego_out)")

    # Run modes
    mode = ap.add_argument_group("Run Modes")
    mode.add_argument("--all", action="store_true", help="Run everything non-interactively")
    mode.add_argument("--tools", help="Comma-separated list of tools to run")
    mode.add_argument("--batch", metavar="DIR", help="Batch-process a directory of files")

    # Feature flags
    feat = ap.add_argument_group("Feature Flags")
    feat.add_argument("--hex", action="store_true", help="Run hex anomaly analysis")
    feat.add_argument("--audio", action="store_true", help="Run audio steganography analysis")
    feat.add_argument("--pdf", action="store_true", help="Run PDF forensic analysis")
    feat.add_argument("--map", action="store_true", help="Generate GPS map if coordinates found")
    feat.add_argument("--smart-wordlist", action="store_true", help="Auto-generate contextual wordlist")
    feat.add_argument("--report", action="store_true", help="Generate HTML report")

    # Options
    opts = ap.add_argument_group("Options")
    opts.add_argument("--bruteforce", help="Path to a wordlist for steghide bruteforce")
    opts.add_argument("--stegsolve", help="Path to StegSolve.jar (optional)")
    opts.add_argument("--workers", type=int, default=4, help="Parallel workers for batch mode (default: 4)")

    return ap.parse_args()


def _run_image_all(img: Path, outdir: Path, args: argparse.Namespace) -> None:
    """Run the complete image analysis pipeline."""
    from .image_analysis import (
        extract_exif_pillow, split_channels, bit_planes,
        lsb_streams_and_carve, do_strings, do_binwalk,
        do_exiftool, do_zsteg, do_stegseek, steghide_attempts,
    )

    print("\n═══ Built-in Analysis ═══")
    print("  [builtin] Extracting EXIF ...")
    extract_exif_pillow(img, outdir / "builtin")
    print("  [builtin] Splitting channels ...")
    split_channels(img, outdir / "builtin" / "channels")
    print("  [builtin] Generating bit-planes ...")
    bit_planes(img, outdir / "builtin" / "bitplanes")
    print("  [builtin] Extracting LSB streams ...")
    lsb_streams_and_carve(img, outdir / "builtin")

    print("\n═══ External Tools ═══")
    print("  [strings] scanning ...")
    do_strings(img, outdir)
    print("  [binwalk] scanning ...")
    do_binwalk(img, outdir)
    print("  [exiftool] scanning ...")
    do_exiftool(img, outdir)
    print("  [zsteg] scanning ...")
    do_zsteg(img, outdir)
    print("  [stegseek] scanning ...")
    do_stegseek(img, outdir)

    # Smart wordlist if requested
    wordlist = Path(args.bruteforce).expanduser().resolve() if args.bruteforce else None
    if args.smart_wordlist:
        print("\n═══ Smart Wordlist ═══")
        from .smart_bruteforce import generate_contextual_wordlist
        wordlist = generate_contextual_wordlist(img, outdir / "smart_bruteforce")
        print(f"  [smart] Wordlist generated: {wordlist}")

    print("\n═══ Steghide Attempts ═══")
    steghide_attempts(img, outdir, wordlist)

    # Stegsolve howto
    stegsolve = Path(args.stegsolve).expanduser().resolve() if args.stegsolve else None
    if stegsolve and stegsolve.exists():
        save_text(
            outdir / "stegsolve" / "stegsolve_howto.txt",
            f'java -jar "{stegsolve}" "{img}"',
        )


def _run_selected_tools(img: Path, outdir: Path, tools_str: str, args: argparse.Namespace) -> None:
    """Run user-selected tools."""
    from .image_analysis import (
        extract_exif_pillow, split_channels, bit_planes,
        lsb_streams_and_carve, do_strings, do_binwalk,
        do_exiftool, do_zsteg, do_stegseek, steghide_attempts,
    )

    wordlist = Path(args.bruteforce).expanduser().resolve() if args.bruteforce else None
    tools = [t.strip().lower() for t in tools_str.split(",") if t.strip()]
    mapping = {
        "builtin": lambda: (
            extract_exif_pillow(img, outdir / "builtin"),
            split_channels(img, outdir / "builtin" / "channels"),
            bit_planes(img, outdir / "builtin" / "bitplanes"),
            lsb_streams_and_carve(img, outdir / "builtin"),
        ),
        "strings": lambda: do_strings(img, outdir),
        "binwalk": lambda: do_binwalk(img, outdir),
        "exiftool": lambda: do_exiftool(img, outdir),
        "zsteg": lambda: do_zsteg(img, outdir),
        "stegseek": lambda: do_stegseek(img, outdir),
        "steghide": lambda: steghide_attempts(img, outdir, wordlist),
    }
    for t in tools:
        fn = mapping.get(t)
        if fn:
            print(f"  [{t}] running ...")
            fn()
        else:
            print(f"  [?] Unknown tool: {t}")


def _interactive_menu(img: Path, outdir: Path, args: argparse.Namespace) -> None:
    """The familiar interactive menu from v3, now with new options."""
    from .image_analysis import (
        extract_exif_pillow, split_channels, bit_planes,
        lsb_streams_and_carve, steghide_attempts, repair_image,
    )
    from .hex_viewer import run_hex_analysis
    from .geo_mapper import run_geo_analysis
    from .smart_bruteforce import generate_contextual_wordlist
    from .report import generate_report

    wordlist = Path(args.bruteforce).expanduser().resolve() if args.bruteforce else None

    while True:
        print("""
╔══════════════════════════════════════════════╗
║         StegoLab v4 — Interactive Menu       ║
╠══════════════════════════════════════════════╣
║  1) Run everything (built-ins + external)    ║
║  2) Choose tools manually                    ║
║  3) Steghide no-password & small bruteforce  ║
║  4) Repair image headers                     ║
║  5) Hex anomaly analysis         [NEW]       ║
║  6) GPS map extraction           [NEW]       ║
║  7) Smart wordlist generation    [NEW]       ║
║  8) Generate HTML report         [NEW]       ║
║  9) Exit                                     ║
╚══════════════════════════════════════════════╝
""")
        c = input("Choose option (1-9): ").strip()
        if c == "1":
            _run_image_all(img, outdir, args)
        elif c == "2":
            tools = input("Tools (comma-separated: builtin,strings,binwalk,exiftool,zsteg,stegseek,steghide): ").strip()
            if tools:
                _run_selected_tools(img, outdir, tools, args)
        elif c == "3":
            steghide_attempts(img, outdir, wordlist)
        elif c == "4":
            repaired = repair_image(img, outdir)
            if repaired:
                print(f"  -> {len(repaired)} repair(s) saved in repairs/ folder.")
        elif c == "5":
            run_hex_analysis(img, outdir)
        elif c == "6":
            run_geo_analysis(img, outdir)
        elif c == "7":
            wl = generate_contextual_wordlist(img, outdir / "smart_bruteforce")
            print(f"  -> Wordlist saved: {wl}")
        elif c == "8":
            rpt = generate_report(img, outdir)
            print(f"  -> Report saved: {rpt}")
        elif c in ("9", "q", "quit", "exit"):
            print("Exiting.")
            break
        else:
            print("Unknown choice. Try again.")


def main() -> None:
    args = parse_args()
    outdir = Path(args.outdir).expanduser().resolve()
    ensure_dir(outdir)

    # ──── Batch mode ────
    if args.batch:
        batch_dir = Path(args.batch).expanduser().resolve()
        if not batch_dir.is_dir():
            print(f"Error: {batch_dir} is not a directory")
            sys.exit(1)

        print(f"\n🔄 Batch mode: analysing {batch_dir} ...")
        from .batch import run_batch
        results = run_batch(batch_dir, outdir, max_workers=args.workers)

        if args.report:
            # Generate combined batch report — use a dummy path
            from .report import generate_report
            rpt = generate_report(batch_dir, outdir)
            print(f"\n📊 Batch report: {rpt}")

        print(f"\n✅ Batch complete. Results in {outdir}")
        return

    # ──── Single-file mode ────
    if not args.input:
        print("Error: no input file specified. Use --batch for directory mode.")
        parse_args()  # triggers help
        sys.exit(1)

    img = Path(args.input).expanduser().resolve()
    if not img.exists():
        print(f"Error: input not found: {img}")
        sys.exit(1)

    ext = img.suffix.lower()

    # Detect file type and route accordingly
    if args.audio or ext in {".wav", ".wave", ".au", ".aiff", ".aif"}:
        print(f"\n🎵 Audio analysis: {img.name}")
        from .audio_analysis import run_audio_analysis
        run_audio_analysis(img, outdir)
        if args.report:
            from .report import generate_report
            generate_report(img, outdir)
        print(f"\n✅ Done. Results in {outdir}")
        return

    if args.pdf or ext == ".pdf":
        print(f"\n📄 PDF forensics: {img.name}")
        from .pdf_analysis import run_pdf_analysis
        run_pdf_analysis(img, outdir)
        if args.report:
            from .report import generate_report
            generate_report(img, outdir)
        print(f"\n✅ Done. Results in {outdir}")
        return

    # Image analysis (default)
    print(f"\n🖼️  Image analysis: {img.name}")

    if args.all:
        _run_image_all(img, outdir, args)

        # Always run hex analysis in --all mode
        print("\n═══ Hex Anomaly Analysis ═══")
        from .hex_viewer import run_hex_analysis
        run_hex_analysis(img, outdir)

        # GPS map
        if args.map:
            print("\n═══ GPS Map ═══")
            from .geo_mapper import run_geo_analysis
            run_geo_analysis(img, outdir)

        if args.report:
            print("\n═══ HTML Report ═══")
            from .report import generate_report
            rpt = generate_report(img, outdir)
            print(f"  Report saved: {rpt}")

        save_text(
            outdir / "REPORT_SUMMARY.txt",
            f"StegoLab v4 report for {img.name} — {time.ctime()}",
        )
        print(f"\n✅ Done. Results in {outdir}")
        return

    if args.tools:
        _run_selected_tools(img, outdir, args.tools, args)
        print(f"\n✅ Done. Results in {outdir}")
        return

    # Individual feature flags
    ran_something = False

    if args.hex:
        print("\n═══ Hex Anomaly Analysis ═══")
        from .hex_viewer import run_hex_analysis
        run_hex_analysis(img, outdir)
        ran_something = True

    if args.map:
        print("\n═══ GPS Map ═══")
        from .geo_mapper import run_geo_analysis
        run_geo_analysis(img, outdir)
        ran_something = True

    if args.smart_wordlist:
        print("\n═══ Smart Wordlist ═══")
        from .smart_bruteforce import generate_contextual_wordlist
        wl = generate_contextual_wordlist(img, outdir / "smart_bruteforce")
        print(f"  Wordlist saved: {wl}")
        ran_something = True

    if args.report:
        print("\n═══ HTML Report ═══")
        from .report import generate_report
        rpt = generate_report(img, outdir)
        print(f"  Report saved: {rpt}")
        ran_something = True

    if ran_something:
        print(f"\n✅ Done. Results in {outdir}")
        return

    # If no flags, go interactive
    _interactive_menu(img, outdir, args)


if __name__ == "__main__":
    main()
