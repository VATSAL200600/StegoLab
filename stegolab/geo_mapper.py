"""GPS extraction and interactive map generation from image EXIF data."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from .core import ensure_dir, save_text


# ──────────────────────── GPS coordinate extraction ────────────────────────


def _dms_to_decimal(dms_tuple, ref: str) -> float:
    """Convert EXIF GPS DMS (degrees, minutes, seconds) to decimal degrees."""
    try:
        degrees = float(dms_tuple[0])
        minutes = float(dms_tuple[1])
        seconds = float(dms_tuple[2])
        decimal = degrees + minutes / 60 + seconds / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return decimal
    except (TypeError, IndexError, ValueError):
        return 0.0


def extract_gps(img_path: Path) -> Optional[Dict[str, float]]:
    """Extract GPS coordinates from image EXIF data.

    Returns dict with 'latitude', 'longitude', and optionally 'altitude',
    or None if no GPS data found.
    """
    try:
        im = Image.open(img_path)
        exif_data = im._getexif()
        if not exif_data:
            return None

        gps_info = {}
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_tag_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag_name] = gps_value

        if not gps_info:
            return None

        lat = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        if lat is None or lon is None:
            return None

        result: Dict[str, float] = {
            "latitude": _dms_to_decimal(lat, lat_ref),
            "longitude": _dms_to_decimal(lon, lon_ref),
        }

        alt = gps_info.get("GPSAltitude")
        if alt is not None:
            try:
                result["altitude"] = float(alt)
            except (TypeError, ValueError):
                pass

        return result

    except Exception:
        return None


# ──────────────────────── Folium map generation ────────────────────────


def generate_map_folium(
    coords: Dict[str, float],
    img_path: Path,
    outdir: Path,
) -> Optional[Path]:
    """Generate an interactive HTML map using folium (Leaflet.js).

    Returns path to the generated map.html, or None on failure.
    """
    ensure_dir(outdir)
    try:
        import folium

        lat = coords["latitude"]
        lon = coords["longitude"]
        alt = coords.get("altitude", "N/A")

        m = folium.Map(location=[lat, lon], zoom_start=15, tiles="OpenStreetMap")

        popup_html = f"""
        <div style="font-family:system-ui;min-width:200px">
            <h4 style="margin:0 0 8px;color:#1a237e">📍 {img_path.name}</h4>
            <p style="margin:4px 0"><b>Latitude:</b> {lat:.6f}</p>
            <p style="margin:4px 0"><b>Longitude:</b> {lon:.6f}</p>
            <p style="margin:4px 0"><b>Altitude:</b> {alt}</p>
            <a href="https://www.google.com/maps?q={lat},{lon}" target="_blank"
               style="color:#1565c0">Open in Google Maps ↗</a>
        </div>
        """

        folium.Marker(
            [lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{img_path.name} — {lat:.4f}, {lon:.4f}",
            icon=folium.Icon(color="red", icon="camera", prefix="fa"),
        ).add_to(m)

        # Add a circle around the location
        folium.Circle(
            [lat, lon],
            radius=100,
            color="#e91e63",
            fill=True,
            fill_opacity=0.15,
        ).add_to(m)

        out_path = outdir / "map.html"
        m.save(str(out_path))
        return out_path

    except ImportError:
        return None
    except Exception:
        return None


# ──────────────────────── Fallback: static HTML map ────────────────────────


def generate_map_static(
    coords: Dict[str, float],
    img_path: Path,
    outdir: Path,
) -> Path:
    """Generate a simple static HTML map using OpenStreetMap embed (no folium needed)."""
    ensure_dir(outdir)
    lat = coords["latitude"]
    lon = coords["longitude"]
    alt = coords.get("altitude", "N/A")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>StegoLab GPS — {img_path.name}</title>
<style>
body{{font-family:Inter,system-ui,sans-serif;margin:0;padding:20px;background:#f5f5f5}}
.card{{background:white;border-radius:12px;padding:24px;max-width:800px;margin:20px auto;box-shadow:0 2px 12px rgba(0,0,0,.08)}}
h1{{color:#1a237e;margin-top:0}}
iframe{{width:100%;height:450px;border:none;border-radius:8px;margin-top:16px}}
.coords{{display:flex;gap:24px;flex-wrap:wrap}}
.coord-box{{background:#e8eaf6;padding:12px 20px;border-radius:8px;flex:1;min-width:150px}}
.coord-label{{font-size:12px;color:#5c6bc0;text-transform:uppercase;letter-spacing:1px}}
.coord-value{{font-size:20px;font-weight:600;color:#1a237e;margin-top:4px}}
a{{color:#1565c0}}
</style></head><body>
<div class="card">
<h1>📍 GPS Location — {img_path.name}</h1>
<div class="coords">
<div class="coord-box"><div class="coord-label">Latitude</div><div class="coord-value">{lat:.6f}</div></div>
<div class="coord-box"><div class="coord-label">Longitude</div><div class="coord-value">{lon:.6f}</div></div>
<div class="coord-box"><div class="coord-label">Altitude</div><div class="coord-value">{alt}</div></div>
</div>
<p><a href="https://www.google.com/maps?q={lat},{lon}" target="_blank">🗺️ Open in Google Maps ↗</a></p>
<iframe src="https://www.openstreetmap.org/export/embed.html?bbox={lon-0.01}%2C{lat-0.01}%2C{lon+0.01}%2C{lat+0.01}&layer=mapnik&marker={lat}%2C{lon}"></iframe>
</div>
<p style="text-align:center;color:#999;font-size:12px;margin-top:24px">Generated by StegoLab v4</p>
</body></html>"""

    out_path = outdir / "map.html"
    save_text(out_path, html)
    return out_path


# ──────────────────────── Orchestrator ────────────────────────


def run_geo_analysis(img_path: Path, outdir: Path) -> Optional[Dict[str, float]]:
    """Extract GPS data and generate a map if coordinates are found.

    Returns the GPS coordinates dict or None.
    """
    geo_dir = outdir / "geo"
    ensure_dir(geo_dir)

    coords = extract_gps(img_path)
    if coords is None:
        save_text(geo_dir / "gps_info.txt", "No GPS data found in image EXIF.")
        print("  [geo] No GPS coordinates found.")
        return None

    lat = coords["latitude"]
    lon = coords["longitude"]
    alt = coords.get("altitude", "N/A")
    print(f"  [geo] 📍 GPS found: {lat:.6f}, {lon:.6f} (alt: {alt})")

    save_text(
        geo_dir / "gps_info.txt",
        f"Latitude: {lat:.6f}\nLongitude: {lon:.6f}\nAltitude: {alt}\n"
        f"Google Maps: https://www.google.com/maps?q={lat},{lon}",
    )

    # Try folium first, fall back to static
    map_path = generate_map_folium(coords, img_path, geo_dir)
    if map_path is None:
        print("  [geo] folium not available, generating static map ...")
        map_path = generate_map_static(coords, img_path, geo_dir)

    print(f"  [geo] Map saved to {map_path}")
    return coords
