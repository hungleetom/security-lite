"""Windows: python build.py"""
import argparse
from pathlib import Path
import subprocess
import sys
import struct


def make_icon(path):
    """Create a small transparent shield icon without an image dependency."""
    size = 32
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            cx, cy = x - 15.5, y - 14
            # Rounded shield silhouette: broad shoulders tapering to a point.
            top = abs(cx) <= 11 and y >= 3
            taper = y >= 7 and abs(cx) <= max(2, 12 - (y - 7) * .43)
            inside = top and taper and y <= 28
            if inside:
                edge = y in (3, 4) or abs(cx) >= max(0, 10 - (y - 3) * .4)
                color = (27, 60, 92, 255) if edge else (44, 164, 184, 255)
                if 13 <= x <= 18 and 12 <= y <= 21:
                    color = (245, 250, 252, 255)
            else:
                color = (0, 0, 0, 0)
            row.append(color)
        pixels.append(row)
    # ICO stores a BGRA, bottom-up XOR bitmap followed by an empty AND mask.
    dib = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0,
                      size * size * 4, 0, 0, 0, 0)
    bitmap = b''.join(bytes((b, g, r, a)) for row in reversed(pixels) for r, g, b, a in row)
    mask = b'\x00' * (size * size // 8)
    image = dib + bitmap + mask
    directory = struct.pack('<HHH', 0, 1, 1)
    entry = struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(image), 22)
    path.write_bytes(directory + entry + image)

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--work-dir', default=str(root / 'work'))
args = parser.parse_args()
work = Path(args.work_dir).resolve()
work.mkdir(parents=True, exist_ok=True)
icon = work / 'security-lite-shield.ico'
make_icon(icon)
subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                '--onedir', '--windowed', '--name', 'SecurityLiteSimple',
                '--icon', str(icon),
                '--workpath', str(work / 'build'), '--specpath', str(work),
                '--distpath', str(root / 'dist'), str(root / 'main.py')], check=True)
