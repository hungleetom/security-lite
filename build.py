"""Windows: python build.py"""
import argparse
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--work-dir', default=str(root / 'work'))
args = parser.parse_args()
work = Path(args.work_dir).resolve()
work.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                '--onedir', '--windowed', '--name', 'SecurityLiteSimple',
                '--workpath', str(work / 'build'), '--specpath', str(work),
                '--distpath', str(root / 'dist'), str(root / 'main.py')], check=True)
