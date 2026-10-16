import shutil
from pathlib import Path
import subprocess

src_jpg = Path(r"C:\Users\User\.gemini\antigravity-ide\brain\f597375c-9408-40ed-9566-c883758cdc84\trinity_cyber_emblem_1791907165556.jpg")
dest_png = Path(r"c:\Users\User\.gemini\antigravity\scratch\autonomous-circularity-network\packages\bartholomew-trinity\icon.png")

ps_cmd = f"""
Add-Type -AssemblyName System.Drawing
$img = [System.Drawing.Image]::FromFile('{src_jpg}')
$img.Save('{dest_png}', [System.Drawing.Imaging.ImageFormat]::Png)
$img.Dispose()
"""

res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
if res.returncode == 0 and dest_png.exists():
    print(f"[OK] Icon updated: {dest_png} ({dest_png.stat().st_size} bytes)")
else:
    print(f"[ERR] Failed: {res.stderr}")
