# PyInstaller spec — builds a single Windows executable (HDM-Dashboard.exe)
# with the Health Data Matrics logo as its icon.
#
#   pip install -r requirements-desktop.txt
#   pyinstaller --clean --noconfirm hospitalapp.spec
# Output: dist/HDM-Dashboard.exe

from PyInstaller.utils.hooks import collect_all, copy_metadata, collect_submodules

# Package metadata for Streamlit AND its whole dependency tree — this is the
# usual cause of "PackageNotFoundError" build/run failures.
datas = copy_metadata("streamlit", recursive=True)
binaries = []
hiddenimports = collect_submodules("streamlit")

# Code, data files and binaries for everything the app touches at runtime.
for pkg in [
    "streamlit", "streamlit_sortables", "altair", "plotly", "pandas", "numpy",
    "matplotlib", "reportlab", "pptx", "PIL", "openpyxl", "pyarrow", "tornado",
    "webview",
]:
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as exc:
        print("spec: skipping", pkg, "->", exc)

# The app itself, the branded theme, and the icon.
datas += [
    ("hospitalapp.py", "."),
    (".streamlit/config.toml", ".streamlit"),
    ("hdm_logo.ico", "."),
]

# Offline charts: bundle plotly.min.js if the workflow fetched it (optional).
import os as _os
if _os.path.isfile("plotly.min.js"):
    datas += [("plotly.min.js", ".")]

a = Analysis(
    ["app_desktop.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="HDM-Dashboard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,          # clean desktop app: no console window
    icon="hdm_logo.ico",    # company logo as the application icon
)
