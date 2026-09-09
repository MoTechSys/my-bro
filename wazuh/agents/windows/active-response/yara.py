# Purpose: Windows YARA entrypoint; owner [ASTRA]; updated 2026-09-09.
# Status: native build/test pending; source: Wazuh 4.14 YARA PoC.
# Configure YARA_ROOTS in soc_windows_ar.py, then build on Windows:
# pyinstaller --clean --onefile --name soc-yara yara.py
from soc_windows_ar import main

if __name__ == '__main__':
    raise SystemExit(main('yara'))
