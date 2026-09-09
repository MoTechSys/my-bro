# Purpose: Windows VT entrypoint; owner [ASTRA]; updated 2026-09-09.
# Status: native build/test pending; source: Wazuh 4.14 custom AR, ISSUE-036.
# Configure VT_ROOTS in soc_windows_ar.py BEFORE packaging:
# pyinstaller --clean --onefile --name remove-threat remove-threat.py
# Deploy dist/remove-threat.exe in the protected active-response/bin directory.
from soc_windows_ar import main

if __name__ == '__main__':
    raise SystemExit(main('remove'))
