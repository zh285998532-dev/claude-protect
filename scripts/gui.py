#!/usr/bin/env python3
"""Start the optional PySide6 panel from an unpacked source release."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
try:
    from claude_protect.gui import main
except ModuleNotFoundError as error:
    if error.name != "PySide6":
        raise
    raise SystemExit("请先在虚拟环境安装界面依赖：python -m pip install -r requirements-gui.txt")

if __name__ == "__main__":
    raise SystemExit(main())
