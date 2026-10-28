import importlib.util
import io
from contextlib import redirect_stderr
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from claude_protect.config import Config

SPEC = importlib.util.spec_from_file_location("tun_repair", Path(__file__).resolve().parents[1] / "scripts/repair_tun.py")
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)


class TunRepairTests(unittest.TestCase):
    def test_repair_requires_administrator_before_reading_configuration(self):
        with patch.object(repair.os, "geteuid", return_value=1000), \
                patch.object(repair, "load_config") as load, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                repair.main(["--proxy-port", "7897"])
            load.assert_not_called()

    def test_existing_namespace_refuses_all_service_changes(self):
        with patch.object(repair.os, "geteuid", return_value=0), \
                patch.object(repair, "load_config", return_value=Config(uid=1000)), \
                patch.object(repair.Path, "exists", return_value=True), \
                patch.object(repair.subprocess, "run") as run, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                repair.main(["--proxy-port", "7897"])
            run.assert_not_called()

    def test_active_or_unknown_service_refuses_file_updates(self):
        for state in ("active", "activating", "deactivating", ""):
            with self.subTest(state=state), patch.object(repair.os, "geteuid", return_value=0), \
                    patch.object(repair, "load_config", return_value=Config(uid=1000)), \
                    patch.object(repair.Path, "exists", return_value=False), \
                    patch.object(repair.subprocess, "run", return_value=types.SimpleNamespace(stdout=state)), \
                    patch.object(repair, "trusted_file") as trusted, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    repair.main(["--proxy-port", "7897"])
                trusted.assert_not_called()


if __name__ == "__main__":
    unittest.main()
