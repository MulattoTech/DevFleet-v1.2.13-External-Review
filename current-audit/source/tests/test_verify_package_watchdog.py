import sys
from pathlib import Path

import pytest


TOOLS = Path(__file__).parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
from verify_package import run_bounded  # noqa: E402


def test_verify_package_watchdog_allows_normal_success():
    result = run_bounded([sys.executable, "-c", "print('ok')"], timeout=5, label="normal test")
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"


def test_verify_package_watchdog_reports_timeout():
    with pytest.raises(RuntimeError, match="timeout"):
        run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2, label="sleeping hook")


def test_verify_package_watchdog_reports_output_flood():
    with pytest.raises(RuntimeError, match="output limit"):
        run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000); sys.stdout.flush()"],
            timeout=5,
            output_limit=4096,
            label="flooding hook",
        )
