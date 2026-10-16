from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import webui.bfs_ops as bfs_ops


def test_resolve_auth_dirs_accepts_relative_and_absolute_config_paths():
    with tempfile.TemporaryDirectory(prefix="grok-bfs-ops-") as temp:
        root = Path(temp)
        relative_dir = root / "relative-cpa"
        absolute_dir = root / "absolute-g2a"
        relative_dir.mkdir()
        absolute_dir.mkdir()
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "cpa_auth_dir": "relative-cpa",
                    "grok2api_auth_dir": str(absolute_dir),
                }
            ),
            encoding="utf-8",
        )

        previous = bfs_ops.CONFIG_FILE
        previous_cpa = bfs_ops.CPA_DIR
        previous_g2a = bfs_ops.G2A_DIR
        bfs_ops.CONFIG_FILE = config
        bfs_ops.CPA_DIR = relative_dir
        bfs_ops.G2A_DIR = absolute_dir
        try:
            resolved = bfs_ops._resolve_auth_dirs()
        finally:
            bfs_ops.CONFIG_FILE = previous
            bfs_ops.CPA_DIR = previous_cpa
            bfs_ops.G2A_DIR = previous_g2a

        assert resolved == [relative_dir, absolute_dir]


if __name__ == "__main__":
    test_resolve_auth_dirs_accepts_relative_and_absolute_config_paths()
    print("OK bfs ops")
