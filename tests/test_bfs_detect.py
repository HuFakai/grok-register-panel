# -*- coding: utf-8 -*-
"""Unit tests for JWT bfs claim detection."""
from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sso_to_auth_json import (  # noqa: E402
    apply_bfs_to_cpa_record,
    inspect_cpa_record_bfs,
    inspect_jwt_bfs,
    inspect_token_bundle_bfs,
    scan_cpa_auth_dir_bfs,
    token_to_cpa_record,
)


def _jwt(payload: object) -> str:
    def b64(obj) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(payload)}.sig"


def test_bfs_key_presence_not_truthiness():
    clean = _jwt({"sub": "u1", "tier": "anon", "exp": 9999999999})
    flagged = _jwt({"sub": "u2", "bfs": 2, "exp": 9999999999})
    zero = _jwt({"sub": "u3", "bfs": 0, "exp": 9999999999})

    c = inspect_jwt_bfs(clean)
    assert c["ok"] is True
    assert c["has_bfs"] is False
    assert c["bfs"] is None

    f = inspect_jwt_bfs(flagged)
    assert f["has_bfs"] is True
    assert f["bfs"] == 2

    # value 0 still counts — key presence is the signal
    z = inspect_jwt_bfs(zero)
    assert z["has_bfs"] is True
    assert z["bfs"] == 0


def test_non_object_and_empty_payloads_are_safe():
    empty = _jwt({})
    empty_info = inspect_jwt_bfs(empty)
    assert empty_info["ok"] is True
    assert empty_info["has_bfs"] is False

    malformed_shape = _jwt([])
    shape_info = inspect_jwt_bfs(malformed_shape)
    assert shape_info["ok"] is False
    assert shape_info["has_bfs"] is False


def test_bundle_prefers_access_token_bfs():
    sso = _jwt({"sub": "sso-user"})
    access = _jwt({"sub": "acc-user", "bfs": 2, "referrer": "grok-build"})
    info = inspect_token_bundle_bfs(access_token=access, sso=sso)
    assert info["has_bfs"] is True
    assert info["source"] == "access_token"
    assert info["bfs"] == 2


def test_unknown_is_not_recorded_as_clean_and_cached_metadata_is_stale():
    unknown = inspect_token_bundle_bfs(access_token="opaque-access-token")
    assert unknown["ok"] is False
    assert unknown["has_bfs"] is False

    record = token_to_cpa_record(
        {"access_token": "opaque-access-token"}, email="unknown@example.com"
    )
    assert record["bfs"] is None
    assert record["bfs_checked"] is False
    assert record["bfs_status"] == "unknown"

    current_flagged = _jwt({"sub": "current", "bfs": 2})
    cached_clean = {
        "access_token": current_flagged,
        "bfs": False,
        "bfs_checked": True,
    }
    current = inspect_cpa_record_bfs(cached_clean)
    assert current["ok"] is True
    assert current["has_bfs"] is True
    assert current["source"] == "access_token"


def test_cpa_record_annotation():
    access = _jwt({"sub": "user-xyz", "bfs": 2, "exp": 2000000000})
    record = token_to_cpa_record(
        {"access_token": access, "refresh_token": "r", "expires_in": 3600},
        email="a@example.com",
        sso=_jwt({"sub": "user-xyz"}),
    )
    assert record["bfs"] is True
    assert record["bfs_checked"] is True
    assert record["bfs_value"] == 2
    assert record["email"] == "a@example.com"

    clean_access = _jwt({"sub": "clean", "exp": 2000000000})
    clean = token_to_cpa_record(
        {"access_token": clean_access, "expires_in": 3600},
        email="b@example.com",
    )
    assert clean["bfs"] is False
    assert clean["bfs_checked"] is True


def test_scan_auth_dir():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        flagged = {
            "type": "xai",
            "email": "flag@example.com",
            "access_token": _jwt({"sub": "f1", "bfs": 2}),
            "disabled": False,
        }
        clean = {
            "type": "xai",
            "email": "clean@example.com",
            "access_token": _jwt({"sub": "c1"}),
        }
        (root / "xai-flag@example.com.json").write_text(
            json.dumps(flagged), encoding="utf-8"
        )
        (root / "xai-clean@example.com.json").write_text(
            json.dumps(clean), encoding="utf-8"
        )
        (root / "auth.json").write_text(
            json.dumps(
                {
                    "https://auth.x.ai::client": {
                        "key": _jwt({"sub": "merged", "bfs": 2}),
                        "email": "merged@example.com",
                    }
                }
            ),
            encoding="utf-8",
        )
        summary = scan_cpa_auth_dir_bfs(root, include_clean=True)
        assert summary["total"] == 3
        assert summary["bfs_count"] == 2
        assert summary["clean_count"] == 1
        assert summary["bfs_rate"] == 66.67
        assert summary["bfs_value_dist"].get("2") == 2
        assert any(item["file"].startswith("auth.json#") for item in summary["items"])


def test_apply_bfs_and_record_field_shortcut():
    rec = {"email": "x@y.z", "bfs": True, "bfs_value": 2, "access_token": ""}
    info = inspect_cpa_record_bfs(rec)
    assert info["has_bfs"] is True
    assert info["source"] == "record.bfs"

    bare = {"access_token": _jwt({"sub": "z", "bfs": 2})}
    apply_bfs_to_cpa_record(bare)
    assert bare["bfs"] is True
    assert bare["bfs_value"] == 2


if __name__ == "__main__":
    test_bfs_key_presence_not_truthiness()
    test_non_object_and_empty_payloads_are_safe()
    test_bundle_prefers_access_token_bfs()
    test_unknown_is_not_recorded_as_clean_and_cached_metadata_is_stale()
    test_cpa_record_annotation()
    test_scan_auth_dir()
    test_apply_bfs_and_record_field_shortcut()
    print("ok")
