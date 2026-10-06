from __future__ import annotations

import io
import os
from pathlib import Path
import zipfile

from demo_cli.engine.simulate import simulate


def _setup_fixtures(tmp_path: Path) -> Path:
    root = tmp_path / "p"
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.txt").write_bytes(b"old")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "new")
        z.writestr("new.txt", "n")
    m_raw = buf.getvalue()
    (root / "m.zip").write_bytes(m_raw)

    data = bytearray(m_raw)
    idx = 0
    while True:
        pos = data.find(b"PK\x03\x04", idx)
        if pos == -1:
            break
        data[pos + 6] |= 0x01
        idx = pos + 4

    idx = 0
    while True:
        pos = data.find(b"PK\x01\x02", idx)
        if pos == -1:
            break
        data[pos + 8] |= 0x01
        idx = pos + 4

    enc_path = root / "enc.zip"
    enc_path.write_bytes(bytes(data))

    assert zipfile.ZipFile(str(enc_path)).infolist()[0].flag_bits & 1 == 1, "enc.zip carries encrypted bit"
    return root


def _rel_destroys(imp, root: Path) -> set[str]:
    return {os.path.relpath(p, str(root)).replace("\\", "/") for p in imp.destroys}


def _rel_creates(imp, root: Path) -> set[str]:
    return {os.path.relpath(p, str(root)).replace("\\", "/") for p in imp.creates}


def test_1_a_glued_password(tmp_path):
    root = _setup_fixtures(tmp_path)

    # 1. unzip -o -Psecret m.zip -> destroys {a.txt}, creates {new.txt}, no unknown
    imp1 = simulate("unzip -o -Psecret m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp1, root) == {"a.txt"}
    assert _rel_creates(imp1, root) == {"new.txt"}
    assert imp1.unknown == []

    # 2. unzip -oPsecret m.zip -> destroys {a.txt}, creates {new.txt}, no unknown
    imp2 = simulate("unzip -oPsecret m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp2, root) == {"a.txt"}
    assert _rel_creates(imp2, root) == {"new.txt"}
    assert imp2.unknown == []

    # 3. unzip -Pxo m.zip -> destroys {}, creates {new.txt}, no unknown
    imp3 = simulate("unzip -Pxo m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp3, root) == set()
    assert _rel_creates(imp3, root) == {"new.txt"}
    assert imp3.unknown == []

    # 4. unzip -Ppw m.zip -> destroys {}, creates {new.txt}, no unknown
    imp4 = simulate("unzip -Ppw m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp4, root) == set()
    assert _rel_creates(imp4, root) == {"new.txt"}
    assert imp4.unknown == []

    # 5. control: unzip -o -P secret m.zip -> destroys {a.txt}, creates {new.txt}, no unknown
    imp5 = simulate("unzip -o -P secret m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp5, root) == {"a.txt"}
    assert _rel_creates(imp5, root) == {"new.txt"}
    assert imp5.unknown == []

    # 6. control: unzip -l -Ppw m.zip -> nothing (lists only)
    imp6 = simulate("unzip -l -Ppw m.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp6, root) == set()
    assert _rel_creates(imp6, root) == set()
    assert imp6.unknown == []


def test_2_an_encrypted_archive(tmp_path):
    root = _setup_fixtures(tmp_path)

    # 1. unzip -o enc.zip -> unknown reasons exactly ["the archive is encrypted"], destroys {}
    imp1 = simulate("unzip -o enc.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp1, root) == set()
    assert [why for _t, why in imp1.unknown] == ["the archive is encrypted"]

    # 2. unzip -o -Ppw enc.zip -> destroys {a.txt}, creates {new.txt}, no unknown
    imp2 = simulate("unzip -o -Ppw enc.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp2, root) == {"a.txt"}
    assert _rel_creates(imp2, root) == {"new.txt"}
    assert imp2.unknown == []

    # 3. unzip -Ppw enc.zip -> destroys {}, creates {new.txt}, no unknown
    imp3 = simulate("unzip -Ppw enc.zip", cwd=str(root), budget_ms=10_000)
    assert _rel_destroys(imp3, root) == set()
    assert _rel_creates(imp3, root) == {"new.txt"}
    assert imp3.unknown == []

