"""SEC-4 testleri."""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ctfrecon import run_all  # noqa: E402
from ctfrecon.analyzers import detect_filetype, decode_attempts, extract_strings  # noqa: E402


def test_png_magic():
    f = detect_filetype(b"\x89PNG\r\n\x1a\n" + b"x" * 20)
    assert "PNG" in f[0].detail


def test_base64_decode():
    payload = base64.b64encode(b"flag{merhaba_dunya}")
    findings = decode_attempts(payload)
    assert any("flag{merhaba_dunya}" in f.detail for f in findings)


def test_hex_decode():
    payload = b"666c61677b6865787d"  # "flag{hex}"
    findings = decode_attempts(payload)
    assert any("flag{hex}" in f.detail for f in findings)


def test_interesting_strings():
    data = b"random bytes here http://example.com/secret and flag{abc}"
    findings = extract_strings(data)
    assert any("http" in f.detail or "flag" in f.detail for f in findings)


def test_run_all_returns_findings():
    findings = run_all(b"%PDF-1.4 some content with key=12345")
    modules = {f.module for f in findings}
    assert "filetype" in modules
    assert "entropy" in modules
