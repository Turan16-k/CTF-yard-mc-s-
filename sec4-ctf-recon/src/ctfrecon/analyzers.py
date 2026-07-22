"""
CTF recon analiz modulleri (dosya/string/entropi/encoding).

Tum moduller saf Python (standart kutuphane). Eklenti mimarisi: her
analiz bir fonksiyon, run_all() hepsini sirayla calistirir.
Egitim/CTF pratigi icindir.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    module: str
    title: str
    detail: str


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# ---- Dosya turu (magic bytes) ----
MAGIC = {
    b"\x89PNG": "PNG goruntu",
    b"\xff\xd8\xff": "JPEG goruntu",
    b"PK\x03\x04": "ZIP/Office/JAR arsivi",
    b"%PDF": "PDF belge",
    b"\x7fELF": "ELF (Linux yurutulebilir)",
    b"MZ": "PE (Windows yurutulebilir)",
    b"GIF8": "GIF goruntu",
    b"\x1f\x8b": "GZIP arsivi",
    b"Rar!": "RAR arsivi",
}


def detect_filetype(data: bytes) -> list[Finding]:
    for sig, name in MAGIC.items():
        if data.startswith(sig):
            return [Finding("filetype", "Dosya turu", f"{name} (sihirli bayt: {sig!r})")]
    return [Finding("filetype", "Dosya turu", "Bilinmeyen/duz veri")]


# ---- Yazdirilabilir string'ler ----
STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_strings(data: bytes, min_len: int = 4, limit: int = 20) -> list[Finding]:
    found = STRING_RE.findall(data)
    out = []
    # Ilginc olanlari oncele: flag, http, key, password
    interesting = [s for s in found if re.search(rb"flag|http|key|pass|secret|token", s, re.I)]
    for s in interesting[:limit]:
        out.append(Finding("strings", "Ilginc string", s.decode(errors="replace")))
    if not out and found:
        out.append(Finding("strings", "String ozeti",
                           f"{len(found)} string bulundu; ilki: {found[0].decode(errors='replace')[:60]}"))
    return out


# ---- Entropi (sifreli/sikistirilmis ipucu) ----
def entropy_check(data: bytes) -> list[Finding]:
    e = shannon_entropy(data)
    note = ""
    if e > 7.5:
        note = " -> yuksek: sifreli/sikistirilmis olabilir"
    elif e < 1.0:
        note = " -> cok dusuk: tekrarli/bos veri"
    return [Finding("entropy", "Shannon entropi", f"{e:.3f}{note}")]


# ---- Encoding tespiti ve cozme ----
def decode_attempts(data: bytes) -> list[Finding]:
    out = []
    text = data.strip()
    # base64?
    if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", text) and len(text) >= 8:
        try:
            dec = base64.b64decode(text, validate=False)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in dec):
                out.append(Finding("decode", "Base64 cozuldu", dec.decode(errors="replace")[:120]))
        except (binascii.Error, ValueError):
            pass
    # hex?
    if re.fullmatch(rb"(?:[0-9a-fA-F]{2})+", text):
        try:
            dec = bytes.fromhex(text.decode())
            out.append(Finding("decode", "Hex cozuldu", dec.decode(errors="replace")[:120]))
        except ValueError:
            pass
    # ROT13 (sadece harf agirlikli kisa metin)
    if re.fullmatch(rb"[A-Za-z\s]+", text) and len(text) < 200:
        import codecs
        rot = codecs.encode(text.decode(), "rot_13")
        if re.search(r"flag|the|key", rot, re.I):
            out.append(Finding("decode", "ROT13 ipucu", rot[:120]))
    return out


def run_all(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for fn in (detect_filetype, entropy_check, extract_strings, decode_attempts):
        findings.extend(fn(data))
    return findings
