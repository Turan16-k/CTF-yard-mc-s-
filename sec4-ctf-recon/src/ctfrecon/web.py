"""
Web recon modulu (yetkili hedefler / CTF icin).

Standart kutuphane (urllib) ile temel pasif/aktif recon:
  - HTTP basliklari, sunucu/teknoloji ipuclari
  - robots.txt
  - sayfa icindeki yorumlar ve gizli ipuclari

Sadece test izni olan hedeflerde kullanin.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class WebFinding:
    title: str
    detail: str


TECH_HINTS = {
    "X-Powered-By": "Backend teknolojisi",
    "Server": "Sunucu yazilimi",
    "Set-Cookie": "Oturum/cerez",
    "X-Generator": "Icerik yonetim sistemi",
}


def recon(url: str, timeout: float = 8.0) -> list[WebFinding]:
    import urllib.request
    out: list[WebFinding] = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctf-recon/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            body = resp.read(200_000).decode(errors="replace")
    except Exception as exc:
        return [WebFinding("Hata", f"Baglanti basarisiz: {exc}")]

    for h, desc in TECH_HINTS.items():
        if h in headers:
            out.append(WebFinding(desc, f"{h}: {headers[h]}"))

    # HTML yorumlari (gizli ipucu)
    for c in re.findall(r"<!--(.*?)-->", body, re.S)[:5]:
        c = c.strip()
        if c:
            out.append(WebFinding("HTML yorumu", c[:120]))

    # flag deseni
    for m in re.findall(r"[A-Za-z0-9_]{0,10}\{[^}]{2,60}\}", body)[:5]:
        out.append(WebFinding("Olasi flag deseni", m))

    # robots.txt
    try:
        from urllib.parse import urljoin
        robots = urljoin(url, "/robots.txt")
        req2 = urllib.request.Request(robots, headers={"User-Agent": "ctf-recon/0.1"})
        with urllib.request.urlopen(req2, timeout=timeout) as r2:
            txt = r2.read(5000).decode(errors="replace")
            if "Disallow" in txt:
                out.append(WebFinding("robots.txt", txt[:200]))
    except Exception:
        pass

    return out or [WebFinding("Bilgi", "Belirgin ipucu bulunamadi")]
