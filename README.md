[README.md](https://github.com/user-attachments/files/30285268/README.md)
# SEC-4 — Otomatik CTF Recon Yardımcısı

> 🛡️ **Yalnızca yetkili hedefler / CTF pratiği içindir.**

Verilen bir dosya veya web hedefi için ilk keşfi (recon) otomatikleştirir: dosya türü, string, entropi, encoding çözme, web başlık/ipucu analizi.

## Modüller (eklenti mimarisi)
**Dosya** (`analyzers.py`):
- Magic byte ile dosya türü tespiti
- İlginç string çıkarımı (flag/http/key/pass...)
- Shannon entropi (şifreli/sıkıştırılmış ipucu)
- Otomatik decode: Base64, Hex, ROT13

**Web** (`web.py`):
- HTTP başlıkları + teknoloji parmak izi
- HTML yorumları, flag deseni `xxx{...}`, robots.txt

## Kullanım
```bash
cd src
python -m ctfrecon.cli file <dosya> [--json rapor.json]
python -m ctfrecon.cli web https://hedef.ornek
```
Örnek: base64 içeren dosyayı verdiğinde otomatik çözer → `flag{...}` ortaya çıkar.

## Test
```bash
python -m pytest tests/ -q   # 5 test
```

## Tasarım
- **Saf Python** (standart kütüphane) — taşınabilir, kurulum derdi yok.
- **Modüler**: her analiz bir fonksiyon; yeni dedektör eklemek kolay.
- **Rapor**: insan-okunur + JSON çıktı (takım paylaşımı).

## Geliştirme yol haritası
1. Kategori bazlı otomasyon (pwn, crypto, forensics, stego).
2. `binwalk`/steganografi entegrasyonu (gömülü dosya çıkarma).
3. LLM destekli ipucu/çözüm önerisi.
4. Web arayüzü + takım paylaşımı.
5. Otomatik writeup taslağı üretimi.
