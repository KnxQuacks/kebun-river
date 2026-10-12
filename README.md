# river-auto-register

Auto-register akun [River Console](https://console.river.ai) + bikin API key otomatis, pakai browser stealth [Camoufox](https://camoufox.com) (Playwright-compatible).

Alur per akun: ambil email sementara dari [zenvex.dev](https://zenvex.dev) → signup di hosted-authkit (nama + email + password, lewati Cloudflare Turnstile) → ambil kode verifikasi 6 digit dari inbox → verifikasi → buka `/keys` → dialog *Create API Key* → simpan secret yang langsung ditampilkan.

## Syarat

- Python 3.10+
- Proxy **residensial** (IP datacenter biasanya mentok di Cloudflare *security verification* halaman authkit)

## Instalasi

```bash
pip install -r requirements.txt
```

Browser Camoufox otomatis diunduh saat pertama kali script dijalankan.

## Proxy

`--proxy` bisa URL tunggal atau path file (satu proxy per baris):

```
host:port:user:pass
```

Lihat `proxy.example.txt`. Untuk bulk, akun ke-i memakai proxy baris ke-i (muter kalau habis).

## Cara pakai

```bash
# 1 akun, browser kelihatan
python river.py --proxy proxy.txt --key-name auto

# bulk 2 akun, headless (tanpa browser kelihatan)
python river.py --headless --count 2 --proxy proxy.txt --key-name auto

# nama / password custom
python river.py --proxy proxy.txt --first Dimas --last Pratama --password "Rahasia.123" --key-name tes
```

| Flag | Default | Keterangan |
| --- | --- | --- |
| `--proxy` | — | URL proxy atau file proxy (`host:port:user:pass` per baris) |
| `--count` | `1` | jumlah akun bulk |
| `--headless` | off | jalan tanpa menampilkan browser |
| `--manual-turnstile` | off | klik Turnstile manual kalau auto gagal |
| `--key-name` | `auto` | nama API key yang dibuat |
| `--first` / `--last` | acak (nama Indonesia) | nama akun |
| `--password` | `ReactVite.911` | password akun (min 10 char) |
| `--email-prefix` | — | prefix email sementara |
| `--keep-open` | off | biarkan browser terbuka setelah selesai |

## Output

Otomatis disimpan di folder script (append + anti-duplikat, tanpa flag tambahan):

- **`result.json`** — array object akun: `first_name`, `last_name`, `email`, `password`, `api_key`, `api_key_status`, `console`
- **`apikeys.txt`** — satu API key per baris, tanpa data lain

Contoh `result.json`:

```json
[
  {
    "first_name": "Farhan",
    "last_name": "Rahman",
    "email": "l233ch4@souss.dev",
    "password": "ReactVite.911",
    "api_key": "rv_...",
    "api_key_status": "created",
    "console": "https://console.river.ai"
  }
]
```

## Cara kerja

1. **Email sementara** — buka zenvex.dev, ambil alamat yang di-generate, buka inbox (inbox dapat email via SSE stream).
2. **Signup** — `console.river.ai` redirect ke hosted-authkit (`login.console.river.ai/sign-up`), isi first/last name + email → Continue.
3. **Turnstile** — widget Cloudflare invisible; di-handle non-blocking (klik kalau ada checkbox, kalau tidak ditunggu auto-verify).
4. **Password** — tahap `sign-up/password` (satu halaman SPA), diketik via keyboard supaya input handler React ke-trigger.
5. **OTP** — poll `article.email-item` terbaru → klik → pindah ke tab **Text** → baca `.text-view`. Kode hanya diterima kalau dekat kata kunci (`verify`/`code`), supaya tidak termakan ID bounce (`bounces+113269907-...`) atau MIME boundary.
6. **API key** — `GET /api/me` buat konfirmasi login → `/keys` → klik *Create Key* → isi `#api-key-name` → submit → baca secret dari `#created-api-key` (fallback: field `key` di response JSON `POST /api/keys`).

## Catatan

- Secret key cuma ditampilkan sekali (dialog *"You won't be able to see it again!"*), jadi selalu dibuat baru per akun.
- Kalau `form signup tidak muncul (masih security verification?)`, ganti proxy / coba `--manual-turnstile`.
- File hasil (`result.json`, `apikeys.txt`, `proxy.txt`) sudah di-`.gitignore`, jangan upload.

## Struktur

```
river-auto-register/
├── river.py            # script utama
├── requirements.txt    # camoufox + requests
├── proxy.example.txt   # contoh format proxy
├── README.md
├── LICENSE             # The Unlicense (public domain)
├── result.json         # hasil (dibuat otomatis, di-gitignore)
└── apikeys.txt         # key saja (dibuat otomatis, di-gitignore)
```
