#!/usr/bin/env python3
"""Auto-register akun River AI (console.river.ai) + ambil API key (backend: Camoufox).

Alur per akun:
  1. Buka zenvex.dev di Camoufox -> ambil alamat email sementara, buka inbox.
  2. Buka console.river.ai -> redirect ke hosted-authkit -> isi first/last
     name + email, lewati Cloudflare Turnstile, klik Continue.
  3. Isi password di tahap sign-up/password, tunggu halaman kode verifikasi.
  4. Poll inbox zenvex via DOM (klik baris article.email-item terbaru, baca
     tab Text di preview), ambil kode 6 digit, isi di halaman authkit.
  5. Setelah masuk console, buka /keys -> dialog Create API Key (isi nama) ->
     baca secret dari #created-api-key.

Hasil selalu disimpan (append, anti-duplikat):
  - result.json : array object akun {first_name, last_name, email, password,
                  api_key, api_key_status, console}
  - apikeys.txt : satu API key per baris
  - ~/workspace/river_ai/run/network.json : traffic intercept terakhir
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse

import requests

try:
    from camoufox.sync_api import Camoufox
except ImportError:
    sys.exit("butuh package 'camoufox': pip install camoufox")

BASE = os.path.expanduser("~/workspace/river_ai")
OUT = os.path.join(BASE, "run")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_JSON = os.path.join(SCRIPT_DIR, "result.json")
APIKEYS_TXT = os.path.join(SCRIPT_DIR, "apikeys.txt")
SIGNUP_URL = "https://console.river.ai/signup"
KEYS_URL = "https://console.river.ai/keys"
ZENvex = "https://zenvex.dev/"

CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

FIRST = ["Dimas", "Rizky", "Fajar", "Bagus", "Yoga", "Ilham", "Reza", "Farhan",
         "Galih", "Hendra", "Irfan", "Joko", "Kurnia", "Lukman", "Nanda", "Putra",
         "Ayu", "Dewi", "Sinta", "Maya", "Nadia", "Putri", "Rina", "Sari"]
LAST = ["Pratama", "Saputra", "Wijaya", "Santoso", "Nugroho", "Kusuma", "Rahman",
        "Setiawan", "Hidayat", "Gunawan", "Firmansyah", "Ramadhan", "Maharani",
        "Anggraini", "Lestari", "Puspita", "Wulandari", "Utami"]

DEFAULT_PASSWORD = "ReactVite.911"


def gen_password(n=20):
    import secrets as _secrets
    import string as _string
    alpha = _string.ascii_letters + _string.digits + "!@#$%^&*"
    return "".join(_secrets.choice(alpha) for _ in range(n))


def append_result(path, result):
    """Tambah satu akun ke result.json tanpa overwrite.

    Format file: JSON array of objects. File lama berisi satu object
    (format sebelum update) otomatis dikonversi jadi array.
    """
    rows = []
    try:
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        if isinstance(old, list):
            rows = old
        elif isinstance(old, dict):
            rows = [old]
    except (FileNotFoundError, ValueError):
        rows = []
    rows.append(result)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    return len(rows)


def append_unique_result(path, result):
    """Append ke result.json, skip kalau api_key sudah tercatat."""
    rows = []
    try:
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        if isinstance(old, list):
            rows = old
        elif isinstance(old, dict):
            rows = [old]
    except (FileNotFoundError, ValueError):
        rows = []
    if result.get("api_key") and any(
            r.get("api_key") == result["api_key"] for r in rows):
        return len(rows)
    return append_result(path, result)


def append_apikey(path, api_key):
    """Tambah satu baris apikey (hanya key), skip kalau sudah ada."""
    key = api_key.strip()
    try:
        with open(path, encoding="utf-8") as f:
            if any(l.strip() == key for l in f):
                return False
    except FileNotFoundError:
        pass
    with open(path, "a", encoding="utf-8") as f:
        f.write(key + "\n")
    return True


def log(msg):
    line = f"[river] {msg}"
    tag = getattr(_worker, "tag", "")
    if tag:
        line = f"[river][{tag}] {msg}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        print(line.encode("ascii", errors="replace").decode("ascii"), flush=True)


_worker = threading.local()
FILE_LOCK = threading.Lock()


def build_proxy(args):
    raw = args.proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not raw:
        return None
    pu = urllib.parse.urlparse(raw)
    proxy = {"server": f"{pu.scheme or 'http'}://{pu.hostname}:{pu.port}"}
    if pu.username:
        proxy["username"] = urllib.parse.unquote(pu.username)
    if pu.password:
        proxy["password"] = urllib.parse.unquote(pu.password)
    return proxy


def launch(args):
    # browser tanpa proxy (pakai egress datacenter bawaan env);
    # proxy residensial hanya dipakai di context halaman river.ai
    kw = {"headless": args.headless}
    cf = Camoufox(**kw)
    browser = cf.__enter__()
    browser._cf_wrapper = cf
    return browser


def close_browser(browser):
    cf = getattr(browser, "_cf_wrapper", None)
    if cf is not None:
        cf.__exit__(None, None, None)
    else:
        try:
            browser.close()
        except Exception:
            pass


def attach_intercept(page, netlog, tag):
    def on_req(req):
        try:
            netlog.append({"tag": tag, "type": "req", "method": req.method,
                           "url": req.url, "headers": dict(req.headers),
                           "post": (req.post_data or "")[:3000]})
        except Exception:
            pass
    def on_resp(resp):
        try:
            entry = {"tag": tag, "type": "resp", "status": resp.status,
                     "url": resp.url, "headers": dict(resp.headers)}
            ct = resp.headers.get("content-type", "")
            if any(k in ct for k in ("json", "text", "javascript")) and \
                    len(resp.url) < 400 and \
                    not any(k in resp.url for k in ("font", "mixpanel", "forwarder.workos",
                                                   "cdn-cgi/rum", "challenge-platform")):
                try:
                    entry["body"] = resp.text()[:6000]
                except Exception:
                    pass
            netlog.append(entry)
        except Exception:
            pass
    page.on("request", on_req)
    page.on("response", on_resp)




# ---------- turnstile ----------

def solve_turnstile(page, manual=False, timeout=60):
    """Klik checkbox Turnstile di iframe Cloudflare; True kalau terverifikasi."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        frames = [f for f in page.frames if "challenges.cloudflare.com" in (f.url or "")]
        if not frames:
            return True  # tidak ada widget
        f = frames[0]
        try:
            state = f.evaluate("""() => ({
                bodyLen: document.body ? document.body.innerHTML.length : -1,
                text: (document.body ? document.body.innerText : '').slice(0, 200),
                checked: !!document.querySelector('input[type=checkbox]:checked')
            })""")
        except Exception:
            state = {}
        log(f"turnstile state: {state}")
        if state.get("checked") or "success" in (state.get("text") or "").lower():
            return True
        if state.get("bodyLen", 0) and state["bodyLen"] > 0 and not manual:
            try:
                f.locator("body").click(timeout=6000)
                log("klik checkbox turnstile")
            except Exception as e:
                log(f"klik turnstile gagal: {str(e)[:80]}")
        elif manual:
            input("[river] selesaikan Turnstile di jendela browser, lalu tekan Enter ... ")
            return True
        time.sleep(4)
    return False


# ---------- zenvex ----------

def get_temp_address(zv, prefix=None):
    zv.goto(ZENvex, wait_until="domcontentloaded", timeout=60000)
    if prefix:
        try:
            for i in range(zv.locator("input").count()):
                el = zv.locator("input").nth(i)
                if "@" in (el.input_value() or ""):
                    el.fill(prefix, timeout=5000)
                    el.press("Enter")
                    time.sleep(2)
                    break
        except Exception:
            pass
    for _ in range(40):
        m = EMAIL_RE.search(zv.inner_text("body"))
        if m:
            addr = m.group(0)
            log(f"alamat sementara: {addr}")
            return addr
        time.sleep(1)
    raise RuntimeError("alamat email tidak muncul di zenvex.dev")


def open_inbox(zv, manual=False):
    solve_turnstile(zv, manual=manual, timeout=45)
    btn = None
    for sel in ["button.cta-btn", "text=/open inbox/i"]:
        try:
            loc = zv.locator(sel).first
            loc.wait_for(state="visible", timeout=8000)
            btn = loc
            break
        except Exception:
            continue
    if btn is None:
        log("tombol open inbox tidak ketemu, lanjut apa adanya")
        zv.wait_for_timeout(3000)
        return
    try:
        for _ in range(30):
            try:
                if not btn.is_disabled():
                    break
            except Exception:
                pass
            time.sleep(2)
        btn.click(timeout=8000)
        log("inbox dibuka")
    except Exception as e:
        log(f"tombol open inbox tidak bisa diklik ({str(e)[:80]}), lanjut apa adanya")
    zv.wait_for_timeout(3000)


def _inbox_via_api(zv, address):
    data = zv.evaluate(
        """(addr) => fetch('/api/inbox/' + encodeURIComponent(addr),
                            {headers: {'Accept': 'application/json'}})
                        .then(r => r.json()).catch(e => ({error: String(e)}))""",
        address,
    )
    if not isinstance(data, dict) or not data.get("success"):
        return []
    res = data.get("result", data)
    if isinstance(res, dict):
        for k in ("emails", "items", "messages", "data"):
            if isinstance(res.get(k), list):
                return res[k]
    return res if isinstance(res, list) else []


def _email_detail(zv, mail_id):
    return zv.evaluate(
        """(id) => fetch('/api/emails/' + encodeURIComponent(id),
                         {headers: {'Accept': 'application/json'}})
                     .then(r => r.json()).catch(e => ({}))""",
        mail_id,
    )


def _extract_code(obj):
    texts = []
    if isinstance(obj, dict):
        res = obj.get("result", obj)
        if isinstance(res, dict):
            for k in ("subject", "from", "sender", "body", "text", "html",
                      "snippet", "content", "message", "preview", "textContent",
                      "text_body", "html_body"):
                if res.get(k):
                    texts.append(str(res[k]))
            for k in ("subject", "body", "text", "html", "content"):
                if obj.get(k):
                    texts.append(str(obj[k]))
        elif isinstance(res, list):
            for it in res:
                c = _extract_code(it)
                if c:
                    return c
    elif isinstance(obj, (list, tuple)):
        for it in obj:
            c = _extract_code(it)
            if c:
                return c
    elif isinstance(obj, str):
        texts.append(obj)
    blob = re.sub(r"<[^>]+>", " ", " ".join(texts))
    return _extract_code_text(blob)


def _extract_code_text(text):
    """Ambil kode dari body text email (sudah decode, BUKAN raw MIME).

    Hanya terima 6 digit yang dekat kata kunci (verify/code/kode) supaya
    tidak termakan ID bounce (bounces+113269907-...) atau MIME boundary.
    """
    blob = re.sub(r"\s+", " ", text or "")
    m = re.search(r"(?:verify|verification|code|kode)[^\d]{0,80}(\d{6})",
                  blob, re.I)
    if m:
        return m.group(1)
    return None


def wait_for_code(zv, address, timeout=300, sender_hint="river"):
    """Poll inbox zenvex via DOM (email masuk lewat SSE stream).

    Baris email = article.email-item (urutan Newest), preview di panel kanan
    dengan tab HTML/Text (.text-view). Klik baris terbaru, baca preview-nya.
    """
    log("menunggu email kode verifikasi ...")
    deadline = time.time() + timeout
    last_n = -1
    last_log = 0
    while time.time() < deadline:
        try:
            n = zv.locator("article.email-item").count()
        except Exception:
            n = 0
        if n > 0:
            if n != last_n:
                log(f"email di inbox: {n}")
                last_n = n
            # coba baris dari terbaru (index 0) s/d 5; baca HANYA tab Text
            for i in range(min(n, 5)):
                try:
                    row = zv.locator("article.email-item").nth(i)
                    info = (row.inner_text() or "")[:160]
                except Exception:
                    continue
                low_info = info.lower()
                if "river" not in low_info and "verify" not in low_info:
                    continue  # baris bukan dari river, skip
                log(f"buka email[{i}]: {info[:100]!r}")
                try:
                    row.click(timeout=3000)
                    zv.wait_for_timeout(2500)
                except Exception:
                    continue
                # alihkan preview ke tab Text (default HTML) — coba bbrp selector
                detail = ""
                for _try in range(3):
                    try:
                        tloc = zv.locator(".text-view").first
                        if tloc.count():
                            detail = tloc.inner_text() or ""
                            if detail.strip():
                                break
                    except Exception:
                        pass
                    for sel in ["[role=tablist] [role=tab]:has-text('Text')",
                                "button:has-text('Text')",
                                "text=/^text$/i"]:
                        try:
                            tab = zv.locator(sel).first
                            if tab.count() and tab.is_visible():
                                tab.click(timeout=2000)
                                zv.wait_for_timeout(1200)
                                break
                        except Exception:
                            continue
                    zv.wait_for_timeout(1000)
                if not detail.strip():
                    log(f"email[{i}] tab Text kosong, lanjut baris berikut ...")
                    continue
                code = _extract_code_text(detail)
                if code and "river" in detail.lower():
                    log(f"kode ketemu di email[{i}] (tab Text): {code}")
                    return code
                log(f"email[{i}] tidak ada kode valid di tab Text, lanjut ...")
        else:
            if time.time() - last_log > 20:
                left = int(deadline - time.time())
                log(f"belum ada email ... ({left} dtk tersisa)")
                last_log = time.time()
        time.sleep(3)
    raise RuntimeError("kode verifikasi tidak datang dalam batas waktu")


# ---------- river signup ----------

def build_authorize_url(page):
    """Bangun URL authorize WorkOS langsung + simpan PKCE verifier di sessionStorage.

    PKCE di-generate di Python (Camoufox memblokir akses TypedArray dari
    page.evaluate); page hanya menerima string polos.
    """
    import base64 as _b64
    import hashlib as _hl
    import secrets as _secrets

    b64u = lambda b: _b64.urlsafe_b64encode(b).rstrip(b"=").decode()
    verifier = b64u(_secrets.token_bytes(96))
    challenge = b64u(_hl.sha256(verifier.encode()).digest())
    # halaman SPA console kadang masih navigasi/redirect saat dipanggil;
    # tunggu stabil + retry evaluate
    cfg = None
    last_err = None
    for _ in range(6):
        try:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=15000)
            except Exception:
                pass
            page.wait_for_timeout(2000)
            page.evaluate("(v) => sessionStorage.setItem('workos:code-verifier', v)", verifier)
            cfg = page.evaluate("() => fetch('/api/auth/config').then(r => r.json())")
            if isinstance(cfg, dict) and cfg.get("workos_client_id"):
                break
            cfg = None
        except Exception as e:
            last_err = e
            time.sleep(2)
            continue
    if not cfg:
        raise RuntimeError(f"gagal baca /api/auth/config: {str(last_err)[:120]} url={page.url}")
    q = urllib.parse.urlencode({
        "client_id": cfg["workos_client_id"],
        "redirect_uri": "https://console.river.ai/auth/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "provider": "authkit",
        "screen_hint": "sign-up",
    })
    return f"https://{cfg['workos_api_hostname']}/user_management/authorize?{q}"


def do_signup(page, first, last, email, password, manual_turnstile=False):
    # alur normal via SPA: console.river.ai auto-redirect ke login.console.river.ai
    # (verifier PKCE sudah diset SPA sendiri, jangan dioverride)
    for target in ["https://console.river.ai/signup", "https://console.river.ai/"]:
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            # NS_ERROR_ABORT = redirect ke login sedang jalan, anggap OK
            log(f"goto {target} note: {str(e)[:60]}")
        # tunggu redirect ke authkit s/d 25 dtk (SPA kadang redirect lambat)
        redirected = False
        for _ in range(12):
            page.wait_for_timeout(2000)
            log(f"goto {target} -> url={page.url}")
            if "login.console.river.ai" in page.url:
                redirected = True
                break
            # halaman /keys dengan tulisan redirecting = lagi mau ke login
            try:
                t = page.evaluate("() => (document.body.innerText||'').slice(0,200)")
                if "redirecting" in t.lower():
                    continue
            except Exception:
                pass
        try:
            txt0 = page.evaluate("() => (document.body.innerText||'').slice(0,500)")
            log(f"landing text: {txt0[:200]!r}")
        except Exception:
            pass
        if "login.console.river.ai" in page.url:
            break
        # coba klik link sign-up / get started di landing
        clicked = False
        for sel in ["text=/sign up/i", "text=/get started/i", "text=/create.*account/i",
                    "a[href*=sign]", "button:has-text('Sign up')"]:
            try:
                loc = page.locator(sel).first
                if loc.count() and loc.is_visible():
                    loc.click(timeout=5000)
                    clicked = True
                    log(f"klik landing: {sel}")
                    break
            except Exception:
                continue
        if clicked:
            page.wait_for_timeout(5000)
            log(f"setelah klik -> url={page.url}")
            if "login.console.river.ai" in page.url:
                break
    else:
        pass
    if "login.console.river.ai" not in page.url:
        raise RuntimeError(f"tidak sampai ke halaman authkit, url={page.url}")
    log(f"authkit url: {page.url[:100]}...")
    # tunggu security verification Cloudflare kelar + form muncul (s/d 120 dtk)
    form_ok = False
    for i in range(60):
        try:
            if page.locator("input[name=email]").count() and \
                    page.locator("input[name=email]").first.is_visible():
                form_ok = True
                break
        except Exception:
            pass
        # selesaikan turnstile kalau ada
        try:
            frames = [f for f in page.frames if "challenges.cloudflare.com" in (f.url or "")]
            if frames:
                log(f"authkit challenge masih aktif ({i*2} dtk), coba klik ...")
                solve_turnstile(page, manual=manual_turnstile, timeout=8)
        except Exception:
            pass
        page.wait_for_timeout(2000)
    log(f"form signup terlihat: {form_ok}")
    if not form_ok:
        try:
            txt0 = page.evaluate("() => (document.body.innerText||'').slice(0,500)")
            log(f"authkit text saat gagal: {txt0[:200]!r} url={page.url}")
        except Exception:
            pass
        raise RuntimeError("form signup tidak muncul (masih security verification?). coba --manual-turnstile / proxy lain")
    page.locator("input[name=first_name]").fill(first)
    page.locator("input[name=last_name]").fill(last)
    page.locator("input[name=email]").fill(email)
    page.wait_for_timeout(1500)
    log("form terisi, klik Continue ...")
    page.locator("button[type=submit]").click()
    # setelah Continue: halaman kode, halaman password, masuk console,
    # atau tahap verifikasi manusia (turnstile) -> selesaikan lalu lanjut
    pw_done = False
    for _ in range(90):
        url = page.url
        txt = ""
        try:
            txt = page.evaluate("() => (document.body.innerText||'').slice(0,1500)")
        except Exception:
            pass
        low = txt.lower()
        if any(k in low for k in ("enter the code", "verification code",
                                  "check your email", "we sent", "6-digit")):
            log("halaman kode verifikasi muncul")
            return
        if "console.river.ai" in url and "login.console.river.ai" not in url:
            log(f"sudah masuk console: {url}")
            return
        # langkah password (sign-up/password, satu halaman SPA) — deteksi via DOM dulu
        if not pw_done:
            try:
                pw_loc = page.locator("input[type=password]").first
                if pw_loc.count() and pw_loc.is_visible():
                    log(f"halaman password muncul (url={url[:60]}), isi password ...")
                    pw_loc.click(timeout=4000)
                    page.keyboard.type(password, delay=40)
                    page.wait_for_timeout(800)
                    log("password diisi, submit ...")
                    for sel in ["button[type=submit]", "text=/continue/i"]:
                        try:
                            page.locator(sel).first.click(timeout=4000)
                            break
                        except Exception:
                            continue
                    pw_done = True
            except Exception as e:
                log(f"isi password gagal: {str(e)[:80]}")
        elif "/password" in url or ("password" in low and "create" in low):
            pass
        # verifikasi manusia (cf-turnstile inline) — non-blocking: widget
        # invisible sering auto-verifikasi sendiri dalam 5-20 dtk, jadi
        # cukup klik kalau ada checkbox, gagal = tunggu iterasi berikutnya
        cf_frames = [f for f in page.frames
                     if "challenges.cloudflare.com" in (f.url or "")]
        if "human" in low or "security verification" in low or cf_frames:
            log("tahap verifikasi manusia, coba selesaikan (non-blocking) ...")
            solve_turnstile(page, manual=manual_turnstile, timeout=10)
        time.sleep(2)
    raise RuntimeError("setelah Continue tidak ada kemajuan. url=" + page.url)


def enter_code(page, code):
    page.wait_for_timeout(2000)
    # ketik via keyboard (fill programmatik tidak men-trigger input handler)
    boxes = page.locator("input[inputmode=numeric], input[type=text], input:not([type=hidden])")
    n = boxes.count()
    log(f"jumlah input kandidat kode: {n}")
    typed = False
    for i in range(n):
        try:
            el = boxes.nth(i)
            if el.is_visible():
                el.click(timeout=4000)
                page.wait_for_timeout(300)
                page.keyboard.type(code, delay=60)
                typed = True
                break
        except Exception:
            continue
    if not typed:
        # fallback: satu digit per kotak
        try:
            for i, d in enumerate(code[:6]):
                boxes.nth(i).click(timeout=3000)
                page.keyboard.type(d, delay=60)
            typed = True
        except Exception as e:
            log(f"ketik per digit gagal: {str(e)[:80]}")
    if not typed:
        raise RuntimeError("tidak ada input kode yang bisa diisi")
    page.wait_for_timeout(1500)
    # klik tombol verifikasi kalau ada
    for sel in ["button[type=submit]", "text=/verify/i", "text=/continue/i"]:
        try:
            page.locator(sel).first.click(timeout=4000)
            break
        except Exception:
            continue
    page.wait_for_url("**console.river.ai/**", timeout=60000)
    log(f"verifikasi sukses -> {page.url}")


def ensure_session(page):
    if "login.console.river.ai" in page.url:
        raise RuntimeError("belum login, masih di halaman authkit")
    log(f"sesi console aktif: {page.url}")


def _key_from_netlog(netlog):
    """Ambil secret dari JSON response POST /api/keys (field "key")."""
    import json as _json
    for e in reversed(netlog):
        if e.get("type") != "resp" or "/api/keys" not in (e.get("url") or ""):
            continue
        try:
            data = _json.loads(e.get("body") or "")
        except Exception:
            continue
        objs = data if isinstance(data, list) else [data]
        for o in objs:
            if isinstance(o, dict) and o.get("key"):
                return o["key"]
    return None


def get_api_key(page, netlog, key_name):
    page.goto(KEYS_URL, wait_until="domcontentloaded", timeout=60000)
    for _ in range(20):
        if "/keys" in page.url:
            break
        page.wait_for_timeout(1000)
    # lanjut segera setelah tombol Create tampil (maks 20 dtk, bukan sleep fix)
    try:
        page.locator("button:has-text('Create Key'), button:has-text('Create key')").first.wait_for(
            state="visible", timeout=20000)
    except Exception:
        page.wait_for_timeout(3000)
    log(f"halaman keys: {page.url}")
    # secret tidak pernah ditampilkan lagi di list -> selalu buat baru.
    # 1) klik tombol Create (header "Create Key" / empty-state "Create key")
    clicked = False
    for sel in ["button:has-text('Create Key')", "button:has-text('Create key')"]:
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                loc.click(timeout=6000)
                clicked = True
                log(f"klik: {sel}")
                break
        except Exception:
            continue
    if not clicked:
        raise RuntimeError("tombol Create key tidak ketemu di halaman /keys")
    # 2) tunggu dialog, isi nama
    try:
        page.locator("#api-key-name").wait_for(state="visible", timeout=20000)
    except Exception:
        raise RuntimeError("dialog Create API Key tidak muncul")
    try:
        page.locator("#api-key-name").fill(key_name, timeout=5000)
    except Exception:
        page.locator("#api-key-name").click(timeout=4000)
        page.keyboard.type(key_name, delay=40)
    page.wait_for_timeout(800)
    # 3) submit, tunggu secret muncul di #created-api-key
    try:
        page.locator("button[type=submit]:has-text('Create Key')").first.click(timeout=6000)
    except Exception:
        page.locator("button[type=submit]").first.click(timeout=6000)
    log("create key di-submit, menunggu secret ...")
    try:
        page.locator("#created-api-key").wait_for(state="visible", timeout=60000)
    except Exception:
        raise RuntimeError("secret key tidak muncul setelah create")
    page.wait_for_timeout(2000)
    try:
        secret = page.locator("#created-api-key").input_value(timeout=5000)
    except Exception:
        secret = ""
    if not secret:
        secret = _key_from_netlog(netlog) or ""
    if not secret or len(secret) < 12:
        raise RuntimeError("secret key kosong/tidak valid")
    log(f"api key baru terbaca ({len(secret)} char)")
    try:
        page.locator("button:has-text('Done')").first.click(timeout=4000)
    except Exception:
        pass
    return secret, "created"


# ---------- main ----------

def proxy_url_from_line(line):
    """Terima 'host:port:user:pass' atau URL http(s)://... -> URL proxy."""
    line = (line or "").strip()
    if not line:
        return None
    if line.startswith("http://") or line.startswith("https://"):
        return line
    p = line.split(":")
    if len(p) >= 4:
        host, port, user = p[0], p[1], p[2]
        pw = ":".join(p[3:])
        return f"http://{user}:{pw}@{host}:{port}"
    return None


def load_proxies(arg):
    """--proxy bisa URL tunggal atau path file (satu proxy per baris)."""
    if not arg:
        return []
    if os.path.isfile(arg):
        urls = []
        with open(arg, encoding="utf-8", errors="replace") as f:
            for line in f:
                u = proxy_url_from_line(line)
                if u:
                    urls.append(u)
        log(f"{len(urls)} proxy dimuat dari {arg}")
        return urls
    u = proxy_url_from_line(arg)
    return [u] if u else []


def build_proxy_from_url(url):
    pu = urllib.parse.urlparse(url)
    proxy = {"server": f"{pu.scheme or 'http'}://{pu.hostname}:{pu.port}"}
    if pu.username:
        proxy["username"] = urllib.parse.unquote(pu.username)
    if pu.password:
        proxy["password"] = urllib.parse.unquote(pu.password)
    return proxy


def run_once(args, proxy_url, idx, total_n):
    """Satu akun penuh. Return result dict."""
    _worker.tag = f"{idx}/{total_n}"
    netlog = []
    first = args.first or random.choice(FIRST)
    last = args.last or random.choice(LAST)
    password = args.password or DEFAULT_PASSWORD
    log(f"=== akun {idx}/{total_n}: {first} {last} ===")

    browser = launch(args)
    try:
        # zenvex: koneksi langsung (tidak butuh IP residensial, hemat kuota proxy)
        zv_ctx = browser.new_context(ignore_https_errors=True)
        zv = zv_ctx.new_page()
        attach_intercept(zv, netlog, "zenvex")
        # river.ai: lewat proxy residensial (Turnstile butuh IP non-datacenter)
        if proxy_url:
            proxy = build_proxy_from_url(proxy_url)
            log(f"river.ai pakai proxy {proxy['server']}")
            river_ctx = browser.new_context(proxy=proxy, ignore_https_errors=True)
        else:
            river_ctx = browser.new_context(ignore_https_errors=True)
        page = river_ctx.new_page()
        attach_intercept(page, netlog, "river")

        email = get_temp_address(zv, prefix=args.email_prefix)
        open_inbox(zv, manual=args.manual_turnstile)

        do_signup(page, first, last, email, password,
                  manual_turnstile=args.manual_turnstile)
        if "login.console.river.ai" in page.url:
            code = wait_for_code(zv, email)
            enter_code(page, code)
        ensure_session(page)
        api_key, status = get_api_key(page, netlog, args.key_name)

        result = {"first_name": first, "last_name": last, "email": email,
                  "password": password,
                  "api_key": api_key, "api_key_status": status,
                  "console": "https://console.river.ai"}
        print("\n===== HASIL =====")
        print(f"nama    : {first} {last}")
        print(f"email   : {email}")
        print(f"password: {password}")
        print(f"api key : {api_key} ({status})")
        # selalu simpan: result.json (array akun) + apikeys.txt (key per baris)
        with FILE_LOCK:
            total = append_unique_result(RESULT_JSON, result)
            log(f"hasil ditambah ke {RESULT_JSON} (total {total} akun)")
            if append_apikey(APIKEYS_TXT, api_key):
                log(f"apikey ditambah ke {APIKEYS_TXT}")
            else:
                log("apikey sudah tercatat, skip duplikat")
        return result
    finally:
        net_name = "network.json" if total_n == 1 else f"network_{idx}.json"
        with open(os.path.join(OUT, net_name), "w", encoding="utf-8") as f:
            json.dump(netlog, f, indent=1, ensure_ascii=False)
        log(f"{len(netlog)} network events tersimpan ({net_name})")
        if not args.keep_open:
            close_browser(browser)


def main():
    ap = argparse.ArgumentParser(description="Auto-register River AI + ambil API key (Camoufox)")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--manual-turnstile", action="store_true")
    ap.add_argument("--proxy", default=None,
                    help="URL proxy tunggal atau path file (satu proxy per baris)")
    ap.add_argument("--count", type=int, default=1,
                    help="jumlah akun yang dibuat (bulk)")
    ap.add_argument("--workers", type=int, default=1,
                    help="jumlah akun yang diproses paralel (concurrent)")
    ap.add_argument("--email-prefix", default=None)
    ap.add_argument("--key-name", default="auto")
    ap.add_argument("--first", default=None)
    ap.add_argument("--last", default=None)
    ap.add_argument("--password", default=None,
                    help="password akun baru (min 10 char); default: ReactVite.911")
    ap.add_argument("--keep-open", action="store_true")
    args = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    proxies = load_proxies(args.proxy)
    n = max(1, args.count)
    workers = max(1, min(args.workers, n))
    log(f"bulk: {n} akun x {workers} workers")

    def _job(idx):
        proxy_url = proxies[(idx - 1) % len(proxies)] if proxies else None
        return run_once(args, proxy_url, idx, n)

    ok, fail = [], []
    if workers == 1:
        for idx in range(1, n + 1):
            try:
                ok.append(_job(idx))
            except Exception as e:
                log(f"akun {idx}/{n} GAGAL: {str(e)[:150]}")
                fail.append(idx)
            if idx < n:
                time.sleep(5)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_job, idx): idx for idx in range(1, n + 1)}
            for fut in concurrent.futures.as_completed(futs):
                idx = futs[fut]
                try:
                    ok.append(fut.result())
                except Exception as e:
                    log(f"akun {idx}/{n} GAGAL: {str(e)[:150]}")
                    fail.append(idx)
    ok.sort(key=lambda r: r.get("email", ""))
    print(f"\n===== RINGKASAN: {len(ok)} sukses, {len(fail)} gagal =====")
    for r in ok:
        print(f"- {r['email']} : {r['api_key']}")
    if fail and not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
