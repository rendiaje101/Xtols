#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from colorama import init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.syntax import Syntax
import rich.box

init()
console = Console()

#  config
GTC_BASE = "https://pbssrv-centralevents.com"
VFK_BASE = "https://api.verifykit.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

APP_VERSION = "8.4.0"
ANDROID_OS = "android 9"
LANG = "en_US"
COUNTRY = "id"
DEVICE_NAME = "SM-G977N"
TIME_ZONE = "Asia/Bangkok"
BUNDLE_ID = "app.source.getcontact"
CARRIER = ("510", "Indosat Ooredoo", "01")

# Konfigurasi Sandi Login
LOGIN_PASSWORD = "RendiSec123"

# Cloud Function AI Endpoint
AI_ENDPOINT = "https://us-central1-ai-chat-bot-bf47e.cloudfunctions.net/chat_function_android"

# Diffie-Hellman params
DH_P = 900719898367
DH_G = 7

CONFIG_DIR = Path(os.environ.get("GTC_CONFIG_DIR", Path.home() / ".config" / "gtc"))
CRED_FILE = CONFIG_DIR / "credentials.json"
RESULTS_DIR = Path(os.environ.get("GTC_RESULTS_DIR", Path(__file__).resolve().parent / "results"))


class GtcError(Exception):
    pass


#  crypto
def _sig(ts: str, message: str, key_hex: str) -> str:
    mac = hmac.new(bytes.fromhex(key_hex), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypt(data: str, key_hex: str) -> str:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()


def decrypt(data: str, key_hex: str) -> str:
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).decryptor()
    out = dec.update(base64.b64decode(data)) + dec.finalize()
    return out[: -out[-1]].decode()


def dh_keypair() -> tuple[int, int]:
    priv = secrets.randbelow(10**8 - 10**6) + 10**6
    return priv, pow(DH_G, priv, DH_P)


def dh_final_key(priv: int, server_pub: int) -> str:
    return hashlib.sha256(str(pow(int(server_pub), priv, DH_P)).encode()).hexdigest()


def _ts() -> str:
    return str(int(time.time() * 1000))


def new_device_id() -> str:
    return secrets.token_hex(8)


#  http
def _post(url: str, body: str, headers: dict, timeout: int = 25) -> requests.Response:
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def gtc_call(endpoint: str, payload: dict, *, token: str, final_key: str,
             device_id: str, encrypted: bool = True) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": device_id,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1" if encrypted else "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if token:
        headers["x-token"] = token
    body = json.dumps({"data": encrypt(raw, final_key)}) if encrypted else raw
    r = _post(GTC_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if encrypted and "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], final_key))
    return r.status_code, parsed


def vfk_call(endpoint: str, payload: dict, device_id: str) -> tuple[int, dict]:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "X-VFK-Client-Device-Id": device_id,
        "X-VFK-Client-Key": VFK_CLIENT_KEY,
        "X-VFK-Sdk-Version": "0.11.4",
        "X-VFK-Os": "android 9.0",
        "X-VFK-App-Version": "8.16.0",         
        "X-VFK-Encrypted": "1",
        "X-VFK-Lang": "in_ID",
        "X-VFK-Req-Timestamp": ts,
        "X-VFK-Req-Signature": _sig(ts, raw, VFK_HMAC_KEY),
    }
    body = json.dumps({"data": encrypt(raw, VFK_FINAL_KEY)}, separators=(",", ":"))
    r = _post(VFK_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], VFK_FINAL_KEY))
    return r.status_code, parsed


def dig(obj, path, default=None):
    for k in path.split("."):
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


#  store
def load_store() -> dict:
    if not CRED_FILE.exists():
        return {"active": None, "credentials": {}}
    return json.loads(CRED_FILE.read_text("utf-8"))


def save_store(store: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(store, indent=2), "utf-8")
    try:
        os.chmod(CRED_FILE, 0o600)
    except OSError:
        pass


def get_cred(store: dict, name: str | None) -> tuple[str, dict]:
    name = name or store.get("active")
    creds = store.get("credentials", {})
    if not name or name not in creds:
        raise GtcError("Tidak ada akun aktif. Tambahkan/pilih akun terlebih dahulu melalui menu.")
    return name, creds[name]


def normalize_phone(raw: str) -> str:
    p = re.sub(r"[^\d+]", "", raw.strip())
    if p.startswith("+"):
        return p
    if p.startswith("0"):
        return "+62" + p[1:]
    if p.startswith("62"):
        return "+" + p
    raise GtcError(f"Invalid phone number: {raw}")


#  features logic
def api_search(cred: dict, phone: str, source: str) -> dict:
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": COUNTRY,
        "phoneNumber": phone,
        "source": "profile" if source == "tags" else "search",
        "token": cred["token"],
    }
    code, body = gtc_call(endpoint, payload, token=cred["token"],
                          final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    meta = dig(body, "meta.httpStatusCode")
    if code != 200 or meta != 200:
        raise GtcError(f"HTTP {code}/{meta}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def api_subscription(cred: dict) -> dict:
    code, body = gtc_call("/v2.8/subscription", {"token": cred["token"]},
                          token=cred["token"], final_key=cred["finalKey"],
                          device_id=cred["clientDeviceId"])
    if code != 200:
        raise GtcError(f"HTTP {code}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def show_captcha(b64_image: str) -> Path:
    path = Path(tempfile.gettempdir()) / f"gtc_captcha_{int(time.time())}.jpg"
    path.write_bytes(base64.b64decode(b64_image))
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass
    return path


CYBER_BANNER = """[bold bright_cyan]
 ██╗  ██╗████████╗ ██████╗ ██╗     ███████╗
╚██╗██╔╝╚══██╔══╝██╔═══██╗██║     ██╔════╝
 ╚███╔╝    ██║   ██║   ██║██║     ███████╗
 ██╔██╗    ██║   ██║   ██║██║     ╚╚╚╚╚██║
██╔╝ ██╗   ██║   ╚██████╔╝███████╗███████║
╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝╚══════╝
[/bold bright_cyan]"""

SUB_BANNER = """[bold bright_green]⚡ XTOLS OSINT & SECURITY SUITE v8.4 ⚡[/bold bright_green]
[dim italic]Author: RendiSec • Status: System Online[/dim italic]"""


def show_xtols_banner(title_text: str):
    os.system('clear' if os.name == 'posix' else 'cls')
    console.print(Panel(
        f"{CYBER_BANNER}\n[center]{SUB_BANNER}[/center]",
        border_style="bright_magenta",
        box=rich.box.DOUBLE,
        padding=(1, 2)
    ))
    console.print(Panel(f"[bold bright_yellow] 🔥 ACTIVE MODULE: {title_text} 🔥 [/bold bright_yellow]", border_style="bright_cyan", box=rich.box.ROUNDED))
    console.print()


#  Direct Menu Functions
def menu_search(source_type: str):
    title = "CARI PROFIL NOMOR (NAMA PEMILIK)" if source_type == "profile" else "CARI TAG NOMOR (NAMA TERSIMPAN)"
    show_xtols_banner(title)
    store = load_store()
    _, cred = get_cred(store, None)
    raw_phone = console.input("[bold yellow]➤ Masukkan nomor telepon: [/bold yellow]").strip()
    phone = normalize_phone(raw_phone)
    
    with console.status(f"[bold cyan]Mencari data untuk {phone}...[/bold cyan]", spinner="dots"):
        body = api_search(cred, phone, source_type)
    
    console.print("\n[bold green]--- HASIL PENCARIAN ---[/bold green]")
    profile = dig(body, "result.profile")
    if profile:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Atribut", style="cyan")
        table.add_column("Informasi", style="white")
        for k in ("displayName", "name", "surname", "phoneNumber", "displayNumber", "tagCount", "email"):
            table.add_row(k, str(profile.get(k) or '-'))
        console.print(table)
        
    tags = dig(body, "result.tags")
    if tags:
        console.print(f"\n[bold cyan]Tags ({len(tags)}):[/bold cyan]")
        tag_table = Table(show_header=True, header_style="bold yellow")
        tag_table.add_column("Tag Name", style="green")
        tag_table.add_column("Count", style="white")
        for t in tags:
            tag_table.add_row(t.get('tag', '-'), str(t.get('count', '')))
        console.print(tag_table)
        
    if not profile and not tags:
        console.print(json.dumps(body, indent=2, ensure_ascii=False))
    console.print("[bold green]-----------------------[/bold green]")


def menu_quota():
    show_xtols_banner("SISA KUOTA AKUN")
    store = load_store()
    name, cred = get_cred(store, None)
    
    with console.status("[bold cyan]Memuat informasi kuota...[/bold cyan]", spinner="dots"):
        body = api_subscription(cred)
        
    u = dig(body, "result.subscriptionInfo.usage") or {}
    
    table = Table(title=f"Kuota Akun: {name}", show_header=True, header_style="bold cyan")
    table.add_column("Fitur", style="yellow")
    table.add_column("Sisa / Limit", style="green")
    
    for key in ("search", "numberDetail"):
        d = u.get(key) or {}
        table.add_row(key, f"{d.get('remainingCount', '?')} / {d.get('limit', '?')}")
        
    console.print(table)
    renew = dig(body, 'result.subscriptionInfo.renewDate', '-')
    console.print(f"[bold dim]📅 Renew Date: {renew}[/bold dim]\n")


def menu_batch():
    show_xtols_banner("CARI BANYAK NOMOR DARI FILE CSV")
    store = load_store()
    _, cred = get_cred(store, None)
    csv_path = console.input("[bold yellow]➤ Masukkan path file CSV: [/bold yellow]").strip()
    if not os.path.exists(csv_path):
        console.print("[bold red]❌ File CSV tidak ditemukan![/bold red]")
        return
    
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        console.print("[bold red]❌ File CSV kosong![/bold red]")
        return
        
    header = rows[0]
    col = 0
    if any(h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor") for h in header):
        col = next(i for i, h in enumerate(header)
                   if h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor"))
        rows = rows[1:]
        
    console.print("\n[bold cyan]🚀 Memulai pencarian batch...[/bold cyan]\n")
    for row in rows:
        if not row or not row[col].strip():
            continue
        raw = row[col].strip()
        try:
            phone = normalize_phone(raw)
            body = api_search(cred, phone, "tags")
            prof = dig(body, "result.profile") or {}
            tags = [t.get("tag", "") for t in (dig(body, "result.tags") or [])]
            console.print(f"[green][OK][/green] {phone} ➔ [bold]{prof.get('displayName', 'Tanpa Nama')}[/bold] | Tags: {len(tags)}")
        except Exception as e:
            console.print(f"[red][FAIL][/red] {raw}: {e}")
        time.sleep(1.5)
    console.print("\n[bold green]✨ Batch selesai.[/bold green]")


def menu_captcha():
    show_xtols_banner("BUKA BLOKIR / CAPTCHA")
    store = load_store()
    _, cred = get_cred(store, None)
    common = dict(token=cred["token"], final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    code, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
    image = dig(body, "result.image")
    if not image:
        console.print(f"[yellow]⚠️ Tidak ada captcha (HTTP {code}). Akun mungkin tidak terblokir.[/yellow]")
        return
    while True:
        path = show_captcha(image)
        console.print(f"[cyan]📁 Gambar captcha disimpan di: {path}[/cyan]")
        answer = console.input("[bold yellow]➤ Masukkan kode captcha (kosong = refresh, 'q' = kembali): [/bold yellow]").strip()
        if answer.lower() == "q":
            break
        if not answer:
            _, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
            image = dig(body, "result.image") or image
            continue
        code, body = gtc_call("/v2.8/verify-code",
                              {"validationCode": answer, "token": cred["token"]}, **common)
        if code == 200 and dig(body, "meta.httpStatusCode") == 200:
            console.print("[bold green]✅ Captcha berhasil diverifikasi![/bold green]")
            break
        console.print("[bold red]❌ Kode salah, captcha baru dibuat.[/bold red]")
        image = dig(body, "result.image") or image


def menu_cred_list():
    show_xtols_banner("LIHAT/GANTI AKUN TERSIMPAN")
    store = load_store()
    creds = store.get("credentials", {})
    if not creds:
        console.print("[yellow]⚠️ Belum ada akun tersimpan.[/yellow]")
        return
        
    table = Table(title="Daftar Akun Tersimpan", show_header=True, header_style="bold magenta")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Nama Akun", style="cyan")
    table.add_column("Nomor Telepon", style="yellow")
    table.add_column("Keterangan", style="white")
    
    for name, c in creds.items():
        mark = "⭐ AKTIF" if name == store.get("active") else ""
        table.add_row(mark, name, c.get('phoneNumber', '-'), c.get('description', ''))
    console.print(table)
    
    sub_opt = console.input("\n[bold yellow]➤ Ketik nama akun untuk dijadikan aktif (kosongkan untuk batal): [/bold yellow]").strip()
    if sub_opt:
        if sub_opt in creds:
            store["active"] = sub_opt
            save_store(store)
            console.print(f"[bold green]✅ Akun aktif berhasil diubah ke: {sub_opt}[/bold green]")
        else:
            console.print("[bold red]❌ Nama akun tidak ditemukan![/bold red]")


def menu_generate():
    show_xtols_banner("TAMBAH AKUN BARU (BUTUH WHATSAPP)")
    raw_phone = console.input("[bold yellow]➤ Masukkan nomor WhatsApp untuk verifikasi (misal 08xxxxxxxx): [/bold yellow]").strip()
    phone = normalize_phone(raw_phone)
    device_id = new_device_id()
    priv, pub = dh_keypair()

    with console.status("[bold cyan]Mendaftarkan perangkat baru...[/bold cyan]", spinner="dots"):
        ts = _ts()
        reg_body = {
            "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
            "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY, "deepLink": None,
            "deviceName": DEVICE_NAME, "deviceType": "Android", "email": None,
            "notificationToken": "", "oldToken": None, "peerKey": pub,
            "timeZone": TIME_ZONE, "token": "",
        }
        raw = json.dumps(reg_body, ensure_ascii=False)
        r = _post(GTC_BASE + "/v2.8/register", raw, {
            "Content-Type": "application/json", "x-os": ANDROID_OS,
            "x-app-version": APP_VERSION, "x-client-device-id": device_id, "x-lang": LANG,
            "x-req-timestamp": ts, "x-country-code": COUNTRY, "x-encrypted": "0",
            "x-req-signature": _sig(ts, raw, HMAC_KEY),
        })
    if r.status_code != 201:
        console.print(f"[bold red]❌ Gagal register: HTTP {r.status_code}[/bold red]")
        return
    reg = r.json()
    token = dig(reg, "result.token")
    server_key = dig(reg, "result.serverKey")
    if not token or not server_key:
        console.print("[bold red]❌ Register gagal: token/serverKey tidak ada[/bold red]")
        return
    final_key = dh_final_key(priv, server_key)

    common = dict(token=token, final_key=final_key, device_id=device_id)
    base = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY,
        "deviceName": DEVICE_NAME, "notificationToken": "", "timeZone": TIME_ZONE,
        "token": token,
    }
    steps = [
        ("/v2.8/init-basic", base, 201),
        ("/v2.8/ad-settings", {"source": "init", "token": token}, 200),
        ("/v2.8/init-intro", {**base, "hasRouting": False}, 201),
        ("/v2.8/email-code-validate/start",
         {"email": f"user{random.randint(10**7, 10**8 - 1)}@gmail.com",
          "fullName": f"User{random.randint(1000, 999999)}", "token": token}, 200),
        ("/v2.8/country", {"countryCode": COUNTRY.upper(), "token": token}, 200),
        ("/v2.8/validation-start",
         {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}, 200),
    ]
    with console.status("[bold cyan]Menginisialisasi profil akun...[/bold cyan]", spinner="dots"):
        for endpoint, payload, want in steps:
            code, body = gtc_call(endpoint, payload, **common)
            if code != want:
                console.print(f"[bold red]❌ Inisialisasi gagal di {endpoint} (HTTP {code})[/bold red]")
                return

        vfk_call("/v2.0/init", {
            "isCallPermissionGranted": True, "countryCode": "ID", "deviceName": DEVICE_NAME,
            "installedApps": '{"whatsapp":0,"telegram":0,"viber":0}',
            "outsideCountryCode": "ID", "outsidePhoneNumber": raw_phone,
            "timezone": TIME_ZONE, "bundleId": BUNDLE_ID,
        }, device_id)

        vfk_call("/v2.0/country", {"countryCode": "ID", "bundleId": BUNDLE_ID}, device_id)

        code, body = vfk_call("/v2.0/start", {
            "countryCode": "ID", "mcc": CARRIER[0], "mnc": CARRIER[2],
            "phoneNumber": phone, "app": "whatsapp", "bundleId": BUNDLE_ID,
        }, device_id)
    
    deeplink = dig(body, "result.deeplink")
    reference = dig(body, "result.reference")
    if not deeplink or not reference:
        console.print("[bold red]❌ Gagal mendapatkan link verifikasi WhatsApp.[/bold red]")
        return

    gtc_call("/v2.8/validation-start",
             {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token},
             **common)

    console.print(Panel(f"[bold yellow]Kirim pesan verifikasi WhatsApp melalui link berikut:[/bold yellow]\n[cyan]{deeplink}[/cyan]", title="Verifikasi WhatsApp"))
    console.input("[bold green]➤ Tekan Enter jika pesan WhatsApp sudah terkirim dan bercentang... [/bold green]")

    with console.status("[bold cyan]Memeriksa hasil verifikasi...[/bold cyan]", spinner="dots"):
        code, body = vfk_call("/v2.0/check", {"reference": reference, "bundleId": BUNDLE_ID}, device_id)
        session_id = dig(body, "result.sessionId")
        if not session_id:
            console.print("[bold red]❌ Verifikasi belum selesai / gagal.[/bold red]")
            return

        code, body = gtc_call("/v2.8/verifykit-result", {"sessionId": session_id, "token": token}, **common)
        validation_date = dig(body, "result.validationDate")
        if not validation_date:
            console.print("[bold red]❌ Gagal mengambil hasil verifykit.[/bold red]")
            return

    store = load_store()
    name = phone
    store.setdefault("credentials", {})[name] = {
        "description": f"Generated {validation_date}",
        "phoneNumber": phone,
        "clientDeviceId": device_id,
        "finalKey": final_key,
        "token": token,
        "validationDate": validation_date,
    }
    store["active"] = name
    save_store(store)
    console.print(f"[bold green]✨ Berhasil! Akun tersimpan dengan nama '{name}'.[/bold green]")


def menu_track_ip():
    show_xtols_banner("TRACK IP / DOMAIN")
    target = console.input("[bold yellow]➤ Masukkan IP Address atau Domain target: [/bold yellow]").strip()
    if not target:
        console.print("[bold red]❌ Target tidak boleh kosong![/bold red]")
        return
        
    url = f"http://ip-api.com/json/{target}"
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    
    with console.status(f"[bold cyan]Melacak informasi untuk {target}...[/bold cyan]", spinner="dots"):
        try:
            response = requests.get(url, params={"fields": fields}, timeout=15)
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            console.print(f"[bold red]❌ Koneksi gagal: {e}[/bold red]")
            return
            
    if result.get("status") == "success":
        table = Table(title=f"Hasil Pelacakan: {result.get('query')}", show_header=True, header_style="bold green")
        table.add_column("Parameter", style="cyan")
        table.add_column("Detail", style="white")
        
        table.add_row("Negara", f"{result.get('country')} ({result.get('countryCode')})")
        table.add_row("Wilayah", f"{result.get('regionName')} ({result.get('region')})")
        table.add_row("Kota", str(result.get('city')))
        table.add_row("Kode Pos", str(result.get('zip')))
        table.add_row("Koordinat", f"Lat {result.get('lat')}, Lon {result.get('lon')}")
        table.add_row("Zona Waktu", str(result.get('timezone')))
        table.add_row("ISP", str(result.get('isp')))
        table.add_row("Organisasi", str(result.get('org')))
        console.print(table)
    else:
        console.print(f"[bold red][-] Gagal melacak IP tersebut: {result.get('message', 'Tidak diketahui')}[/bold red]")


def menu_track_phone_number():
    show_xtols_banner("TRACK NOMOR TELEPON (OPERATOR & WILAYAH)")
    number = console.input("[bold yellow]➤ Masukkan nomor telepon Indonesia: [/bold yellow]").strip()
    if not number:
        console.print("[bold red]⚠️ Mohon sertakan nomor telepon.[/bold red]")
        return

    cleaned = re.sub(r'[^0-9]', '', str(number))
    if cleaned.startswith('0'):
        cleaned = '62' + cleaned[1:]

    prefix = cleaned[:5]
    provider_map = {
        "62811": {"provider": "Telkomsel (Kartu Halo)", "region": "Nasional"},
        "62812": {"provider": "Telkomsel (simPATI)", "region": "Jabodetabek"},
        "62813": {"provider": "Telkomsel (simPATI)", "region": "Jawa Timur"},
        "62821": {"provider": "Telkomsel (Kartu AS)", "region": "Jawa Tengah"},
        "62822": {"provider": "Telkomsel (Kartu AS)", "region": "Bali & Nusa Tenggara"},
        "62823": {"provider": "Telkomsel (Loop)", "region": "Sumatera"},
        "62814": {"provider": "Indosat (IM3)", "region": "Jabodetabek"},
        "62815": {"provider": "Indosat (Mentari)", "region": "Jawa Barat"},
        "62816": {"provider": "Indosat (Matrix)", "region": "Nasional"},
        "62855": {"provider": "Indosat (IM3 Ooredoo)", "region": "Jawa Tengah"},
        "62856": {"provider": "Indosat (IM3 Ooredoo)", "region": "Jawa Timur"},
        "62857": {"provider": "Indosat (IM3 Ooredoo)", "region": "Kalimantan"},
        "62858": {"provider": "Indosat (IM3 Ooredoo)", "region": "Sulawesi"},
        "62817": {"provider": "XL Axiata", "region": "Jabodetabek"},
        "62818": {"provider": "XL Axiata", "region": "Jawa Tengah & Timur"},
        "62819": {"provider": "XL Axiata", "region": "Sumatera & Kalimantan"},
        "62859": {"provider": "XL Prabayar", "region": "Nasional"},
        "62877": {"provider": "XL Prabayar", "region": "Jawa Barat"},
        "62878": {"provider": "XL Prabayar", "region": "Bali, NTB, NTT"},
        "62895": {"provider": "Tri (3)", "region": "Jakarta"},
        "62896": {"provider": "Tri (3)", "region": "Jawa Tengah"},
        "62897": {"provider": "Tri (3)", "region": "Jawa Timur"},
        "62898": {"provider": "Tri (3)", "region": "Sumatera"},
        "62899": {"provider": "Tri (3)", "region": "Sulawesi"},
        "62881": {"provider": "Smartfren", "region": "Jabodetabek"},
        "62882": {"provider": "Smartfren", "region": "Jawa Barat"},
        "62883": {"provider": "Smartfren", "region": "Jawa Tengah"},
        "62884": {"provider": "Smartfren", "region": "Nasional"},
        "62831": {"provider": "Axis", "region": "Jabodetabek"},
        "62832": {"provider": "Axis", "region": "Jawa Tengah"},
        "62833": {"provider": "Axis", "region": "Jawa Timur"},
        "62838": {"provider": "Axis", "region": "Sumatera"},
        "62851": {"provider": "By.U (Telkomsel Digital)", "region": "Online / Nasional"}
    }

    info = provider_map.get(prefix, {"provider": "Tidak diketahui / prefix tidak umum", "region": "Tidak tersedia"})
    tipe = 'Pascabayar' if re.search(r'(halo|matrix)', info["provider"], re.IGNORECASE) else 'Prabayar'
    
    table = Table(title=f"Analisa Nomor: +{cleaned}", show_header=True, header_style="bold yellow")
    table.add_column("Atribut", style="cyan")
    table.add_column("Hasil", style="white")
    
    table.add_row("Operator", info["provider"])
    table.add_row("Prefix", prefix)
    table.add_row("Tipe Layanan", tipe)
    table.add_row("Wilayah", info["region"])
    table.add_row("Negara", "Indonesia")
    console.print(table)


def menu_track_social():
    show_xtols_banner("TRACK SOCIAL MEDIA (150+ PLATFORM)")
    username = console.input("[bold yellow]➤ Masukkan username target: [/bold yellow]").strip()
    if not username:
        console.print("[bold red]⚠️ Username tidak boleh kosong.[/bold red]")
        return

    platforms = {
        "Instagram": "https://www.instagram.com/{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Twitter / X": "https://twitter.com/{}",
        "GitHub": "https://github.com/{}",
        "Facebook": "https://www.facebook.com/{}",
        "YouTube": "https://www.youtube.com/@{}",
        "Pinterest": "https://www.pinterest.com/{}",
        "LinkedIn": "https://www.linkedin.com/in/{}",
        "Telegram": "https://t.me/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Spotify": "https://open.spotify.com/user/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "SoundCloud": "https://soundcloud.com/{}",
        "Medium": "https://medium.com/@{}",
        "Behance": "https://www.behance.net/{}",
        "Dribbble": "https://dribbble.com/{}",
        "Flickr": "https://www.flickr.com/people/{}",
        "Vimeo": "https://vimeo.com/{}",
        "VK": "https://vk.com/{}",
        "Codepen": "https://codepen.io/{}",
        "Dev.to": "https://dev.to/{}",
        "Ebay": "https://www.ebay.com/usr/{}",
        "Fiverr": "https://www.fiverr.com/{}",
        "Goodreads": "https://www.goodreads.com/{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
        "Kaggle": "https://www.kaggle.com/{}",
        "Last.fm": "https://www.last.fm/user/{}",
        "MyAnimeList": "https://myanimelist.net/profile/{}",
        "Patreon": "https://www.patreon.com/{}",
        "PayPal": "https://www.paypal.com/paypalme/{}",
        "Quora": "https://www.quora.com/profile/{}",
        "Substack": "https://{}.substack.com",
        "Tumblr": "https://{}.tumblr.com",
        "Wattpad": "https://www.wattpad.com/user/{}",
        "Bandcamp": "https://bandcamp.com/{}",
        "BuyMeACoffee": "https://buymeacoffee.com/{}",
        "Chess.com": "https://www.chess.com/member/{}",
        "DailyMotion": "https://www.dailymotion.com/{}",
        "DeviantArt": "https://www.deviantart.com/{}",
        "Duolingo": "https://www.duolingo.com/profile/{}",
        "Figma": "https://www.figma.com/@{}",
        "Genius": "https://genius.com/{}",
        "Giphy": "https://giphy.com/{}",
        "Gumroad": "https://gumroad.com/{}",
        "HuggingFace": "https://huggingface.co/{}",
        "Imgur": "https://imgur.com/user/{}",
        "Ko-fi": "https://ko-fi.com/{}",
        "Letterboxd": "https://letterboxd.com/{}",
        "Mastodon": "https://mastodon.social/@{}",
        "Mixcloud": "https://www.mixcloud.com/{}",
        "Myspace": "https://myspace.com/{}",
        "Npm": "https://www.npmjs.com/~{}",
        "OpenSea": "https://opensea.io/{}",
        "Pypi": "https://pypi.org/user/{}",
        "Rumble": "https://rumble.com/user/{}",
        "Scratch": "https://scratch.mit.edu/users/{}",
        "Strava": "https://www.strava.com/athletes/{}",
        "Trello": "https://trello.com/{}",
        "TryHackMe": "https://tryhackme.com/p/{}",
        "Unsplash": "https://unsplash.com/@{}",
        "Venmo": "https://venmo.com/{}",
        "Zenn": "https://zenn.dev/{}"
    }

    console.print(f"\n[bold cyan]🔍 Memeriksa ketersediaan username '{username}' secara paralel...[/bold cyan]\n")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    found_results = []

    def check_platform(name, url_template):
        url = url_template.format(username)
        try:
            res = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            if res.status_code == 200:
                return (name, url, True)
        except Exception:
            pass
        return (name, url, False)

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_platform, name, url): name for name, url in platforms.items()}
        for future in as_completed(futures):
            name, url, is_found = future.result()
            if is_found:
                console.print(f"[green][+] Ditemukan ({name}):[/green] [link={url}]{url}[/link]")
                found_results.append((name, url))

    console.print(f"\n[bold green]✨ Selesai! Ditemukan di {len(found_results)} dari {len(platforms)} platform.[/bold green]")


def menu_cctv_hack():
    os.system('clear' if os.name == 'posix' else 'cls')
    
    cctv_banner = """[bold red]
   ██████╗██████╗ ████████╗██╗   ██╗
  ██╔════╝██╔══██╗╚══██╔══╝██║   ██║
  ██║     ██║  ██║   ██║   ██║   ██║
  ██║     ██║  ██║   ██║   ╚██╗ ██╔╝
  ╚██████╗██████╔╝   ██║    ╚████╔╝ 
   ╚═════╝╚═════╝    ╚═╝     ╚═══╝   
     HACK SCANNER (INSECAM)[/bold red]
[bold yellow]⚠️ WARNING : I AM NOT RESPONSIBLE FOR THE MISUSE ![/bold yellow]"""
    
    console.print(Panel(cctv_banner, title="[bold red]CCTV SECURITY[/bold red]", subtitle="[bold cyan]Author : RendiSec[/bold cyan]"))
    
    countries_list = [
        ("[01]", "United States", "[31]", "Mexico", "[61]", "Moldova"),
        ("[02]", "Japan", "[32]", "Finland", "[62]", "Nicaragua"),
        ("[03]", "Italy", "[33]", "China", "[63]", "Malta"),
        ("[04]", "Korea", "[34]", "Chile", "[64]", "Trinidad & Tobago"),
        ("[05]", "France", "[35]", "South Africa", "[65]", "Saudi Arabia"),
        ("[06]", "Germany", "[36]", "Slovakia", "[66]", "Croatia"),
        ("[07]", "Taiwan", "[37]", "Hungary", "[67]", "Cyprus"),
        ("[08]", "Russia", "[38]", "Ireland", "[68]", "Pakistan"),
        ("[09]", "United Kingdom", "[39]", "Egypt", "[69]", "UAE"),
        ("[10]", "Netherlands", "[40]", "Thailand", "[70]", "Kazakhstan"),
        ("[11]", "Czech Republic", "[41]", "Ukraine", "[71]", "Kuwait"),
        ("[12]", "Turkey", "[42]", "Serbia", "[72]", "Venezuela"),
        ("[13]", "Austria", "[43]", "Hong Kong", "[73]", "Georgia"),
        ("[14]", "Switzerland", "[44]", "Greece", "[74]", "Montenegro"),
        ("[15]", "Spain", "[45]", "Portugal", "[75]", "El Salvador"),
        ("[16]", "Canada", "[46]", "Latvia", "[76]", "Luxembourg"),
        ("[17]", "Sweden", "[47]", "Singapore", "[77]", "Curacao"),
        ("[18]", "Israel", "[48]", "Iceland", "[78]", "Puerto Rico"),
        ("[19]", "Iran", "[49]", "Malaysia", "[79]", "Costa Rica"),
        ("[20]", "Poland", "[50]", "Colombia", "[80]", "Belarus"),
        ("[21]", "India", "[51]", "Tunisia", "[81]", "Albania"),
        ("[22]", "Norway", "[52]", "Estonia", "[82]", "Liechtenstein"),
        ("[23]", "Romania", "[53]", "Dominican Rep", "[83]", "Bosnia"),
        ("[24]", "Viet Nam", "[54]", "Slovenia", "[84]", "Paraguay"),
        ("[25]", "Belgium", "[55]", "Ecuador", "[85]", "Philippines"),
        ("[26]", "Brazil", "[56]", "Lithuania", "[86]", "Faroe Islands"),
        ("[27]", "Bulgaria", "[57]", "Palestinian", "[87]", "Guatemala"),
        ("[28]", "Indonesia", "[58]", "New Zealand", "[88]", "Nepal"),
        ("[29]", "Denmark", "[59]", "Bangladesh", "[89]", "Peru"),
        ("[30]", "Argentina", "[60]", "Panama", "[90]", "Uruguay"),
        ("[91]", "Extra", "[92]", "Andorra", "[93]", "Antigua"),
        ("[94]", "Armenia", "[95]", "Angola", "[96]", "Australia"),
        ("[97]", "Aruba", "[98]", "Azerbaijan", "[99]", "Barbados"),
        ("[100]", "Bonaire", "[101]", "Bahamas", "[102]", "Botswana"),
        ("[103]", "Congo", "[104]", "Ivory Coast", "[105]", "Algeria"),
        ("[106]", "Fiji", "[107]", "Gabon", "[108]", "Guernsey"),
        ("[109]", "Greenland", "[110]", "Guadeloupe", "[111]", "Guam"),
        ("[112]", "Guyana", "[113]", "Honduras", "[114]", "Jersey"),
        ("[115]", "Jamaica", "[116]", "Jordan", "[117]", "Kenya"),
        ("[118]", "Cambodia", "[119]", "Saint Kitts", "[120]", "Cayman Islands"),
        ("[121]", "Laos", "[122]", "Lebanon", "[123]", "Sri Lanka"),
        ("[124]", "Morocco", "[125]", "Madagascar", "[126]", "Macedonia"),
        ("[127]", "Mongolia", "[128]", "Macao", "[129]", "Martinique"),
        ("[130]", "Mauritius", "[131]", "Namibia", "[132]", "New Caledonia"),
        ("[133]", "Nigeria", "[134]", "Qatar", "[135]", "Reunion"),
        ("[136]", "Sudan", "[137]", "Senegal", "[138]", "Suriname"),
        ("[139]", "Sao Tome", "[140]", "Syria", "[141]", "Tanzania"),
        ("[142]", "Uganda", "[143]", "Uzbekistan", "[144]", "St. Vincent"),
        ("[145]", "Benin", "", "", "", "")
    ]

    table = Table(show_header=False, box=rich.box.ROUNDED, border_style="cyan", padding=(0, 1))
    table.add_column("No1", style="bold yellow", width=5)
    table.add_column("C1", style="white", width=14)
    table.add_column("No2", style="bold yellow", width=5)
    table.add_column("C2", style="white", width=14)
    table.add_column("No3", style="bold yellow", width=5)
    table.add_column("C3", style="white", width=14)

    for row in countries_list:
        table.add_row(row[0], row[1], row[2], row[3], row[4], row[5])

    console.print(Panel(table, title="[bold bright_cyan]🌍 PILIH NOMOR NEGARA CCTV[/bold bright_cyan]", border_style="magenta"))

    try:
        countries_code_map = [
            "US", "JP", "IT", "KR", "FR", "DE", "TW", "RU", "GB", "NL",
            "CZ", "TR", "AT", "CH", "ES", "CA", "SE", "IL", "PL", "IR",
            "NO", "RO", "IN", "VN", "BE", "BR", "BG", "ID", "DK", "AR",
            "MX", "FI", "CN", "CL", "ZA", "SK", "HU", "IE", "EG", "TH",
            "UA", "RS", "HK", "GR", "PT", "LV", "SG", "IS", "MY", "CO",
            "TN", "EE", "DO", "SI", "EC", "LT", "PS", "NZ", "BD", "PA",
            "MD", "NI", "MT", "TT", "SA", "HR", "CY", "PK", "AE", "KZ",
            "KW", "VE", "GE", "ME", "SV", "LU", "CW", "PR", "CR", "BY",
            "AL", "LI", "BA", "PY", "PH", "FO", "GT", "NP", "PE", "UY",
            "-" , "AD", "AG", "AM", "AO", "AU", "AW", "AZ", "BB",
            "BQ", "BS", "BW", "CG", "CI", "DZ", "FJ", "GA", "GG", "GL",
            "GP", "GU", "GY", "HN", "JE", "JM", "JO", "KE", "KH", "KN",
            "KY", "LA", "LB", "LK", "MA", "MG", "MK", "MN", "MO", "MQ",
            "MU", "NA", "NC", "NG", "QA", "RE", "SD", "SN", "SR", "ST",
            "SY", "TZ", "UG", "UZ", "VC", "BJ"
        ]

        num_input = console.input("\n[bold yellow]➤ Masukkan Nomor Negara (contoh: 28 untuk Indonesia): [/bold yellow]").strip()
        if not num_input.isdigit():
            console.print("[bold red]❌ Input harus berupa angka.[/bold red]")
            return

        num = int(num_input)
        if num not in range(1, len(countries_code_map) + 1):
            console.print("[bold red]❌ Pilihan nomor negara tidak valid.[/bold red]")
            return

        country = countries_code_map[num - 1]
        if country == "-":
            console.print("[bold red]❌ Negara ini tidak memiliki data stream publik.[/bold red]")
            return

        console.print(f"\n[bold cyan][+] Mencari stream aktif di negara: {country}...[/bold cyan]\n")

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0"}
        res = requests.get(f"http://www.insecam.org/en/bycountry/{country}", headers=headers, timeout=10)
        match_pages = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)
        if not match_pages:
            console.print("[bold red]❌ Tidak ada halaman stream ditemukan untuk kode negara ini.[/bold red]")
            return
            
        last_page = int(match_pages[0])
        console.print(f"[bold green][+] Total halaman ditemukan: {last_page}[/bold green]")
        
        filename = f"cctv_links_{country}.txt"
        found_count = 0

        with open(filename, "w") as f, console.status("[bold green]Memindai stream kamera aktif...", spinner="dots"):
            for page in range(1, min(last_page + 1, 3)):
                page_res = requests.get(f"http://www.insecam.org/en/bycountry/{country}/?page={page}", headers=headers, timeout=10)
                find_ip = re.findall(r"http://\d+.\d+.\d+.\d+:\d+", page_res.text)
                
                for ip in set(find_ip):
                    try:
                        check = requests.get(ip, headers=headers, timeout=2)
                        if check.status_code == 200:
                            console.print(f"[bold green][LIVE][/bold green] {ip}")
                            f.write(ip + "\n")
                            found_count += 1
                    except:
                        continue

        console.print(f"\n[bold green]✨ Selesai! Berhasil menyimpan {found_count} tautan aktif ke file {filename}[/bold green]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Error: {e}[/bold red]")


def menu_ai_chat():
    show_xtols_banner("TANYA CLOUD AI (GEMINI/GPT)")
    prompt = console.input("[bold yellow]➤ Masukkan pertanyaan untuk Cloud AI (ketik 'keluar' untuk kembali): [/bold yellow]").strip()
    if not prompt or prompt.lower() in ("keluar", "q"):
        return

    payload = {
        "data": {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "timeZone": TIME_ZONE,
            "countryCode": COUNTRY
        }
    }

    with console.status("[bold cyan]Menghubungkan ke Cloud AI...[/bold cyan]", spinner="dots"):
        try:
            response = requests.post(AI_ENDPOINT, json=payload, headers={"Content-Type": "application/json"}, timeout=30)
            response.raise_for_status()
            res_json = response.json()
            
            answer = None
            choice = dig(res_json, "result.choices.0")
            if choice:
                answer = dig(choice, "message.content") or dig(choice, "text")
            if not answer:
                answer = dig(res_json, "result.text") or dig(res_json, "text") or dig(res_json, "response")

            if answer:
                console.print(Panel(Markdown(str(answer).strip()), title="🤖 [Jawaban Cloud AI]", border_style="green"))
            else:
                console.print(json.dumps(res_json, indent=2, ensure_ascii=False))
        except Exception as e:
            console.print(f"[bold red]❌ Error terhubung ke Cloud AI: {e}[/bold red]")


MENU = [
    ("Cari profil nomor        (nama pemilik)", "profile"),
    ("Cari tag nomor           (nama tersimpan orang lain)", "tags"),
    ("Sisa kuota akun", "quota"),
    ("Cari banyak nomor dari file CSV", "batch"),
    ("Buka blokir / captcha", "captcha"),
    ("Lihat/ganti akun tersimpan", "credlist"),
    ("Tambah akun baru (butuh WhatsApp)", "generate"),
    ("Credits Pembuat Tools", "credits"),
    ("Track IP / Domain", "trackip"),
    ("Track Nomor Telepon (Operator & Wilayah)", "trackphone"),
    ("Track Social Media (150+ Platform)", "tracksocial"),
    ("CCTV Hack Scanner (Insecam)", "cctvhack"),
    ("Tanya Cloud AI (Gemini/GPT)", "cloud_ai"),
]


def ask(prompt: str) -> str:
    try:
        return console.input(prompt).strip()
    except EOFError:
        return "0"


def check_login() -> bool:
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(Panel(
            f"{CYBER_BANNER}\n[center]{SUB_BANNER}[/center]",
            border_style="bright_magenta",
            box=rich.box.DOUBLE,
            padding=(1, 2)
        ))
        
        password = console.input("[bold yellow]🔐 Masukkan sandi login: [/bold yellow]").strip()
        if password == LOGIN_PASSWORD:
            console.print("\n[bold green]✅ Login Berhasil! Selamat datang, RendiSec.[/bold green]\n")
            time.sleep(1)
            return True
        else:
            remaining = max_attempts - attempt
            console.print(f"\n[bold red]❌ Sandi salah! Sisa percobaan: {remaining}[/bold red]")
            if remaining > 0:
                time.sleep(1.5)
            else:
                console.print("[bold red]❌ Batas percobaan habis. Akses ditolak.[/bold red]")
                return False
    return False


def interactive() -> int:
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(Panel(
            f"{CYBER_BANNER}\n[center]{SUB_BANNER}[/center]",
            border_style="bright_magenta",
            box=rich.box.DOUBLE,
            padding=(1, 2)
        ))
        
        store = load_store() if CRED_FILE.exists() else {}
        active = store.get("active") or "Belum ada"
        console.print(f"[bold cyan]👤 Status Akun Aktif:[/bold cyan] [bold yellow]{active}[/bold yellow]\n")
        
        menu_lines = []
        for i, (label, _) in enumerate(MENU, 1):
            menu_lines.append(f"  [bright_cyan]{i:02d}.[/bright_cyan] [white]{label}[/white]")
        menu_lines.append("  [bright_red]00.[/bright_red] [bold red]Keluar[/bold red]")
        
        console.print(Panel(
            "\n".join(menu_lines),
            title="[bold bright_magenta]📋 XTOLS MAIN MENU[/bold bright_magenta]",
            border_style="bright_yellow",
            box=rich.box.ROUNDED,
            padding=(1, 2)
        ))
        console.print()
        
        choice = ask("[bold yellow]➤ Nomor pilihan: [/bold yellow]")
        if choice in ("0", "00", "q", "keluar", ""):
            console.print("[bold cyan]Keluar dari program. Terima kasih![/bold cyan]")
            return 0
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU)):
                console.print("[bold red]Pilihan tidak valid.[/bold red]\n")
                time.sleep(1)
                continue
        except ValueError:
            console.print("[bold red]Masukkan angka yang benar.[/bold red]\n")
            time.sleep(1)
            continue

        action = MENU[idx][1]
        try:
            if action == "cctvhack":
                menu_cctv_hack()
            elif action == "credits":
                show_xtols_banner("CREDITS PEMBUAT TOOLS")
                console.print(Panel("• [cyan]RendiSec[/cyan]\n• [cyan]VynnGrup[/cyan]\n• [cyan]PutraWibu[/cyan]\n• [cyan]GeminiAi[/cyan]\n• [cyan]XynnHd[/cyan]\n• [cyan]Xynaa[/cyan]", border_style="magenta"))
            elif action == "profile":
                menu_search("profile")
            elif action == "tags":
                menu_search("tags")
            elif action == "quota":
                menu_quota()
            elif action == "batch":
                menu_batch()
            elif action == "captcha":
                menu_captcha()
            elif action == "credlist":
                menu_cred_list()
            elif action == "generate":
                menu_generate()
            elif action == "trackip":
                menu_track_ip()
            elif action == "trackphone":
                menu_track_phone_number()
            elif action == "tracksocial":
                menu_track_social()
            elif action == "cloud_ai":
                menu_ai_chat()
                
            console.input("\n[bold green]Tekan Enter untuk kembali ke menu... [/bold green]")
        except GtcError as e:
            console.print(f"\n[bold red][Error] {e}[/bold red]")
            console.input("\n[bold yellow]Tekan Enter untuk kembali ke menu... [/bold yellow]")
        except Exception as e:
            console.print(f"\n[bold red][Unexpected Error] {e}[/bold red]")
            console.input("\n[bold yellow]Tekan Enter untuk kembali ke menu... [/bold yellow]")


def main() -> int:
    if not check_login():
        return 1
    return interactive()


if __name__ == "__main__":
    sys.exit(main())
