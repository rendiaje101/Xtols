import { Telegraf, Markup } from "telegraf";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ================= KONFIGURASI =================
const BOT_TOKEN = process.env.BOT_TOKEN || "8609165845:AAGSOPjnAmHhMrOH7OVVdvB8Fr-r1Yk7BEU";
const LOGIN_PASSWORD = process.env.BOT_PASSWORD || "RendiSec123";
const MENU_VIDEO_PATH = process.env.MENU_VIDEO_PATH || path.join(__dirname, "menu.mp4");

const GTC_BASE = "https://pbssrv-centralevents.com";
const VFK_BASE = "https://api.verifykit.com";
const WEB_SOURCE_API = "https://www.apiii-putzyy.my.id/api/tools/source";
const WEB_SOURCE_DEFAULT_KEY = "Putzyy";
const AI_ENDPOINT = "https://us-central1-ai-chat-bot-bf47e.cloudfunctions.net/chat_function_android";

const HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762";
const VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932";
const VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d";
const VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa";

const APP_VERSION = "8.4.0";
const ANDROID_OS = "android 9";
const LANG = "en_US";
const COUNTRY = "id";
const DEVICE_NAME = "SM-G977N";
const TIME_ZONE = "Asia/Bangkok";
const BUNDLE_ID = "app.source.getcontact";
const CARRIER = ["510", "Indosat Ooredoo", "01"];

const DH_P = 900719898367n;
const DH_G = 7n;

const CONFIG_DIR = process.env.GTC_CONFIG_DIR || path.join(process.env.HOME || __dirname, ".config", "gtc");
const CRED_FILE = path.join(CONFIG_DIR, "credentials.json");

const userSessions = new Map();
const authedChats = new Set();

// ================= LOGGER TERMUX =================
function formatTimeWib() {
  return new Date().toLocaleTimeString("id-ID", {
    timeZone: "Asia/Jakarta",
    hour12: false,
  });
}

function formatUserTag(from) {
  if (!from) return "UnknownUser (0)";
  const name = [from.first_name, from.last_name].filter(Boolean).join(" ").trim() || "TanpaNama";
  const handle = from.username ? `@${from.username}` : "no-username";
  return `${name} [${handle}] (ID: ${from.id})`;
}

function logActivity(ctx, detail = "") {
  const time = formatTimeWib();
  const who = formatUserTag(ctx?.from);
  const chatType = ctx?.chat?.type || "private";
  const suffix = detail ? ` -> ${detail}` : "";
  console.log(`[${time} WIB] [${chatType}] ${who}${suffix}`);
}

// ================= KRIPTOGRAFI & UTILITAS =================
function sig(ts, message, keyHex) {
  const mac = crypto.createHmac("sha256", Buffer.from(keyHex, "hex"));
  mac.update(`${ts}-${message}`);
  return mac.digest("base64");
}

function pkcs7Pad(buf) {
  const blockSize = 16;
  const padLen = blockSize - (buf.length % blockSize);
  return Buffer.concat([buf, Buffer.alloc(padLen, padLen)]);
}

function pkcs7Unpad(buf) {
  if (!buf.length) return buf;
  const padLen = buf[buf.length - 1];
  if (padLen < 1 || padLen > 16) return buf;
  return buf.subarray(0, buf.length - padLen);
}

function resolveAesKey(keyInput) {
  if (Buffer.isBuffer(keyInput)) {
    if ([16, 24, 32].includes(keyInput.length)) return keyInput;
    throw new Error(`Invalid key length: ${keyInput.length}`);
  }
  const str = String(keyInput || "").trim();
  if (/^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0) {
    const hexBuf = Buffer.from(str, "hex");
    if ([16, 24, 32].includes(hexBuf.length)) return hexBuf;
  }
  const utfBuf = Buffer.from(str, "utf8");
  if ([16, 24, 32].includes(utfBuf.length)) return utfBuf;

  const b64Buf = Buffer.from(str, "base64");
  if ([16, 24, 32].includes(b64Buf.length)) return b64Buf;

  throw new Error(`Invalid key length (got ${utfBuf.length} utf8 bytes / ${str.length} hex chars)`);
}

function getAesAlgorithm(keyBuf) {
  if (keyBuf.length === 16) return "aes-128-ecb";
  if (keyBuf.length === 24) return "aes-192-ecb";
  if (keyBuf.length === 32) return "aes-256-ecb";
  throw new Error(`Invalid key length: ${keyBuf.length}`);
}

function encryptAesEcb(plainText, keyHex) {
  const keyBuf = resolveAesKey(keyHex);
  const algo = getAesAlgorithm(keyBuf);
  const cipher = crypto.createCipheriv(algo, keyBuf, null);
  cipher.setAutoPadding(false);
  const padded = pkcs7Pad(Buffer.from(plainText, "utf8"));
  const enc = Buffer.concat([cipher.update(padded), cipher.final()]);
  return enc.toString("base64");
}

function decryptAesEcb(base64Cipher, keyHex) {
  const keyBuf = resolveAesKey(keyHex);
  const algo = getAesAlgorithm(keyBuf);
  const decipher = crypto.createDecipheriv(algo, keyBuf, null);
  decipher.setAutoPadding(false);
  const dec = Buffer.concat([decipher.update(Buffer.from(base64Cipher, "base64")), decipher.final()]);
  return pkcs7Unpad(dec).toString("utf8");
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function dhKeypair() {
  const min = 1000000n;
  const max = 100000000n;
  const randNum = BigInt(crypto.randomInt(0, Number(max - min)));
  const priv = min + randNum;
  const pub = modPow(DH_G, priv, DH_P);
  return { priv, pub: pub.toString() };
}

function dhFinalKey(priv, serverPub) {
  const shared = modPow(BigInt(serverPub), priv, DH_P);
  return crypto.createHash("sha256").update(shared.toString()).digest("hex");
}

function nowMs() {
  return String(Date.now());
}

function newDeviceId() {
  return crypto.randomBytes(8).toString("hex");
}

function dig(obj, dotPath, fallback = undefined) {
  return dotPath.split(".").reduce((acc, key) => {
    if (acc && typeof acc === "object" && key in acc) return acc[key];
    return undefined;
  }, obj) ?? fallback;
}

function escapeMd(val) {
  return String(val ?? "").replace(/([_*`\[\\])/g, "\\$1");
}

function normalizePhone(raw) {
  const cleaned = String(raw || "").replace(/[^\d+]/g, "").trim();
  if (cleaned.startsWith("+")) return cleaned;
  if (cleaned.startsWith("0")) return "+62" + cleaned.slice(1);
  if (cleaned.startsWith("62")) return "+" + cleaned;
  throw new Error(`Format nomor tidak valid: ${raw}`);
}

function normalizeWebUrl(rawUrl) {
  const cleaned = String(rawUrl || "").trim();
  if (!cleaned) throw new Error("URL target tidak boleh kosong.");
  if (!cleaned.startsWith("http://") && !cleaned.startsWith("https://")) {
    return `https://${cleaned}`;
  }
  return cleaned;
}

// ================= PENYIMPANAN KREDENSIAL =================
function loadStore() {
  if (!fs.existsSync(CRED_FILE)) {
    return { active: null, credentials: {} };
  }
  return JSON.parse(fs.readFileSync(CRED_FILE, "utf8"));
}

function saveStore(store) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CRED_FILE, JSON.stringify(store, null, 2), "utf8");
  try {
    fs.chmodSync(CRED_FILE, 0o600);
  } catch {}
}

function getActiveCred() {
  const store = loadStore();
  const activeName = store.active;
  const cred = activeName ? store.credentials?.[activeName] : null;
  if (!cred) {
    throw new Error("Belum ada akun aktif. Gunakan /generate untuk membuat akun atau /accounts untuk memilih akun.");
  }
  return { name: activeName, cred, store };
}

// ================= API CALLS =================
async function gtcCall(endpoint, payload, { token = "", finalKey, deviceId, encrypted = true }) {
  const raw = JSON.stringify(payload);
  const ts = nowMs();
  const headers = {
    "Content-Type": "application/json",
    "x-os": ANDROID_OS,
    "x-app-version": APP_VERSION,
    "x-client-device-id": deviceId,
    "x-lang": LANG,
    "x-req-timestamp": ts,
    "x-country-code": COUNTRY,
    "x-encrypted": encrypted ? "1" : "0",
    "x-req-signature": sig(ts, raw, HMAC_KEY),
  };
  if (token) headers["x-token"] = token;

  const body = encrypted ? JSON.stringify({ data: encryptAesEcb(raw, finalKey) }) : raw;
  const resp = await axios.post(GTC_BASE + endpoint, body, {
    headers,
    timeout: 20000,
    validateStatus: () => true,
  });

  let parsed = resp.data;
  if (typeof parsed === "string") {
    parsed = JSON.parse(parsed);
  }
  if (encrypted && parsed && typeof parsed === "object" && "data" in parsed) {
    parsed = JSON.parse(decryptAesEcb(parsed.data, finalKey));
  }
  return { status: resp.status, body: parsed };
}

async function vfkCall(endpoint, payload, deviceId) {
  const raw = JSON.stringify(payload);
  const ts = nowMs();
  const headers = {
    "Content-Type": "application/json",
    "X-VFK-Client-Device-Id": deviceId,
    "X-VFK-Client-Key": VFK_CLIENT_KEY,
    "X-VFK-Sdk-Version": "0.11.4",
    "X-VFK-Os": "android 9.0",
    "X-VFK-App-Version": "8.16.0",
    "X-VFK-Encrypted": "1",
    "X-VFK-Lang": "in_ID",
    "X-VFK-Req-Timestamp": ts,
    "X-VFK-Req-Signature": sig(ts, raw, VFK_HMAC_KEY),
  };
  const body = JSON.stringify({ data: encryptAesEcb(raw, VFK_FINAL_KEY) });
  const resp = await axios.post(VFK_BASE + endpoint, body, {
    headers,
    timeout: 20000,
    validateStatus: () => true,
  });

  let parsed = resp.data;
  if (typeof parsed === "string") {
    parsed = JSON.parse(parsed);
  }
  if (parsed && typeof parsed === "object" && "data" in parsed) {
    parsed = JSON.parse(decryptAesEcb(parsed.data, VFK_FINAL_KEY));
  }
  return { status: resp.status, body: parsed };
}

async function apiSearch(cred, phone, sourceType) {
  const endpoint = sourceType === "tags" ? "/v2.8/number-detail" : "/v2.8/search";
  const payload = {
    countryCode: COUNTRY,
    phoneNumber: phone,
    source: sourceType === "tags" ? "profile" : "search",
    token: cred.token,
  };
  const { status, body } = await gtcCall(endpoint, payload, {
    token: cred.token,
    finalKey: cred.finalKey,
    deviceId: cred.clientDeviceId,
  });
  const meta = dig(body, "meta.httpStatusCode");
  if (status !== 200 || (meta !== undefined && meta !== 200)) {
    throw new Error(`HTTP ${status}/${meta ?? "?"}: ${dig(body, "meta.errorMessage", "unknown error")}`);
  }
  return body;
}

async function apiSubscription(cred) {
  const { status, body } = await gtcCall(
    "/v2.8/subscription",
    { token: cred.token },
    {
      token: cred.token,
      finalKey: cred.finalKey,
      deviceId: cred.clientDeviceId,
    }
  );
  if (status !== 200) {
    throw new Error(`HTTP ${status}: ${dig(body, "meta.errorMessage", "unknown error")}`);
  }
  return body;
}

// ================= FITUR OSINT & TOOLS =================
const PREFIX_MAP = {
  "62811": { provider: "Telkomsel (Kartu Halo)", region: "Nasional", wilayah: "Seluruh Indonesia (Pascabayar)" },
  "62812": { provider: "Telkomsel (simPATI)", region: "Jabodetabek", wilayah: "Jakarta, Bogor, Depok, Tangerang, Bekasi" },
  "62813": { provider: "Telkomsel (simPATI)", region: "Jawa Timur", wilayah: "Surabaya, Malang, Sidoarjo, Madura, Kediri" },
  "62821": { provider: "Telkomsel (Kartu AS)", region: "Jawa Tengah", wilayah: "Semarang, Solo, Yogyakarta, Purwokerto" },
  "62822": { provider: "Telkomsel (Kartu AS)", region: "Bali & Nusa Tenggara", wilayah: "Denpasar, Mataram, Kupang" },
  "62823": { provider: "Telkomsel (Loop)", region: "Sumatera", wilayah: "Medan, Palembang, Pekanbaru, Padang" },
  "62852": { provider: "Telkomsel (AS)", region: "Sulawesi & Kalimantan", wilayah: "Makassar, Manado, Balikpapan, Banjarmasin" },
  "62853": { provider: "Telkomsel (AS)", region: "Sumatera & Maluku", wilayah: "Medan, Banda Aceh, Ambon, Jayapura" },
  "62814": { provider: "Indosat (IM3)", region: "Jabodetabek", wilayah: "Jakarta, Bogor, Depok, Tangerang, Bekasi" },
  "62815": { provider: "Indosat (Mentari)", region: "Jawa Barat", wilayah: "Bandung, Cimahi, Sukabumi, Cirebon" },
  "62816": { provider: "Indosat (Matrix)", region: "Nasional", wilayah: "Seluruh Indonesia (Pascabayar)" },
  "62855": { provider: "Indosat (IM3 Ooredoo)", region: "Jawa Tengah", wilayah: "Semarang, Surakarta, Tegal" },
  "62856": { provider: "Indosat (IM3 Ooredoo)", region: "Jawa Timur", wilayah: "Surabaya, Malang, Jember" },
  "62857": { provider: "Indosat (IM3 Ooredoo)", region: "Kalimantan & Jawa", wilayah: "Banjarmasin, Pontianak, Samarinda" },
  "62858": { provider: "Indosat (IM3 Ooredoo)", region: "Sulawesi & Sumatera", wilayah: "Makassar, Medan, Palembang" },
  "62817": { provider: "XL Axiata", region: "Jabodetabek", wilayah: "Jakarta, Bogor, Depok, Tangerang, Bekasi" },
  "62818": { provider: "XL Axiata", region: "Jawa Tengah & Timur", wilayah: "Semarang, Yogyakarta, Surabaya" },
  "62819": { provider: "XL Axiata", region: "Sumatera & Kalimantan", wilayah: "Medan, Pekanbaru, Pontianak" },
  "62859": { provider: "XL Prabayar", region: "Nasional", wilayah: "Jaringan Utama Nasional XL" },
  "62877": { provider: "XL Prabayar", region: "Jawa Barat", wilayah: "Bandung, Bogor, Tasikmalaya, Cirebon" },
  "62878": { provider: "XL Prabayar", region: "Bali, NTB, NTT", wilayah: "Denpasar, Mataram, Kupang" },
  "62895": { provider: "Tri (3)", region: "Jakarta", wilayah: "Jakarta & Sekitarnya" },
  "62896": { provider: "Tri (3)", region: "Jawa Tengah", wilayah: "Semarang, Surakarta, Tegal" },
  "62897": { provider: "Tri (3)", region: "Jawa Timur", wilayah: "Surabaya, Malang, Sidoarjo" },
  "62898": { provider: "Tri (3)", region: "Sumatera", wilayah: "Medan, Palembang, Bandar Lampung" },
  "62899": { provider: "Tri (3)", region: "Sulawesi", wilayah: "Makassar, Manado, Kendari" },
  "62881": { provider: "Smartfren", region: "Jabodetabek", wilayah: "Jakarta, Bogor, Depok, Tangerang, Bekasi" },
  "62882": { provider: "Smartfren", region: "Jawa Barat", wilayah: "Bandung, Cimahi, Sukabumi" },
  "62883": { provider: "Smartfren", region: "Jawa Tengah", wilayah: "Semarang, Yogyakarta, Surakarta" },
  "62884": { provider: "Smartfren", region: "Nasional", wilayah: "Cakupan Nasional Smartfren" },
  "62831": { provider: "Axis", region: "Jabodetabek", wilayah: "Jakarta, Bogor, Depok, Tangerang, Bekasi" },
  "62832": { provider: "Axis", region: "Jawa Tengah", wilayah: "Semarang, Solo, Yogyakarta" },
  "62833": { provider: "Axis", region: "Jawa Timur", wilayah: "Surabaya, Malang, Kediri" },
  "62838": { provider: "Axis", region: "Sumatera", wilayah: "Medan, Batam, Padang" },
  "62851": { provider: "By.U (Telkomsel Digital)", region: "Online / Nasional", wilayah: "Seluruh Indonesia (Berbasis Digital)" },
};

function analyzePhone(rawNumber) {
  let cleaned = String(rawNumber || "").replace(/[^\d]/g, "");
  if (cleaned.startsWith("0")) cleaned = "62" + cleaned.slice(1);
  const prefix = cleaned.slice(0, 5);
  const info = PREFIX_MAP[prefix] || {
    provider: "Tidak diketahui / prefix khusus",
    region: "Tidak tersedia",
    wilayah: "Wilayah tidak terdefinisi",
  };
  const tipe = /halo|matrix/i.test(info.provider) ? "Pascabayar" : "Prabayar";
  return { cleaned, prefix, tipe, ...info };
}

const SOCIAL_PLATFORMS = {
  Instagram: "https://www.instagram.com/{}",
  TikTok: "https://www.tiktok.com/@{}",
  "Twitter / X": "https://twitter.com/{}",
  GitHub: "https://github.com/{}",
  Facebook: "https://www.facebook.com/{}",
  YouTube: "https://www.youtube.com/@{}",
  Pinterest: "https://www.pinterest.com/{}",
  LinkedIn: "https://www.linkedin.com/in/{}",
  Telegram: "https://t.me/{}",
  Reddit: "https://www.reddit.com/user/{}",
  Twitch: "https://www.twitch.tv/{}",
  Spotify: "https://open.spotify.com/user/{}",
  Steam: "https://steamcommunity.com/id/{}",
  SoundCloud: "https://soundcloud.com/{}",
  Medium: "https://medium.com/@{}",
  Behance: "https://www.behance.net/{}",
  Dribbble: "https://dribbble.com/{}",
  Flickr: "https://www.flickr.com/people/{}",
  Vimeo: "https://vimeo.com/{}",
  VK: "https://vk.com/{}",
  Codepen: "https://codepen.io/{}",
  "Dev.to": "https://dev.to/{}",
  Ebay: "https://www.ebay.com/usr/{}",
  Fiverr: "https://www.fiverr.com/{}",
  Goodreads: "https://www.goodreads.com/{}",
  HackerNews: "https://news.ycombinator.com/user?id={}",
  Kaggle: "https://www.kaggle.com/{}",
  "Last.fm": "https://www.last.fm/user/{}",
  MyAnimeList: "https://myanimelist.net/profile/{}",
  Patreon: "https://www.patreon.com/{}",
  PayPal: "https://www.paypal.com/paypalme/{}",
  Quora: "https://www.quora.com/profile/{}",
  Substack: "https://{}.substack.com",
  Tumblr: "https://{}.tumblr.com",
  Wattpad: "https://www.wattpad.com/user/{}",
  Bandcamp: "https://bandcamp.com/{}",
  BuyMeACoffee: "https://buymeacoffee.com/{}",
  "Chess.com": "https://www.chess.com/member/{}",
  DailyMotion: "https://www.dailymotion.com/{}",
  DeviantArt: "https://www.deviantart.com/{}",
  Duolingo: "https://www.duolingo.com/profile/{}",
  Figma: "https://www.figma.com/@{}",
  Genius: "https://genius.com/{}",
  Giphy: "https://giphy.com/{}",
  Gumroad: "https://gumroad.com/{}",
  HuggingFace: "https://huggingface.co/{}",
  Imgur: "https://imgur.com/user/{}",
  "Ko-fi": "https://ko-fi.com/{}",
  Letterboxd: "https://letterboxd.com/{}",
  Mastodon: "https://mastodon.social/@{}",
  Mixcloud: "https://www.mixcloud.com/{}",
  Myspace: "https://myspace.com/{}",
  Npm: "https://www.npmjs.com/~{}",
  OpenSea: "https://opensea.io/{}",
  Pypi: "https://pypi.org/user/{}",
  Rumble: "https://rumble.com/user/{}",
  Scratch: "https://scratch.mit.edu/users/{}",
  Strava: "https://www.strava.com/athletes/{}",
  Trello: "https://trello.com/{}",
  TryHackMe: "https://tryhackme.com/p/{}",
  Unsplash: "https://unsplash.com/@{}",
  Venmo: "https://venmo.com/{}",
  Zenn: "https://zenn.dev/{}",
};

async function scanSocialUsername(username) {
  const entries = Object.entries(SOCIAL_PLATFORMS);
  const found = [];
  const concurrency = 15;
  let index = 0;

  async function worker() {
    while (index < entries.length) {
      const i = index++;
      const [name, template] = entries[i];
      const url = template.replace("{}", encodeURIComponent(username));
      try {
        const res = await axios.get(url, {
          headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
          timeout: 5000,
          maxRedirects: 5,
          validateStatus: (s) => s === 200,
        });
        if (res.status === 200) {
          found.push({ name, url });
        }
      } catch {}
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
  return found;
}

// ================= WEB SOURCE (KIRIM KE CHAT TANPA UPLOAD DOKUMEN) =================
function decodeEscapedSource(text) {
  let decoded = String(text ?? "");
  if (/\\n|\\t|\\\/|\\u|\\"/i.test(decoded)) {
    decoded = decoded
      .replace(/\\r\\n/g, "\n")
      .replace(/\\n/g, "\n")
      .replace(/\\r/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\"/g, '"')
      .replace(/\\\//g, "/")
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
  return decoded;
}

function extractWebSource(payload) {
  if (typeof payload === "string") {
    return decodeEscapedSource(payload);
  }
  if (Array.isArray(payload)) {
    return payload.map((item) => extractWebSource(item)).filter(Boolean).join("\n");
  }
  if (payload && typeof payload === "object") {
    const keys = [
      "source",
      "html",
      "code",
      "content",
      "body",
      "data",
      "result",
      "response",
      "text",
      "raw",
    ];
    for (const k of keys) {
      if (k in payload && payload[k] !== null && payload[k] !== undefined) {
        const val = payload[k];
        if (typeof val === "string" && (val.includes("<") || val.length > 100)) {
          return decodeEscapedSource(val);
        }
        if (typeof val === "object") {
          const nested = extractWebSource(val);
          if (nested) return nested;
        }
      }
    }
    let best = "";
    for (const val of Object.values(payload)) {
      const candidate = typeof val === "object" ? extractWebSource(val) : String(val ?? "");
      if (candidate.length > best.length) best = candidate;
    }
    if (best) return decodeEscapedSource(best);
    return JSON.stringify(payload, null, 2);
  }
  return String(payload ?? "");
}

async function fetchWebSource(rawUrl, apiKey = WEB_SOURCE_DEFAULT_KEY) {
  const targetUrl = normalizeWebUrl(rawUrl);
  const resp = await axios.get(WEB_SOURCE_API, {
    params: { url: targetUrl, apikey: apiKey },
    timeout: 15000,
    validateStatus: () => true,
  });

  if (resp.status < 200 || resp.status >= 300) {
    throw new Error(`API Web Source mengembalikan HTTP ${resp.status}`);
  }

  const source = extractWebSource(resp.data);
  if (!source || !source.trim()) {
    throw new Error("Source web kosong.");
  }
  return { targetUrl, source };
}

async function sendWebSourceResult(ctx, rawUrl) {
  await ctx.reply(`🌐 Mengambil source untuk \`${escapeMd(rawUrl)}\`...`, {
    parse_mode: "Markdown",
  });

  const { targetUrl, source } = await fetchWebSource(rawUrl);
  const normalized = String(source).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const chunkSize = 3500;
  const chunks = [];

  for (let i = 0; i < normalized.length; i += chunkSize) {
    chunks.push(normalized.slice(i, i + chunkSize).replace(/```/g, "'''"));
  }

  await ctx.reply(
    [
      "╔══════════════════════╗",
      "║   🌐 *WEB SOURCE READY*   ║",
      "╚══════════════════════╝",
      `• *Target*   : ${escapeMd(targetUrl)}`,
      `• *Ukuran*   : *${normalized.length}* karakter`,
      `• *Bagian*   : *${chunks.length}* part`,
    ].join("\n"),
    { parse_mode: "Markdown" }
  );

  const maxParts = chunks.slice(0, 8);
  for (let idx = 0; idx < maxParts.length; idx++) {
    await ctx.reply(
      `📄 *Bagian ${idx + 1}/${chunks.length}:*\n\`\`\`html\n${maxParts[idx]}\n\`\`\``,
      { parse_mode: "Markdown" }
    );
  }

  if (chunks.length > 8) {
    await ctx.reply(`⚠️ Source terlalu panjang (${chunks.length} bagian). Bagian 1–8 sudah dikirim.`);
  }
}

async function askCloudAi(prompt) {
  const payload = {
    data: {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      timeZone: TIME_ZONE,
      countryCode: COUNTRY,
    },
  };
  const resp = await axios.post(AI_ENDPOINT, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: 20000,
  });
  const resJson = resp.data;
  const choice = dig(resJson, "result.choices.0");
  return (
    dig(choice, "message.content") ||
    dig(choice, "text") ||
    dig(resJson, "result.text") ||
    dig(resJson, "text") ||
    dig(resJson, "response") ||
    JSON.stringify(resJson, null, 2)
  );
}

// ================= HANDLER UTAMA PROFIL, TAG, KUOTA & GENERATE WA =================
async function handlePhoneSearch(ctx, rawPhone, sourceType) {
  const phone = normalizePhone(rawPhone);
  const { cred } = getActiveCred();
  const label = sourceType === "tags" ? "TAG NOMOR" : "PROFIL NOMOR";

  await ctx.reply(`🔍 Mencari *${label}* untuk \`${escapeMd(phone)}\`...`, {
    parse_mode: "Markdown",
  });

  const body = await apiSearch(cred, phone, sourceType);
  const profile = dig(body, "result.profile");
  const tags = dig(body, "result.tags");

  const lines = [
    "╔══════════════════════╗",
    `║   📌 *${label}*`,
    "╚══════════════════════╝",
    `• *Target* : \`${escapeMd(phone)}\`\n`,
  ];

  if (profile && typeof profile === "object") {
    lines.push("*Profil:*");
    for (const k of ["displayName", "name", "surname", "phoneNumber", "displayNumber", "tagCount", "email"]) {
      lines.push(`• *${k}*: \`${escapeMd(profile[k] || "-")}\``);
    }
  }

  if (Array.isArray(tags) && tags.length > 0) {
    lines.push(`\n*Tags (${tags.length}):*`);
    for (const t of tags.slice(0, 50)) {
      const tagName = escapeMd(t?.tag ?? "-");
      const tagCount = t?.count ?? "";
      lines.push(`• ${tagName}${tagCount !== "" ? ` (${tagCount})` : ""}`);
    }
    if (tags.length > 50) {
      lines.push(`_...dan ${tags.length - 50} tag lainnya._`);
    }
  }

  if (!profile && (!Array.isArray(tags) || tags.length === 0)) {
    const rawJson = JSON.stringify(body, null, 2).slice(0, 3500);
    lines.push("```json\n" + rawJson + "\n```");
  }

  await ctx.reply(lines.join("\n").slice(0, 4000), { parse_mode: "Markdown" });
}

async function handleQuota(ctx) {
  const { name, cred } = getActiveCred();
  const body = await apiSubscription(cred);

  const u = dig(body, "result.subscriptionInfo.usage") || {};
  const search = u.search || {};
  const detail = u.numberDetail || {};
  const renew = dig(body, "result.subscriptionInfo.renewDate", "-");

  const text = [
    "╔══════════════════════╗",
    "║     📊 *SISA KUOTA*     ║",
    "╚══════════════════════╝",
    `• *Akun*         : \`${escapeMd(name)}\``,
    `• *Search*       : *${search.remainingCount ?? "?"}* / ${search.limit ?? "?"}`,
    `• *NumberDetail* : *${detail.remainingCount ?? "?"}* / ${detail.limit ?? "?"}`,
    `• *Renew Date*   : \`${escapeMd(renew)}\``,
  ].join("\n");

  await ctx.reply(text, { parse_mode: "Markdown" });
}

async function startGenerateAccount(ctx, rawPhone) {
  const phone = normalizePhone(rawPhone);
  const deviceId = newDeviceId();
  const { priv, pub } = dhKeypair();

  await ctx.reply(`⏳ Mendaftarkan perangkat untuk \`${escapeMd(phone)}\`...`, {
    parse_mode: "Markdown",
  });

  const ts = nowMs();
  const regPayload = {
    carrierCountryCode: CARRIER[0],
    carrierName: CARRIER[1],
    carrierNetworkCode: CARRIER[2],
    countryCode: COUNTRY,
    deepLink: null,
    deviceName: DEVICE_NAME,
    deviceType: "Android",
    email: null,
    notificationToken: "",
    oldToken: null,
    peerKey: pub,
    timeZone: TIME_ZONE,
    token: "",
  };
  const rawReg = JSON.stringify(regPayload);

  const regResp = await axios.post(GTC_BASE + "/v2.8/register", rawReg, {
    headers: {
      "Content-Type": "application/json",
      "x-os": ANDROID_OS,
      "x-app-version": APP_VERSION,
      "x-client-device-id": deviceId,
      "x-lang": LANG,
      "x-req-timestamp": ts,
      "x-country-code": COUNTRY,
      "x-encrypted": "0",
      "x-req-signature": sig(ts, rawReg, HMAC_KEY),
    },
    timeout: 20000,
    validateStatus: () => true,
  });

  if (regResp.status !== 201) {
    throw new Error(`Gagal register: HTTP ${regResp.status}`);
  }

  const token = dig(regResp.data, "result.token");
  const serverKey = dig(regResp.data, "result.serverKey");
  if (!token || !serverKey) {
    throw new Error("Register gagal: token/serverKey tidak ada.");
  }

  const finalKey = dhFinalKey(priv, serverKey);
  const common = { token, finalKey, deviceId };
  const base = {
    carrierCountryCode: CARRIER[0],
    carrierName: CARRIER[1],
    carrierNetworkCode: CARRIER[2],
    countryCode: COUNTRY,
    deviceName: DEVICE_NAME,
    notificationToken: "",
    timeZone: TIME_ZONE,
    token,
  };

  const randNum = crypto.randomInt(10000000, 99999999);
  const randUser = crypto.randomInt(1000, 999999);
  const steps = [
    ["/v2.8/init-basic", base, 201],
    ["/v2.8/ad-settings", { source: "init", token }, 200],
    ["/v2.8/init-intro", { ...base, hasRouting: false }, 201],
    [
      "/v2.8/email-code-validate/start",
      { email: `user${randNum}@gmail.com`, fullName: `User${randUser}`, token },
      200,
    ],
    ["/v2.8/country", { countryCode: COUNTRY.toUpperCase(), token }, 200],
    [
      "/v2.8/validation-start",
      { app: "verifykit", countryCode: COUNTRY, notificationToken: "", token },
      200,
    ],
  ];

  for (const [endpoint, payload, want] of steps) {
    const { status } = await gtcCall(endpoint, payload, common);
    if (status !== want) {
      throw new Error(`Inisialisasi gagal di ${endpoint} (HTTP ${status})`);
    }
  }

  await vfkCall(
    "/v2.0/init",
    {
      isCallPermissionGranted: true,
      countryCode: "ID",
      deviceName: DEVICE_NAME,
      installedApps: '{"whatsapp":0,"telegram":0,"viber":0}',
      outsideCountryCode: "ID",
      outsidePhoneNumber: rawPhone,
      timezone: TIME_ZONE,
      bundleId: BUNDLE_ID,
    },
    deviceId
  );

  await vfkCall("/v2.0/country", { countryCode: "ID", bundleId: BUNDLE_ID }, deviceId);

  const { body: startBody } = await vfkCall(
    "/v2.0/start",
    {
      countryCode: "ID",
      mcc: CARRIER[0],
      mnc: CARRIER[2],
      phoneNumber: phone,
      app: "whatsapp",
      bundleId: BUNDLE_ID,
    },
    deviceId
  );

  const deeplink = dig(startBody, "result.deeplink");
  const reference = dig(startBody, "result.reference");
  if (!deeplink || !reference) {
    throw new Error("Gagal mendapatkan link verifikasi WhatsApp.");
  }

  await gtcCall(
    "/v2.8/validation-start",
    { app: "verifykit", countryCode: COUNTRY, notificationToken: "", token },
    common
  );

  userSessions.set(ctx.chat.id, {
    step: "await_wa_confirm",
    data: { phone, deviceId, finalKey, token, reference },
  });

  await ctx.reply(
    `📲 Kirim pesan verifikasi WhatsApp melalui link berikut:\n${deeplink}\n\nSetelah pesan WA terkirim dan bercentang, klik tombol di bawah:`,
    Markup.inlineKeyboard([[Markup.button.callback("✅ Cek & Simpan Akun", "confirm_wa_verify")]])
  );
}

// ================= BOT TELEGRAM & TAMPILAN MENU =================
const bot = new Telegraf(BOT_TOKEN, { handlerTimeout: 60000 });

bot.use(async (ctx, next) => {
  if (ctx.message?.text) {
    logActivity(ctx, `TEXT: "${ctx.message.text.slice(0, 120)}"`);
  } else if (ctx.callbackQuery?.data) {
    logActivity(ctx, `TOMBOL: [${ctx.callbackQuery.data}]`);
  } else if (ctx.message) {
    const keys = Object.keys(ctx.message).filter((k) => !["message_id", "from", "chat", "date"].includes(k));
    logActivity(ctx, `MEDIA/MSG: ${keys.join(", ") || "unknown"}`);
  }
  return next();
});

function mainMenuKeyboard() {
  return Markup.inlineKeyboard([
    [
      Markup.button.callback("👤 Cari Profil", "act_profile"),
      Markup.button.callback("🏷️ Cari Tag", "act_tags"),
    ],
    [
      Markup.button.callback("📊 Sisa Kuota", "act_quota"),
      Markup.button.callback("📱 Track Nomor", "act_trackphone"),
    ],
    [
      Markup.button.callback("🌐 Track IP/Domain", "act_trackip"),
      Markup.button.callback("🔎 Track Sosmed", "act_tracksocial"),
    ],
    [
      Markup.button.callback("📄 Web Source", "act_websource"),
      Markup.button.callback("🤖 Cloud AI", "act_ai"),
    ],
    [
      Markup.button.callback("➕ Buat Akun (WA)", "act_generate"),
      Markup.button.callback("🔓 Captcha", "act_captcha"),
    ],
    [
      Markup.button.callback("🗂️ Akun Tersimpan", "act_accounts"),
      Markup.button.callback("ℹ️ Credits", "act_credits"),
    ],
  ]);
}

function buildStyledMenuText(title, activeAccount, extraPrefix = "") {
  const hasVideo = fs.existsSync(MENU_VIDEO_PATH);
  const lines = [];
  if (extraPrefix) lines.push(extraPrefix);
  lines.push(
    "╔══════════════════════╗",
    `║  ⚡ *${title}*`,
    "╚══════════════════════╝",
    "_Author : RendiSec • Suite v8.4_",
    `• *Status*     : 🟢 Unlocked`,
    `• *Akun Aktif* : \`${escapeMd(activeAccount || "Belum ada")}\``,
    `• *Menu Video* : ${hasVideo ? `🎬 \`${escapeMd(path.basename(MENU_VIDEO_PATH))}\`` : "⚪ Mode Teks"}`,
    "",
    "👇 *Pilih modul di bawah atau ketik /help:*"
  );
  return lines.join("\n");
}

async function replyMenuWithVideo(ctx, text, extraOptions = {}) {
  const keyboard = extraOptions.reply_markup ? extraOptions : { ...extraOptions, ...mainMenuKeyboard() };
  if (fs.existsSync(MENU_VIDEO_PATH)) {
    try {
      await ctx.replyWithVideo(
        { source: MENU_VIDEO_PATH, filename: path.basename(MENU_VIDEO_PATH) },
        {
          caption: text,
          parse_mode: "Markdown",
          ...keyboard,
        }
      );
      return;
    } catch (err) {
      console.error(`[${formatTimeWib()} WIB] Gagal kirim video menu:`, err?.message || err);
    }
  }
  await ctx.reply(text, {
    parse_mode: "Markdown",
    ...keyboard,
  });
}

function isAuthed(ctx) {
  return authedChats.has(ctx.chat.id);
}

async function requireAuth(ctx) {
  if (isAuthed(ctx)) return true;
  userSessions.set(ctx.chat.id, { step: "await_login" });
  await ctx.reply(
    [
      "╔══════════════════════╗",
      "║   🔐 *AKSES TERKUNCI*    ║",
      "╚══════════════════════╝",
      "Silakan kirimkan sandi login untuk membuka panel:",
    ].join("\n"),
    { parse_mode: "Markdown" }
  );
  return false;
}

bot.start(async (ctx) => {
  const chatId = ctx.chat.id;
  if (!authedChats.has(chatId)) {
    userSessions.set(chatId, { step: "await_login" });
    return ctx.reply(
      [
        "╔══════════════════════╗",
        "║  ⚡ *XTOLS SUITE v8.4*   ║",
        "╚══════════════════════╝",
        "_Author : RendiSec_",
        "• *Status* : 🔒 Terkunci",
        "",
        "🔐 Masukkan sandi login terlebih dahulu:",
      ].join("\n"),
      { parse_mode: "Markdown" }
    );
  }
  const store = loadStore();
  const menuText = buildStyledMenuText("XTOLS DASHBOARD", store.active);
  await replyMenuWithVideo(ctx, menuText);
});

bot.command("help", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  await ctx.reply(
    [
      "╔══════════════════════╗",
      "║    📖 *PANDUAN BOT*     ║",
      "╚══════════════════════╝",
      "• `/menu` - Tampilkan dashboard + video",
      "• `/profile <nomor>` - Cari profil nomor",
      "• `/tags <nomor>` - Cari tag nomor",
      "• `/quota` - Cek sisa kuota akun",
      "• `/trackphone <nomor>` - Analisa prefix & wilayah",
      "• `/trackip <ip/domain>` - Lacak IP atau domain",
      "• `/tracksocial <user>` - Scan username sosmed",
      "• `/websource <url>` - Ambil source web ke chat",
      "• `/ai <prompt>` - Tanya Cloud AI",
      "• `/generate <nomor>` - Buat akun via WhatsApp",
      "• `/captcha` - Refresh & verifikasi captcha",
      "• `/accounts` - Kelola akun tersimpan",
    ].join("\n"),
    { parse_mode: "Markdown" }
  );
});

bot.command("menu", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const store = loadStore();
  const menuText = buildStyledMenuText("XTOLS MAIN MENU", store.active);
  await replyMenuWithVideo(ctx, menuText);
});

bot.command("profile", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const arg = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!arg) return ctx.reply("Contoh: `/profile 081234567890`", { parse_mode: "Markdown" });
  try {
    await handlePhoneSearch(ctx, arg, "profile");
  } catch (e) {
    await ctx.reply(`❌ Error profil: ${e.message}`);
  }
});

bot.command("tags", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const arg = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!arg) return ctx.reply("Contoh: `/tags 081234567890`", { parse_mode: "Markdown" });
  try {
    await handlePhoneSearch(ctx, arg, "tags");
  } catch (e) {
    await ctx.reply(`❌ Error tag: ${e.message}`);
  }
});

bot.command("quota", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  try {
    await handleQuota(ctx);
  } catch (e) {
    await ctx.reply(`❌ Error kuota: ${e.message}`);
  }
});

bot.command("trackphone", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const arg = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!arg) return ctx.reply("Contoh: `/trackphone 081234567890`", { parse_mode: "Markdown" });
  const info = analyzePhone(arg);
  await ctx.reply(
    [
      "╔══════════════════════╗",
      "║   📱 *ANALISA NOMOR*    ║",
      "╚══════════════════════╝",
      `• *Nomor*    : \`+${info.cleaned}\``,
      `• *Prefix*   : \`${info.prefix}\``,
      `• *Operator* : ${escapeMd(info.provider)}`,
      `• *Tipe*     : ${info.tipe}`,
      `• *Region*   : ${escapeMd(info.region)}`,
      `• *Wilayah*  : ${escapeMd(info.wilayah)}`,
    ].join("\n"),
    { parse_mode: "Markdown" }
  );
});

bot.command("trackip", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const target = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!target) return ctx.reply("Contoh: `/trackip 8.8.8.8` atau `/trackip example.com`", { parse_mode: "Markdown" });
  try {
    const fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query";
    const resp = await axios.get(`[http://ip-api.com/json/$](http://ip-api.com/json/$){encodeURIComponent(target)}`, {
      params: { fields },
      timeout: 15000,
    });
    const r = resp.data;
    if (r.status !== "success") return ctx.reply(`❌ Gagal melacak: ${r.message || "Tidak diketahui"}`);
    await ctx.reply(
      [
        "╔══════════════════════╗",
        "║   🌐 *IP / DOMAIN*     ║",
        "╚══════════════════════╝",
        `• *Target*     : \`${escapeMd(r.query)}\``,
        `• *Negara*     : ${escapeMd(r.country)} (${escapeMd(r.countryCode)})`,
        `• *Wilayah*    : ${escapeMd(r.regionName)} (${escapeMd(r.region)})`,
        `• *Kota*       : ${escapeMd(r.city || "-")}`,
        `• *Kode Pos*   : ${escapeMd(r.zip || "-")}`,
        `• *Koordinat*  : Lat ${r.lat}, Lon ${r.lon}`,
        `• *Zona Waktu* : ${escapeMd(r.timezone || "-")}`,
        `• *ISP*        : ${escapeMd(r.isp || "-")}`,
        `• *Organisasi* : ${escapeMd(r.org || "-")}`,
      ].join("\n"),
      { parse_mode: "Markdown" }
    );
  } catch (e) {
    await ctx.reply(`❌ Koneksi gagal: ${e.message}`);
  }
});

bot.command("tracksocial", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const username = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!username) return ctx.reply("Contoh: `/tracksocial johndoe`", { parse_mode: "Markdown" });
  await ctx.reply(`🔍 Memeriksa username \`${escapeMd(username)}\`...`, { parse_mode: "Markdown" });
  const found = await scanSocialUsername(username);
  if (!found.length) {
    return ctx.reply(`⚠️ Tidak ditemukan profil aktif untuk \`${escapeMd(username)}\`.`, { parse_mode: "Markdown" });
  }
  const lines = found.map((item) => `• *${escapeMd(item.name)}*: ${item.url}`);
  await ctx.reply(`✨ Ditemukan di *${found.length}* platform:\n\n` + lines.join("\n"), {
    parse_mode: "Markdown",
    disable_web_page_preview: true,
  });
});

bot.command("websource", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const rawUrl = ctx.message.text.split(" ").slice(1).join(" ").trim() || "google.com";
  try {
    await sendWebSourceResult(ctx, rawUrl);
  } catch (e) {
    await ctx.reply(`❌ Gagal mengambil source: ${e.message}`);
  }
});

bot.command("ai", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const prompt = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!prompt) return ctx.reply("Contoh: `/ai Jelaskan cara kerja Diffie-Hellman`", { parse_mode: "Markdown" });
  try {
    const ans = await askCloudAi(prompt);
    await ctx.reply(`🤖 *Jawaban Cloud AI:*\n\n${String(ans).slice(0, 3900)}`);
  } catch (e) {
    await ctx.reply(`❌ Error Cloud AI: ${e.message}`);
  }
});

bot.command("generate", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const arg = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!arg) return ctx.reply("Contoh: `/generate 081234567890`", { parse_mode: "Markdown" });
  try {
    await startGenerateAccount(ctx, arg);
  } catch (e) {
    await ctx.reply(`❌ Gagal generate akun: ${e.message}`);
  }
});

bot.action("confirm_wa_verify", async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  const sess = userSessions.get(ctx.chat.id);
  if (!sess || sess.step !== "await_wa_confirm") {
    return ctx.reply("⚠️ Tidak ada sesi verifikasi WA yang aktif.");
  }
  const { phone, deviceId, finalKey, token, reference } = sess.data;
  try {
    const { body: checkBody } = await vfkCall("/v2.0/check", { reference, bundleId: BUNDLE_ID }, deviceId);
    const sessionId = dig(checkBody, "result.sessionId");
    if (!sessionId) {
      return ctx.reply("❌ Verifikasi belum selesai. Pastikan pesan WA sudah terkirim lalu coba lagi.");
    }

    const { body: resBody } = await gtcCall(
      "/v2.8/verifykit-result",
      { sessionId, token },
      { token, finalKey, deviceId }
    );
    const validationDate = dig(resBody, "result.validationDate");
    if (!validationDate) {
      return ctx.reply("❌ Gagal mengambil hasil verifykit.");
    }

    const store = loadStore();
    store.credentials = store.credentials || {};
    store.credentials[phone] = {
      description: `Generated ${validationDate}`,
      phoneNumber: phone,
      clientDeviceId: deviceId,
      finalKey,
      token,
      validationDate,
    };
    store.active = phone;
    saveStore(store);
    userSessions.delete(ctx.chat.id);

    await ctx.reply(`✨ Berhasil! Akun \`${escapeMd(phone)}\` tersimpan dan dijadikan aktif.`, {
      parse_mode: "Markdown",
    });
  } catch (e) {
    await ctx.reply(`❌ Error saat cek verifikasi: ${e.message}`);
  }
});

bot.command("captcha", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  try {
    const { cred } = getActiveCred();
    const common = { token: cred.token, finalKey: cred.finalKey, deviceId: cred.clientDeviceId };
    const { status, body } = await gtcCall("/v2.8/refresh-code", { token: cred.token }, common);
    const imageB64 = dig(body, "result.image");
    if (!imageB64) {
      return ctx.reply(`⚠️ Tidak ada captcha (HTTP ${status}). Akun mungkin tidak terblokir.`);
    }
    userSessions.set(ctx.chat.id, { step: "await_captcha_code" });
    await ctx.replyWithPhoto(
      { source: Buffer.from(imageB64, "base64") },
      { caption: "🔐 Balas pesan ini dengan kode captcha yang terlihat pada gambar:" }
    );
  } catch (e) {
    await ctx.reply(`❌ Error captcha: ${e.message}`);
  }
});

bot.command("accounts", async (ctx) => {
  if (!(await requireAuth(ctx))) return;
  const store = loadStore();
  const creds = store.credentials || {};
  const names = Object.keys(creds);
  if (!names.length) return ctx.reply("⚠️ Belum ada akun tersimpan.");

  const buttons = names.map((n) => [
    Markup.button.callback(`${n === store.active ? "⭐ " : ""}${n}`, `use_acc_${n}`),
  ]);
  await ctx.reply("🗂️ *Daftar Akun Tersimpan* (klik untuk mengaktifkan):", {
    parse_mode: "Markdown",
    ...Markup.inlineKeyboard(buttons),
  });
});

const ACTION_PROMPTS = {
  act_profile: { step: "await_profile_phone", text: "Masukkan nomor telepon untuk cek *profil*:" },
  act_tags: { step: "await_tags_phone", text: "Masukkan nomor telepon untuk cek *tag*:" },
  act_trackphone: { step: "await_trackphone", text: "Masukkan nomor telepon Indonesia untuk dianalisa:" },
  act_trackip: { step: "await_trackip", text: "Masukkan IP Address atau Domain:" },
  act_tracksocial: { step: "await_tracksocial", text: "Masukkan username target:" },
  act_websource: { step: "await_websource", text: "Masukkan URL target (contoh: google.com):" },
  act_ai: { step: "await_ai", text: "Masukkan pertanyaan untuk Cloud AI:" },
  act_generate: { step: "await_generate_phone", text: "Masukkan nomor WhatsApp untuk verifikasi (misal 0812xxxx):" },
};

for (const [actionId, cfg] of Object.entries(ACTION_PROMPTS)) {
  bot.action(actionId, async (ctx) => {
    await ctx.answerCbQuery().catch(() => {});
    if (!(await requireAuth(ctx))) return;
    userSessions.set(ctx.chat.id, { step: cfg.step });
    await ctx.reply(cfg.text, { parse_mode: "Markdown" });
  });
}

bot.action("act_quota", async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!(await requireAuth(ctx))) return;
  try {
    await handleQuota(ctx);
  } catch (e) {
    await ctx.reply(`❌ Error kuota: ${e.message}`);
  }
});

bot.action("act_captcha", async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!(await requireAuth(ctx))) return;
  try {
    const { cred } = getActiveCred();
    const common = { token: cred.token, finalKey: cred.finalKey, deviceId: cred.clientDeviceId };
    const { status, body } = await gtcCall("/v2.8/refresh-code", { token: cred.token }, common);
    const imageB64 = dig(body, "result.image");
    if (!imageB64) {
      return ctx.reply(`⚠️ Tidak ada captcha (HTTP ${status}). Akun mungkin tidak terblokir.`);
    }
    userSessions.set(ctx.chat.id, { step: "await_captcha_code" });
    await ctx.replyWithPhoto(
      { source: Buffer.from(imageB64, "base64") },
      { caption: "🔐 Balas pesan ini dengan kode captcha yang terlihat pada gambar:" }
    );
  } catch (e) {
    await ctx.reply(`❌ Error captcha: ${e.message}`);
  }
});

bot.action("act_accounts", async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!(await requireAuth(ctx))) return;
  const store = loadStore();
  const creds = store.credentials || {};
  const names = Object.keys(creds);
  if (!names.length) return ctx.reply("⚠️ Belum ada akun tersimpan.");
  const buttons = names.map((n) => [
    Markup.button.callback(`${n === store.active ? "⭐ " : ""}${n}`, `use_acc_${n}`),
  ]);
  await ctx.reply("🗂️ *Daftar Akun Tersimpan* (klik untuk mengaktifkan):", {
    parse_mode: "Markdown",
    ...Markup.inlineKeyboard(buttons),
  });
});

bot.action("act_credits", async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await ctx.reply(
    [
      "╔══════════════════════╗",
      "║      ℹ️ *CREDITS*       ║",
      "╚══════════════════════╝",
      "• RendiSec",
      "• VynnGrup",
      "• PutraWibu",
      "• GeminiAi",
      "• XynnHd",
      "• Xynaa",
    ].join("\n"),
    { parse_mode: "Markdown" }
  );
});

bot.action(/^use_acc_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  if (!(await requireAuth(ctx))) return;
  const accName = ctx.match[1];
  const store = loadStore();
  if (!store.credentials?.[accName]) {
    return ctx.reply("❌ Akun tidak ditemukan.");
  }
  store.active = accName;
  saveStore(store);
  await ctx.reply(`✅ Akun aktif diubah ke \`${escapeMd(accName)}\`.`, { parse_mode: "Markdown" });
});

bot.on("text", async (ctx) => {
  const text = ctx.message.text.trim();
  if (text.startsWith("/")) return;

  const chatId = ctx.chat.id;
  const sess = userSessions.get(chatId);

  if (sess?.step === "await_login") {
    if (text === LOGIN_PASSWORD) {
      authedChats.add(chatId);
      userSessions.delete(chatId);
      logActivity(ctx, "LOGIN BERHASIL");
      const store = loadStore();
      const menuText = buildStyledMenuText("XTOLS DASHBOARD", store.active, "✅ *Login berhasil!*\n");
      return await replyMenuWithVideo(ctx, menuText);
    }
    logActivity(ctx, "LOGIN GAGAL (sandi salah)");
    return ctx.reply("❌ Sandi salah. Coba lagi:");
  }

  if (!(await requireAuth(ctx))) return;
  if (!sess) return;

  userSessions.delete(chatId);

  try {
    if (sess.step === "await_profile_phone") return await handlePhoneSearch(ctx, text, "profile");
    if (sess.step === "await_tags_phone") return await handlePhoneSearch(ctx, text, "tags");
    if (sess.step === "await_generate_phone") return await startGenerateAccount(ctx, text);

    if (sess.step === "await_trackphone") {
      const info = analyzePhone(text);
      return await ctx.reply(
        [
          "╔══════════════════════╗",
          "║   📱 *ANALISA NOMOR*    ║",
          "╚══════════════════════╝",
          `• *Nomor*    : \`+${info.cleaned}\``,
          `• *Operator* : ${escapeMd(info.provider)}`,
          `• *Tipe*     : ${info.tipe}`,
          `• *Region*   : ${escapeMd(info.region)}`,
          `• *Wilayah*  : ${escapeMd(info.wilayah)}`,
        ].join("\n"),
        { parse_mode: "Markdown" }
      );
    }

    if (sess.step === "await_trackip") {
      const resp = await axios.get(`[http://ip-api.com/json/$](http://ip-api.com/json/$){encodeURIComponent(text)}`, { timeout: 15000 });
      const r = resp.data;
      if (r.status !== "success") return await ctx.reply(`❌ Gagal: ${r.message || "Tidak diketahui"}`);
      return await ctx.reply(
        [
          "╔══════════════════════╗",
          "║   🌐 *IP / DOMAIN*     ║",
          "╚══════════════════════╝",
          `• *Target*    : \`${escapeMd(r.query)}\``,
          `• *Negara*    : ${escapeMd(r.country)} (${escapeMd(r.countryCode)})`,
          `• *Kota*      : ${escapeMd(r.city || "-")}`,
          `• *ISP*       : ${escapeMd(r.isp || "-")}`,
          `• *Koordinat* : ${r.lat}, ${r.lon}`,
        ].join("\n"),
        { parse_mode: "Markdown" }
      );
    }

    if (sess.step === "await_tracksocial") {
      await ctx.reply(`🔍 Memindai \`${escapeMd(text)}\`...`, { parse_mode: "Markdown" });
      const found = await scanSocialUsername(text);
      if (!found.length) return await ctx.reply("⚠️ Tidak ditemukan.");
      return await ctx.reply(found.map((f) => `• *${escapeMd(f.name)}*: ${f.url}`).join("\n"), {
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      });
    }

    if (sess.step === "await_websource") {
      return await sendWebSourceResult(ctx, text);
    }

    if (sess.step === "await_ai") {
      const ans = await askCloudAi(text);
      return await ctx.reply(`🤖 *Cloud AI:*\n\n${String(ans).slice(0, 3900)}`);
    }

    if (sess.step === "await_captcha_code") {
      const { cred } = getActiveCred();
      const { status, body } = await gtcCall(
        "/v2.8/verify-code",
        { validationCode: text, token: cred.token },
        { token: cred.token, finalKey: cred.finalKey, deviceId: cred.clientDeviceId }
      );
      if (status === 200 && dig(body, "meta.httpStatusCode") === 200) {
        return await ctx.reply("✅ Captcha berhasil diverifikasi!");
      }
      return await ctx.reply("❌ Kode captcha salah atau gagal diverifikasi.");
    }
  } catch (e) {
    await ctx.reply(`❌ Error: ${e.message}`);
  }
});

bot.catch((err, ctx) => {
  console.error(`[${formatTimeWib()} WIB] Telegraf error untuk update ${ctx?.update?.update_id}:`, err?.message || err);
});

process.on("unhandledRejection", (reason) => {
  console.error(`[${formatTimeWib()} WIB] Unhandled Rejection:`, reason?.message || reason);
});

process.on("uncaughtException", (err) => {
  console.error(`[${formatTimeWib()} WIB] Uncaught Exception:`, err?.message || err);
});

bot.launch().then(() => {
  console.log("==========================================");
  console.log("  XTOLS TELEGRAM BOT BERJALAN (LIVE LOG)");
  console.log("==========================================");
  console.log(`Video menu : ${MENU_VIDEO_PATH} (${fs.existsSync(MENU_VIDEO_PATH) ? "ADA" : "BELUM ADA"})`);
});

process.once("SIGINT", () => bot.stop("SIGINT"));
process.once("SIGTERM", () => bot.stop("SIGTERM"));
