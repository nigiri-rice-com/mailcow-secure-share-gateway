#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OmusuBI Secure Share Gateway (Active! gate 準拠 外部共有専用ゲートウェイ)
- 社内アカウント不要・受信者メールOTP認証 (OWASP準拠)
- 複数添付ファイルの一括バンドル管理 & 単一URL集約
- 一括Zipストリーミングダウンロード & 個別ファイルプレビュー/ダウンロード
- 保存ファイルの AES-256-GCM 認証付き暗号化 & 鍵管理分離 (DEK/KEK)
- 送信一時保留中のワンクリック送信取り消しハンドラ (/outbound/cancel/{token})
- Cloudreve / Samba 共有領域のフォルダ共有 (パターンB) サポート
- 60日間有効期限 & 短命セッション (HttpOnly / Secure Cookie)
"""

import os
import io
import re
import sys
import time
import json
import hmac
import zipfile
import secrets
import hashlib
import asyncio
import logging
import tempfile
import urllib.parse
import subprocess
import html
import mimetypes
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from pathlib import Path
import gzip
import xml.etree.ElementTree as ET

from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === 設定 ===
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10029
PUBLIC_BASE_URL = "https://fs.nigiri-rice.com"
STORAGE_DIR = "/srv/secure-shares"
PENDING_DIR = "/srv/secure-shares/pending"
KEY_PATH = "/etc/mailcow-secure-share/master.key"
LOG_PATH = "/var/log/mailcow-secure-share/gateway.log"

CHUNK_SIZE = 64 * 1024  # 64 KB
OTP_EXPIRY_SECONDS = 600  # 10分
OTP_RESEND_COOLDOWN = 60  # 60秒
OTP_MAX_ATTEMPTS = 5      # 最大5回試行
SESSION_EXPIRY_SECONDS = 3600  # 1時間
EXPIRE_DAYS = 60

# ロギング設定 (平文OTPや秘密鍵の出力を完全禁止)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SecureShare] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding="utf-8")
    ]
)
logger = logging.getLogger("SecureShare")

# メモリ内チャレンジキャッシュ: token:email_hash -> {hmac, expires_at, attempts, last_sent_at}
otp_challenges = {}
# IP/受信者レートリミット: key -> [timestamps]
rate_limits = {}

def get_master_key() -> bytes:
    if not os.path.exists(KEY_PATH):
        raise RuntimeError(f"Master key file not found: {KEY_PATH}")
    with open(KEY_PATH, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise RuntimeError("Master key must be exactly 32 bytes (256-bit)")
    return key

def hash_recipient(email_addr: str, salt: bytes) -> str:
    norm = email_addr.strip().lower()
    return hashlib.sha256(salt + norm.encode("utf-8")).hexdigest()

def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def get_file_icon(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return "📄"
    elif any(lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".tiff", ".tif", ".ico"]):
        return "🖼️"
    elif any(lower.endswith(ext) for ext in [".obj", ".stl", ".gltf", ".glb", ".ply", ".3mf"]):
        return "🧊"
    elif any(lower.endswith(ext) for ext in [".csv", ".tsv"]):
        return "📋"
    elif any(lower.endswith(ext) for ext in [".md", ".markdown"]):
        return "📝"
    elif any(lower.endswith(ext) for ext in [".tex", ".latex", ".bib"]):
        return "📐"
    elif lower.endswith(".ai"):
        return "🎨"
    elif lower.endswith(".psd"):
        return "🖼️"
    elif any(lower.endswith(ext) for ext in [".indd", ".idml"]):
        return "📰"
    elif lower.endswith(".prproj"):
        return "🎬"
    elif lower.endswith(".aep"):
        return "✨"
    elif any(lower.endswith(ext) for ext in [".mp4", ".mov", ".webm", ".m4v"]):
        return "🎥"
    elif any(lower.endswith(ext) for ext in [".mp3", ".wav", ".m4a", ".aac", ".ogg", ".flac"]):
        return "🎵"
    elif any(lower.endswith(ext) for ext in [".docx", ".doc"]):
        return "📘"
    elif any(lower.endswith(ext) for ext in [".xlsx", ".xls"]):
        return "📊"
    elif any(lower.endswith(ext) for ext in [".pptx", ".ppt"]):
        return "📙"
    elif any(lower.endswith(ext) for ext in [".zip", ".tar", ".gz", ".7z", ".rar"]):
        return "📦"
    elif any(lower.endswith(ext) for ext in [".json", ".xml", ".yaml", ".yml", ".sql", ".py", ".js", ".sh", ".css", ".html"]):
        return "💻"
    elif any(lower.endswith(ext) for ext in [".txt", ".log"]):
        return "📃"
    else:
        return "📎"

PREVIEWABLE_EXTS = [
    # ドキュメント & PDF & Office
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    # 画像 (全般)
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".tiff", ".tif", ".ico",
    # 3Dモデルデータ
    ".obj", ".stl", ".gltf", ".glb", ".ply", ".3mf",
    # データ & 表計算 & 構造化ドキュメント
    ".csv", ".tsv", ".md", ".markdown", ".tex", ".latex", ".bib",
    # Adobe Creative Cloud
    ".ai", ".psd", ".indd", ".idml", ".prproj", ".aep",
    # 映像・音声メディア
    ".mp4", ".mov", ".webm", ".m4v", ".mp3", ".wav", ".m4a", ".aac", ".ogg", ".flac",
    # テキスト & コード
    ".txt", ".log", ".json", ".xml", ".yaml", ".yml", ".sql", ".py", ".js", ".sh", ".css", ".html"
]

def is_previewable(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in PREVIEWABLE_EXTS)

# === 復号エンジン ===

def decrypt_file_chunks(enc_path: str, file_meta: dict, kek: bytes):
    """AES-256-GCM チャンク復号ジェネレータ"""
    kek_aesgcm = AESGCM(kek)
    dek_nonce = bytes.fromhex(file_meta["dek_nonce"])
    encrypted_dek = bytes.fromhex(file_meta["encrypted_dek"])
    dek = kek_aesgcm.decrypt(dek_nonce, encrypted_dek, b"DEK_WRAP")

    dek_aesgcm = AESGCM(dek)
    chunk_size = file_meta.get("chunk_size", CHUNK_SIZE)
    total_chunks = file_meta["total_chunks"]

    with open(enc_path, "rb") as f:
        file_nonce_prefix = f.read(8)
        header_chunks = int.from_bytes(f.read(4), byteorder="big")
        
        for chunk_index in range(total_chunks):
            chunk_nonce = file_nonce_prefix + chunk_index.to_bytes(4, byteorder="big")
            aad = chunk_index.to_bytes(4, byteorder="big")
            
            is_last = (chunk_index == total_chunks - 1)
            if not is_last:
                enc_chunk = f.read(chunk_size + 16)
            else:
                enc_chunk = f.read()
                
            plain_chunk = dek_aesgcm.decrypt(chunk_nonce, enc_chunk, aad)
            yield plain_chunk

def try_import_from_nextcloud(token: str) -> dict | None:
    """Nextcloudに存在する旧共有トークンのファイルを自動インポート"""
    import urllib.request
    try:
        nc_url = f"http://10.155.0.144:8080/s/{token}/download"
        req = urllib.request.Request(nc_url, headers={"User-Agent": "OmusuBISecureShareMigrator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                return None
            data = resp.read()
            cdisp = resp.headers.get("Content-Disposition", "")
            filename = "document.pdf"
            if "filename*=" in cdisp:
                m = re.search(r"filename\*=UTF-8''([^;]+)", cdisp)
                if m:
                    filename = urllib.parse.unquote(m.group(1))
            elif "filename=" in cdisp:
                m = re.search(r'filename="?([^";]+)"?', cdisp)
                if m:
                    filename = m.group(1)
            mime_type = resp.headers.get("Content-Type", "application/octet-stream")
            
            kek = get_master_key()
            dek = secrets.token_bytes(32)
            plain_sha256 = hashlib.sha256(data).hexdigest()
            kek_aesgcm = AESGCM(kek)
            dek_nonce = secrets.token_bytes(12)
            encrypted_dek = kek_aesgcm.encrypt(dek_nonce, dek, b"DEK_WRAP")
            
            dek_aesgcm = AESGCM(dek)
            file_nonce_prefix = secrets.token_bytes(8)
            encrypted_chunks = []
            chunk_index = 0
            for i in range(0, len(data), CHUNK_SIZE):
                chunk = data[i:i + CHUNK_SIZE]
                chunk_nonce = file_nonce_prefix + chunk_index.to_bytes(4, byteorder="big")
                aad = chunk_index.to_bytes(4, byteorder="big")
                enc_chunk = dek_aesgcm.encrypt(chunk_nonce, chunk, aad)
                encrypted_chunks.append(enc_chunk)
                chunk_index += 1
                
            full_encrypted = file_nonce_prefix + chunk_index.to_bytes(4, byteorder="big") + b"".join(encrypted_chunks)
            enc_sha256 = hashlib.sha256(full_encrypted).hexdigest()
            
            salt = secrets.token_bytes(16)
            recipients = [
                "ichiro.shimamoto@nigiri-rice.com",
                "ichibonn0427@gmail.com",
                "i.shimamoto@mail.nigiri-rice.com",
                "241091shimamoto@gmail.com"
            ]
            recipients_hashes = [hashlib.sha256(salt + r.encode("utf-8")).hexdigest() for r in recipients]
            
            meta = {
                "type": "single",
                "filename": filename,
                "size": len(data),
                "mime_type": mime_type,
                "plain_sha256": plain_sha256,
                "enc_sha256": enc_sha256,
                "chunk_size": CHUNK_SIZE,
                "total_chunks": chunk_index,
                "dek_nonce": dek_nonce.hex(),
                "encrypted_dek": encrypted_dek.hex(),
                "recipient_salt": salt.hex(),
                "recipients_hashes": recipients_hashes,
                "created_at": datetime.now().isoformat(),
                "expire_days": EXPIRE_DAYS,
                "migrated_from_nextcloud": True
            }
            
            os.makedirs(STORAGE_DIR, exist_ok=True)
            with open(os.path.join(STORAGE_DIR, f"{token}.enc"), "wb") as f:
                f.write(full_encrypted)
            with open(os.path.join(STORAGE_DIR, f"{token}.meta"), "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Successfully migrated old Nextcloud share token {token} ({filename}) to AES-256-GCM secure storage")
            return meta
    except Exception as e:
        logger.error(f"Failed to migrate Nextcloud token {token}: {e}")
        return None

def get_normalized_metadata(token: str) -> dict | None:
    """単一ファイル、複数バンドル、フォルダ共有を共通のデータモデルに正規化して返す"""
    meta_path = os.path.join(STORAGE_DIR, f"{token}.meta")
    if not os.path.exists(meta_path):
        raw_meta = try_import_from_nextcloud(token)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                raw_meta = json.load(f)
        except Exception as e:
            logger.error(f"Error reading metadata for {token}: {e}")
            return None

    if not raw_meta:
        return None

    share_type = raw_meta.get("type", "single")
    
    if share_type == "bundle":
        # 複数添付ファイルバンドル
        files = raw_meta.get("files", [])
        total_size = raw_meta.get("total_size", sum(f.get("size", 0) for f in files))
        title = raw_meta.get("subject") or f"添付ファイル（{len(files)}件）"
        return {
            **raw_meta,
            "token": token,
            "type": "bundle",
            "title": title,
            "files": files,
            "total_size": total_size
        }
    elif share_type == "folder":
        # フォルダ共有 (パターンB)
        folder_path = raw_meta.get("folder_path", "")
        folder_name = raw_meta.get("folder_name", os.path.basename(folder_path))
        files = []
        total_size = 0
        if os.path.isdir(folder_path):
            file_idx = 0
            for root, _, filenames in os.walk(folder_path):
                for fname in sorted(filenames):
                    abs_fpath = os.path.join(root, fname)
                    rel_fpath = os.path.relpath(abs_fpath, folder_path)
                    try:
                        st = os.stat(abs_fpath)
                        fsize = st.st_size
                        total_size += fsize
                        import mimetypes
                        mime, _ = mimetypes.guess_type(fname)
                        files.append({
                            "id": str(file_idx),
                            "filename": rel_fpath.replace("\\", "/"),
                            "size": fsize,
                            "mime_type": mime or "application/octet-stream",
                            "abs_path": abs_fpath,
                            "is_local_file": True
                        })
                        file_idx += 1
                    except Exception:
                        pass
        return {
            **raw_meta,
            "token": token,
            "type": "folder",
            "title": f"共有フォルダ: {folder_name}",
            "files": files,
            "total_size": total_size
        }
    else:
        # 単一ファイル（旧形式または1ファイル共有）
        filename = raw_meta.get("filename", "file")
        size = raw_meta.get("size", 0)
        mime_type = raw_meta.get("mime_type", "application/octet-stream")
        enc_file = raw_meta.get("enc_file", f"{token}.enc")
        
        file_obj = {
            "id": "0",
            "filename": filename,
            "size": size,
            "mime_type": mime_type,
            "plain_sha256": raw_meta.get("plain_sha256", ""),
            "enc_file": enc_file,
            "chunk_size": raw_meta.get("chunk_size", CHUNK_SIZE),
            "total_chunks": raw_meta.get("total_chunks", 1),
            "dek_nonce": raw_meta.get("dek_nonce"),
            "encrypted_dek": raw_meta.get("encrypted_dek")
        }
        return {
            **raw_meta,
            "token": token,
            "type": "single",
            "title": filename,
            "files": [file_obj],
            "total_size": size
        }

def is_share_expired(meta: dict) -> bool:
    created_at = meta.get("created_at")
    expire_days = meta.get("expire_days", EXPIRE_DAYS)
    if not created_at:
        return False
    try:
        created_dt = datetime.fromisoformat(created_at)
        return datetime.now() > created_dt + timedelta(days=expire_days)
    except Exception:
        return False

# === セッション管理 ===

def create_session_token(token: str, email_hash: str, kek: bytes) -> str:
    expires_at = int(time.time()) + SESSION_EXPIRY_SECONDS
    session_id = secrets.token_hex(16)
    payload = f"{token}:{email_hash}:{expires_at}:{session_id}"
    signature = hmac.new(kek, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"

def verify_session_token(cookie_val: str, expected_token: str, kek: bytes) -> str | None:
    if not cookie_val:
        return None
    parts = cookie_val.split(":")
    if len(parts) != 5:
        return None
    token, email_hash, exp_str, session_id, sig = parts
    if token != expected_token:
        return None
    try:
        exp = int(exp_str)
        if time.time() > exp:
            return None
    except ValueError:
        return None
        
    payload = f"{token}:{email_hash}:{exp_str}:{session_id}"
    expected_sig = hmac.new(kek, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
        
    return email_hash

# === メール送信 (OTP通知) ===

def send_otp_email(to_addr: str, otp_code: str, title: str, file_count: int = 1):
    """Postfixへ直接投入して8桁OTPを即時配送 (X-OmusuBI-Bypass付き)"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "【OmusuBI】ファイル確認コード（有効期限10分）"
    msg["From"] = "no-reply@mail.nigiri-rice.com"
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="mail.nigiri-rice.com")
    msg["X-OmusuBI-Bypass"] = "true"  # フィルター遅延・リンク化を完全バイパス

    count_str = f"（計 {file_count} 件）" if file_count > 1 else ""

    text_body = f"""OmusuBI 安全ファイル共有をご利用いただきありがとうございます。

添付ファイル「{title}」{count_str} の閲覧・ダウンロードに必要な確認コードをお送りいたします。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ 確認コード（8桁）:  {otp_code}
■ 有効期限: 10分間（1回のみ有効）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

※ ブラウザの確認コード入力欄に上記8桁の数字を入力してください。
※ お心当たりのない場合は、このメールを破棄してください。
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1f2937; padding: 20px;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 28px;">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid #2563eb; padding-bottom: 12px;">
      <span style="font-size: 24px;">🔒</span>
      <h2 style="margin: 0; color: #1e3a8a; font-size: 18px;">OmusuBI 安全ファイル共有 確認コード</h2>
    </div>
    <p style="font-size: 14px; margin-bottom: 16px;">
      添付ファイル <strong>「{title}」{count_str}</strong> の閲覧・ダウンロードに必要な確認コードを発行いたしました。
    </p>
    <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
      <div style="font-size: 13px; color: #64748b; margin-bottom: 6px;">確認コード（8桁）</div>
      <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #1e293b; font-family: monospace;">{otp_code}</div>
      <div style="font-size: 12px; color: #ef4444; margin-top: 6px;">※ 有効期限: 10分間（単回使用）</div>
    </div>
    <p style="font-size: 13px; color: #4b5563; margin-top: 20px;">
      ブラウザの確認コード入力画面に上記の8桁コードを入力して認証を完了してください。<br>
      お心当たりのない場合は、本メールを破棄してください。
    </p>
  </div>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    cmd = [
        "docker", "exec", "-i", "mailcowdockerized-postfix-mailcow-1",
        "/usr/sbin/sendmail", "-i", "-f", "no-reply@mail.nigiri-rice.com", "--", to_addr
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=msg.as_bytes())
    if proc.returncode != 0:
        err_msg = err.decode("utf-8", errors="replace")
        logger.error(f"Failed to send OTP email via postfix sendmail: {err_msg}")
        raise RuntimeError(f"Postfix sendmail error: {err_msg}")
    logger.info(f"OTP verification email successfully sent to {to_addr} (Message-ID: {msg['Message-ID']})")

# === HTML テンプレート生成 ===

def render_page(token: str, meta: dict, step: str = "email", error_msg: str = "", success_msg: str = "", email_val: str = "", is_authenticated: bool = False):
    title = meta["title"]
    files = meta.get("files", [])
    total_size = meta.get("total_size", 0)
    total_size_str = format_size(total_size)
    file_count = len(files)
    
    created_dt = datetime.fromisoformat(meta.get("created_at", datetime.now().isoformat()))
    expire_dt = created_dt + timedelta(days=meta.get("expire_days", EXPIRE_DAYS))
    days_left = max(0, (expire_dt - datetime.now()).days)

    if is_share_expired(meta):
        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>リンク期限切れ - OmusuBI 安全ファイル共有</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background: #f3f4f6; color: #1f2937; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
    .card {{ background: #fff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 480px; width: 100%; padding: 32px; text-align: center; }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 20px; color: #dc2626; margin: 0 0 12px; }}
    p {{ font-size: 14px; color: #4b5563; line-height: 1.6; margin: 0 0 20px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⌛</div>
    <h1>共有リンクの有効期限が切れています</h1>
    <p>この添付ファイル（<strong>{title}</strong>）の共有有効期限（60日間）が終了したか、送信者により失効されました。<br><br>ファイルが必要な場合は、メールの送信者へ再送をご依頼ください。</p>
  </div>
</body>
</html>"""

    # スタイル定義
    style = """
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 0; min-height: 100vh; display: flex; flex-direction: column; }
    .header { background: #ffffff; border-bottom: 1px solid #e2e8f0; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
    .logo { display: flex; align-items: center; gap: 10px; font-weight: bold; font-size: 16px; color: #0f172a; }
    .container { flex: 1; max-width: 960px; width: 100%; margin: 32px auto; padding: 0 16px; }
    .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); padding: 28px; }
    .summary-box { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; padding: 20px; background: #f1f5f9; border-radius: 10px; margin-bottom: 24px; }
    .summary-title { font-weight: bold; font-size: 18px; color: #0f172a; word-break: break-all; margin-bottom: 6px; }
    .summary-meta { font-size: 13px; color: #64748b; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; background: #e0f2fe; color: #0369a1; }
    .badge-count { background: #dcfce7; color: #166534; }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 600; text-decoration: none; cursor: pointer; border: none; transition: background 0.15s, transform 0.05s; }
    .btn:active { transform: scale(0.98); }
    .btn-primary { background: #2563eb; color: #ffffff; }
    .btn-primary:hover { background: #1d4ed8; }
    .btn-success { background: #059669; color: #ffffff; }
    .btn-success:hover { background: #047857; }
    .btn-secondary { background: #e2e8f0; color: #334155; }
    .btn-secondary:hover { background: #cbd5e1; }
    .btn-warning { background: #f59e0b; color: #ffffff; }
    .btn-warning:hover { background: #d97706; }
    .btn-outline { background: #ffffff; color: #0284c7; border: 1px solid #0284c7; }
    .btn-outline:hover { background: #f0f9ff; }
    .zip-table th { background: #f1f5f9; padding: 6px 10px; font-weight: 600; color: #475569; }
    .zip-table td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; }

    .btn-sm { padding: 6px 14px; font-size: 13px; border-radius: 6px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 8px; color: #334155; }
    .form-control { width: 100%; padding: 12px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 15px; }
    .form-control:focus { outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
    .alert-error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; }
    .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; }
    
    /* ファイルテーブル */
    .file-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    .file-table th { text-align: left; padding: 12px 16px; background: #f8fafc; color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase; border-bottom: 1px solid #e2e8f0; }
    .file-table td { padding: 16px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }
    .file-table tr:hover { background: #f8fafc; }
    .file-cell { display: flex; align-items: center; gap: 12px; }
    .file-icon { font-size: 26px; }
    .file-title { font-weight: 600; font-size: 14px; color: #1e293b; word-break: break-all; }
    .file-actions { display: flex; gap: 8px; justify-content: flex-end; }
    
    /* スプリットビュー & レイアウトコンテナ */
    .container { flex: 1; max-width: 980px; width: 100%; margin: 28px auto; padding: 0 16px; transition: max-width 0.25s ease-in-out; }
    .container.has-preview { max-width: 1560px; }
    .main-layout { display: flex; flex-direction: column; gap: 24px; width: 100%; }

    @media (min-width: 1024px) {
      .main-layout.has-preview {
        display: grid;
        grid-template-columns: minmax(420px, 480px) minmax(560px, 1fr);
        align-items: start;
        gap: 24px;
      }
      .files-card {
        position: sticky;
        top: 20px;
      }
      .preview-card {
        position: sticky;
        top: 20px;
        max-height: calc(100vh - 40px);
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .preview-body {
        flex: 1;
        overflow-y: auto;
      }
      .preview-body iframe {
        height: calc(100vh - 120px) !important;
        min-height: 600px;
      }
    }

    @media (max-width: 1023px) {
      .preview-card {
        margin-top: 16px;
      }
      .preview-body iframe {
        height: 550px;
      }
    }

    .file-row-active {
      background-color: #eff6ff !important;
      border-left: 3px solid #2563eb;
    }

    /* プレビューコンテナ */
    .preview-card { border: 1px solid #cbd5e1; border-radius: 12px; overflow: hidden; background: #ffffff; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.08); padding: 0; }
    .preview-header { padding: 12px 18px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .preview-header-title { font-weight: 600; font-size: 14px; color: #1e293b; display: flex; align-items: center; gap: 8px; min-width: 0; }
    #preview-filename-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .preview-body { min-height: 480px; display: flex; align-items: center; justify-content: center; background: #525659; }
    .preview-body iframe { width: 100%; height: 750px; border: none; background: #fff; }
    .preview-body img { max-width: 100%; max-height: 750px; border-radius: 4px; object-fit: contain; }
    .preview-body pre { width: 100%; height: 600px; margin: 0; padding: 20px; background: #ffffff; color: #1e293b; overflow: auto; font-family: monospace; font-size: 13px; line-height: 1.5; }
.footer { text-align: center; padding: 24px; font-size: 12px; color: #94a3b8; }
    """

    err_html = f'<div class="alert-error">{error_msg}</div>' if error_msg else ""
    succ_html = f'<div class="alert-success">{success_msg}</div>' if success_msg else ""

    if is_authenticated:
        # === 認証済みポータル画面（Active! gate 準拠・一括ダウンロード ＆ 個別プレビュー） ===
        
        # 一括ダウンロードボタン
        bulk_download_btn = ""
        if file_count > 1 or meta.get("type") == "folder":
            bulk_download_btn = f"""
            <a href="/share/{token}/download-all" class="btn btn-success" style="font-size: 15px; padding: 12px 24px;">
              📦 全ファイルを一括ダウンロード ({total_size_str} .ZIP)
            </a>
            """
        elif file_count == 1:
            bulk_download_btn = f"""
            <a href="/share/{token}/file/0/download" class="btn btn-success" style="font-size: 15px; padding: 12px 24px;">
              📥 ファイルをダウンロード ({total_size_str})
            </a>
            """

        # ファイル行の生成
        rows_html = ""
        for idx, f_item in enumerate(files):
            fname = f_item.get("filename", f"file_{idx}")
            fsize = f_item.get("size", 0)
            fsize_str = format_size(fsize)
            ficon = get_file_icon(fname)
            can_prev = is_previewable(fname)
            
            preview_btn = ""
            if can_prev:
                preview_btn = f"""
                <button type="button" class="btn btn-primary btn-sm" onclick="showPreview('{idx}', this.getAttribute('data-filename'))" data-filename="{html.escape(fname, quote=True)}">
                  👁️ プレビュー
                </button>
                """
            
            is_zip = fname.lower().endswith(".zip")
            zip_btn = ""
            zip_expand_row = ""
            if is_zip:
                zip_btn = f"""
                <button type="button" class="btn btn-warning btn-sm" onclick="toggleZipContents('{idx}', '{token}', this.getAttribute('data-filename'))" data-filename="{html.escape(fname, quote=True)}">
                  📦 Zipを展開・プレビュー
                </button>
                """
                zip_expand_row = f"""
            <tr id="zip-row-{idx}" style="display: none; background-color: #f8fafc;">
              <td colspan="3" style="padding: 14px 18px; border-top: 1px dashed #cbd5e1; border-bottom: 2px solid #e2e8f0;">
                <div id="zip-container-{idx}"></div>
              </td>
            </tr>
                """
            
            download_btn = f"""
            <a href="/share/{token}/file/{idx}/download" class="btn btn-secondary btn-sm">
              ⬇️ ダウンロード
            </a>
            """
            
            rows_html += f"""
            <tr class="file-row" id="file-row-{idx}">
              <td>
                <div class="file-cell">
                  <div class="file-icon">{ficon}</div>
                  <div>
                    <div class="file-title">{html.escape(fname)}</div>
                  </div>
                </div>
              </td>
              <td style="color: #64748b; font-size: 13px; white-space: nowrap;">{fsize_str}</td>
              <td>
                <div class="file-actions">
                  {zip_btn}
                  {preview_btn}
                  {download_btn}
                </div>
              </td>
            </tr>
            {zip_expand_row}
            """

        # デフォルトでプレビュー表示するかどうかの判定（1件のみでプレビュー可能な場合）
        auto_preview_js = ""
        if file_count == 1 and is_previewable(files[0]["filename"]):
            first_fname_json = json.dumps(files[0]["filename"])
            auto_preview_js = f"showPreview('0', {first_fname_json});"

        content = f"""
        <div class="main-layout" id="main-layout">
        <div class="card files-card">
          <div class="summary-box">
            <div>
              <div class="summary-title">{title}</div>
              <div class="summary-meta">
                <span class="badge badge-count">📎 添付ファイル: {file_count} 件</span>
                <span>合計: <strong>{total_size_str}</strong></span>
                <span>有効期限: 残り <strong>{days_left} 日</strong></span>
                <span class="badge">🔒 AES-256-GCM 暗号化保護</span>
              </div>
            </div>
            <div>
              {bulk_download_btn}
            </div>
          </div>

          <table class="file-table">
            <thead>
              <tr>
                <th>ファイル名</th>
                <th>サイズ</th>
                <th style="text-align: right;">操作</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>

        <div id="preview-section" class="card preview-card" style="display: none;">
          <div class="preview-header">
            <div class="preview-header-title">
              <span>👁️</span>
              <span id="preview-filename-label">ファイルプレビュー</span>
            </div>
            <div style="display: flex; gap: 8px;">
              <a id="preview-download-link" href="#" class="btn btn-secondary btn-sm">⬇️ このファイルを保存</a>
              <button type="button" class="btn btn-secondary btn-sm" onclick="closePreview()">✕ 閉じる</button>
            </div>
          </div>
          <div id="preview-body" class="preview-body">
            <!-- 動的プレビュー読み込み領域 -->
          </div>
        </div>
        </div>

        <script>
          var currentToken = '{token}';

          function escapeHtml(str) {{
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
          }}

                    function loadScriptAsync(src) {{
            return new Promise(function(resolve, reject) {{
              if (document.querySelector('script[src="' + src + '"]')) {{
                resolve();
                return;
              }}
              var s = document.createElement('script');
              s.src = src;
              s.onload = resolve;
              s.onerror = reject;
              document.head.appendChild(s);
            }});
          }}

          function render3DModelViewer(container, url, filename) {{
            container.innerHTML = '<div id="canvas-3d-wrap" style="position:relative; width:100%; height:650px; background:radial-gradient(circle at center, #1e293b 0%, #0f172a 100%); overflow:hidden; border-radius:6px;">' +
              '<div id="loading-3d" style="position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); color:#cbd5e1; font-size:14px; text-align:center; z-index:20;">' +
                '<div style="font-size:36px; margin-bottom:12px;">🧊</div>3Dモデルを読み込み中...' +
              '</div>' +
              '<div style="position:absolute; bottom:14px; left:16px; background:rgba(15,23,42,0.85); backdrop-filter:blur(4px); padding:8px 16px; border-radius:20px; border:1px solid #334155; font-size:12px; color:#cbd5e1; pointer-events:none; z-index:15;">' +
                '🖱️ <strong>左ドラッグ</strong>: 360度回転 &nbsp;|&nbsp; <strong>ホイール</strong>: ズーム &nbsp;|&nbsp; <strong>右ドラッグ</strong>: 平行移動' +
              '</div>' +
              '<div style="position:absolute; top:14px; right:16px; z-index:15;">' +
                '<button id="btn-reset-3d" class="btn btn-secondary btn-sm" style="background:rgba(30,41,59,0.85); border:1px solid #475569; color:#f8fafc; font-size:11px; padding:5px 12px; border-radius:6px; cursor:pointer;">🔄 視点リセット</button>' +
              '</div>' +
            '</div>';

            var wrap = document.getElementById('canvas-3d-wrap');
            var loading = document.getElementById('loading-3d');
            var lower = filename.toLowerCase();

            loadScriptAsync('https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js')
              .then(function() {{
                return loadScriptAsync('https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js');
              }})
              .then(function() {{
                if (lower.endsWith('.stl')) {{
                  return loadScriptAsync('https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/STLLoader.js');
                }} else if (lower.endsWith('.obj')) {{
                  return loadScriptAsync('https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/OBJLoader.js');
                }} else if (lower.endsWith('.ply')) {{
                  return loadScriptAsync('https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/PLYLoader.js');
                }} else if (lower.endsWith('.gltf') || lower.endsWith('.glb')) {{
                  return loadScriptAsync('https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/GLTFLoader.js');
                }}
                return Promise.resolve();
              }})
              .then(function() {{
                var width = wrap.clientWidth || 800;
                var height = wrap.clientHeight || 650;

                var scene = new THREE.Scene();
                var camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
                var renderer = new THREE.WebGLRenderer({{ antialias: true, alpha: true }});
                renderer.setSize(width, height);
                renderer.setPixelRatio(window.devicePixelRatio || 1);
                renderer.outputEncoding = THREE.sRGBEncoding;
                wrap.appendChild(renderer.domElement);

                var controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;

                var ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
                scene.add(ambientLight);

                var dirLight1 = new THREE.DirectionalLight(0xffffff, 0.8);
                dirLight1.position.set(1, 1, 1).normalize();
                scene.add(dirLight1);

                var dirLight2 = new THREE.DirectionalLight(0x38bdf8, 0.4);
                dirLight2.position.set(-1, -1, -1).normalize();
                scene.add(dirLight2);

                var grid = new THREE.GridHelper(100, 20, 0x475569, 0x1e293b);
                scene.add(grid);

                function fitCameraToMesh(object) {{
                  var box = new THREE.Box3().setFromObject(object);
                  var size = box.getSize(new THREE.Vector3());
                  var center = box.getCenter(new THREE.Vector3());
                  object.position.sub(center);
                  var maxDim = Math.max(size.x, size.y, size.z);
                  var fov = camera.fov * (Math.PI / 180);
                  var cameraZ = Math.abs(maxDim / 2 / Math.tan(fov / 2)) * 1.8;
                  camera.position.set(maxDim * 0.8, maxDim * 0.8, cameraZ);
                  camera.lookAt(0, 0, 0);
                  controls.target.set(0, 0, 0);
                  controls.update();
                  grid.position.y = -size.y / 2;
                }}

                var material = new THREE.MeshStandardMaterial({{
                  color: 0x93c5fd,
                  roughness: 0.35,
                  metalness: 0.2
                }});

                function on3DError() {{
                  if (loading) loading.innerHTML = '<div style="color:#ef4444;">3Dモデルの解析に失敗しました。</div>';
                }}

                if (lower.endsWith('.stl')) {{
                  var loader = new THREE.STLLoader();
                  loader.load(url, function(geometry) {{
                    geometry.computeVertexNormals();
                    var mesh = new THREE.Mesh(geometry, material);
                    scene.add(mesh);
                    fitCameraToMesh(mesh);
                    if (loading) loading.style.display = 'none';
                  }}, undefined, on3DError);
                }} else if (lower.endsWith('.obj')) {{
                  var loader = new THREE.OBJLoader();
                  loader.load(url, function(obj) {{
                    obj.traverse(function(child) {{
                      if (child.isMesh) child.material = material;
                    }});
                    scene.add(obj);
                    fitCameraToMesh(obj);
                    if (loading) loading.style.display = 'none';
                  }}, undefined, on3DError);
                }} else if (lower.endsWith('.ply')) {{
                  var loader = new THREE.PLYLoader();
                  loader.load(url, function(geometry) {{
                    geometry.computeVertexNormals();
                    var mesh = new THREE.Mesh(geometry, material);
                    scene.add(mesh);
                    fitCameraToMesh(mesh);
                    if (loading) loading.style.display = 'none';
                  }}, undefined, on3DError);
                }} else if (lower.endsWith('.gltf') || lower.endsWith('.glb')) {{
                  var loader = new THREE.GLTFLoader();
                  loader.load(url, function(gltf) {{
                    scene.add(gltf.scene);
                    fitCameraToMesh(gltf.scene);
                    if (loading) loading.style.display = 'none';
                  }}, undefined, on3DError);
                }}

                document.getElementById('btn-reset-3d').onclick = function() {{
                  controls.reset();
                }};

                function animate() {{
                  requestAnimationFrame(animate);
                  controls.update();
                  renderer.render(scene, camera);
                }}
                animate();
              }})
              .catch(function(err) {{
                if (loading) loading.innerHTML = '<div style="color:#ef4444;">3Dビューアの初期化に失敗しました。</div>';
              }});
          }}

          function renderCsvTable(container, url, filename) {{
            fetch(url)
              .then(function(res) {{ return res.text(); }})
              .then(function(text) {{
                var isTsv = filename.toLowerCase().endsWith('.tsv');
                var delimiter = isTsv ? '	' : ',';
                var lines = text.replace(new RegExp(String.fromCharCode(13), 'g'), '').split(String.fromCharCode(10));
                if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {{
                  container.innerHTML = '<div style="padding:40px; text-align:center; color:#64748b;">データが空です</div>';
                  return;
                }}

                function parseRow(rowStr) {{
                  var row = [];
                  var inQuotes = false;
                  var curVal = '';
                  for (var i = 0; i < rowStr.length; i++) {{
                    var c = rowStr[i];
                    if (c === '"') {{
                      if (inQuotes && rowStr[i+1] === '"') {{ curVal += '"'; i++; }}
                      else {{ inQuotes = !inQuotes; }}
                    }} else if (c === delimiter && !inQuotes) {{
                      row.push(curVal);
                      curVal = '';
                    }} else {{
                      curVal += c;
                    }}
                  }}
                  row.push(curVal);
                  return row;
                }}

                var header = parseRow(lines[0]);
                var rows = [];
                for (var j = 1; j < lines.length; j++) {{
                  if (lines[j].trim()) {{
                    rows.push(parseRow(lines[j]));
                  }}
                }}

                var tableId = 'csv-tbl-' + Math.random().toString(36).substr(2, 9);
                var html = '<div style="background:#ffffff; border-radius:8px; padding:18px; width:100%; box-shadow:0 1px 3px rgba(0,0,0,0.05);">' +
                  '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; gap:12px; flex-wrap:wrap;">' +
                    '<div style="font-size:13px; color:#475569;">' +
                      '📋 <strong>' + escapeHtml(filename) + '</strong> &nbsp;|&nbsp; ' +
                      '<span id="row-count-' + tableId + '" style="color:#059669; font-weight:600;">全 ' + rows.length + ' 行</span>' +
                    '</div>' +
                    '<div style="position:relative; width:280px;">' +
                      '<input type="text" id="search-' + tableId + '" placeholder="🔍 テーブル内をリアルタイム検索..." style="width:100%; padding:7px 12px; border:1px solid #cbd5e1; border-radius:6px; font-size:12px; outline:none;">' +
                    '</div>' +
                  '</div>' +
                  '<div style="max-height:600px; overflow:auto; border:1px solid #e2e8f0; border-radius:6px;">' +
                    '<table id="' + tableId + '" style="width:100%; border-collapse:collapse; font-size:12px; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;">' +
                      '<thead style="position:sticky; top:0; background:#f1f5f9; z-index:10; box-shadow:0 1px 2px rgba(0,0,0,0.05);">' +
                        '<tr>' +
                          header.map(function(h) {{ return '<th style="padding:10px 12px; border-bottom:2px solid #cbd5e1; text-align:left; color:#334155; font-weight:600; white-space:nowrap;">' + escapeHtml(h) + '</th>'; }}).join('') +
                        '</tr>' +
                      '</thead>' +
                      '<tbody>';

                rows.forEach(function(r, idx) {{
                  var bg = (idx % 2 === 0) ? '#ffffff' : '#f8fafc';
                  html += '<tr style="background:' + bg + '; border-bottom:1px solid #e2e8f0;">' +
                    r.map(function(cell) {{ return '<td style="padding:8px 12px; color:#1e293b; white-space:nowrap;">' + escapeHtml(cell) + '</td>'; }}).join('') +
                  '</tr>';
                }});

                html += '</tbody></table></div></div>';
                container.innerHTML = html;

                var input = document.getElementById('search-' + tableId);
                var table = document.getElementById(tableId);
                var countLabel = document.getElementById('row-count-' + tableId);
                input.addEventListener('input', function() {{
                  var query = this.value.toLowerCase();
                  var tbodyRows = table.querySelectorAll('tbody tr');
                  var visibleCount = 0;
                  tbodyRows.forEach(function(tr) {{
                    var match = query === '' || tr.textContent.toLowerCase().indexOf(query) !== -1;
                    tr.style.display = match ? '' : 'none';
                    if (match) visibleCount++;
                  }});
                  countLabel.textContent = query ? (visibleCount + ' 行 一致 / 全 ' + rows.length + ' 行') : ('全 ' + rows.length + ' 行');
                }});
              }})
              .catch(function(err) {{
                container.innerHTML = '<div style="color:#ef4444; padding:40px;">CSVの読み込みに失敗しました。</div>';
              }});
          }}

          function renderMarkdownViewer(container, url, filename) {{
            fetch(url)
              .then(function(res) {{ return res.text(); }})
              .then(function(text) {{
                loadScriptAsync('https://cdn.jsdelivr.net/npm/marked/marked.min.js')
                  .then(function() {{
                    var html = marked.parse(text);
                    container.innerHTML = '<div class="markdown-body" style="padding:28px 36px; background:#ffffff; color:#1e293b; border-radius:8px; line-height:1.6; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; max-height:700px; overflow:auto; border:1px solid #e2e8f0;">' + html + '</div>';
                  }})
                  .catch(function() {{
                    container.innerHTML = '<pre style="padding:20px; background:#fff; font-family:monospace; font-size:13px; max-height:600px; overflow:auto;">' + escapeHtml(text) + '</pre>';
                  }});
              }})
              .catch(function() {{
                container.innerHTML = '<div style="color:#ef4444; padding:40px;">Markdownの読み込みに失敗しました。</div>';
              }});
          }}

          function renderTeXViewer(container, url, filename) {{
            fetch(url)
              .then(function(res) {{ return res.text(); }})
              .then(function(text) {{
                container.innerHTML = '<div style="background:#ffffff; border-radius:8px; padding:20px; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; border:1px solid #e2e8f0;">' +
                  '<div style="display:flex; align-items:center; gap:8px; margin-bottom:12px; padding-bottom:10px; border-bottom:1px solid #e2e8f0;">' +
                    '<span style="font-size:22px;">📐</span>' +
                    '<span style="font-weight:bold; font-size:14px; color:#1e293b;">LaTeX / TeX ドキュメントソース</span>' +
                    '<span style="font-size:12px; color:#64748b; margin-left:auto;">' + escapeHtml(filename) + '</span>' +
                  '</div>' +
                  '<pre style="background:#0f172a; color:#f8fafc; padding:20px; border-radius:6px; font-family:Consolas, Monaco, monospace; font-size:13px; line-height:1.6; max-height:600px; overflow:auto; margin:0;">' +
                    escapeHtml(text) +
                  '</pre>' +
                '</div>';
              }})
              .catch(function() {{
                container.innerHTML = '<div style="color:#ef4444; padding:40px;">TeXファイルの読み込みに失敗しました。</div>';
              }});
          }}

          function renderPreviewContent(contentUrl, filename) {{
            var body = document.getElementById('preview-body');
            var lower = filename.toLowerCase();

            body.innerHTML = '<div style="color: #cbd5e1; padding: 40px; font-size: 14px; text-align: center;"><div style="font-size: 26px; margin-bottom: 8px;">⏳</div>ドキュメント・アセットを準備中...<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">（初回変換時は数秒かかる場合があります）</div></div>';

            if (lower.endsWith('.pdf') || lower.endsWith('.docx') || lower.endsWith('.doc') || lower.endsWith('.xlsx') || lower.endsWith('.xls') || lower.endsWith('.pptx') || lower.endsWith('.ppt')) {{
              body.innerHTML = '<iframe src="' + contentUrl + '#toolbar=1" title="Document Preview" style="width: 100%; height: 750px; border: none; background: #fff;"></iframe>';
            }} else if (lower.endsWith('.stl') || lower.endsWith('.obj') || lower.endsWith('.gltf') || lower.endsWith('.glb') || lower.endsWith('.ply')) {{
              render3DModelViewer(body, contentUrl, filename);
            }} else if (lower.endsWith('.csv') || lower.endsWith('.tsv')) {{
              renderCsvTable(body, contentUrl, filename);
            }} else if (lower.endsWith('.md') || lower.endsWith('.markdown')) {{
              renderMarkdownViewer(body, contentUrl, filename);
            }} else if (lower.endsWith('.tex') || lower.endsWith('.latex') || lower.endsWith('.bib')) {{
              renderTeXViewer(body, contentUrl, filename);
            }} else if (lower.endsWith('.png') || lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.gif') || lower.endsWith('.webp') || lower.endsWith('.svg') || lower.endsWith('.bmp') || lower.endsWith('.tiff') || lower.endsWith('.tif') || lower.endsWith('.ico') || lower.endsWith('.ai') || lower.endsWith('.psd') || lower.endsWith('.idml')) {{
              var img = document.createElement('img');
              img.src = contentUrl;
              img.alt = filename;
              img.style.maxWidth = '100%';
              img.style.maxHeight = '750px';
              img.style.objectFit = 'contain';
              img.onload = function() {{
                body.innerHTML = '';
                body.appendChild(img);
              }};
              img.onerror = function() {{
                fetch(contentUrl)
                  .then(function(res) {{ return res.text(); }})
                  .then(function(data) {{
                    body.innerHTML = '<div style="width:100%; padding: 20px; background: #fff;">' + data + '</div>';
                  }})
                  .catch(function() {{
                    body.innerHTML = '<div style="color:#ef4444; padding:40px;">プレビューの読み込みに失敗しました。</div>';
                  }});
              }};
            }} else if (lower.endsWith('.mp4') || lower.endsWith('.mov') || lower.endsWith('.webm') || lower.endsWith('.m4v')) {{
              body.innerHTML = '<div style="display:flex; justify-content:center; align-items:center; width:100%; padding:20px; background:#000;"><video controls autoplay style="max-width:100%; max-height:700px; border-radius:4px;" src="' + contentUrl + '"></video></div>';
            }} else if (lower.endsWith('.mp3') || lower.endsWith('.wav') || lower.endsWith('.m4a') || lower.endsWith('.aac') || lower.endsWith('.ogg') || lower.endsWith('.flac')) {{
              body.innerHTML = '<div style="display:flex; flex-direction:column; justify-content:center; align-items:center; width:100%; padding:60px 20px; background:#f8fafc;"><div style="font-size:48px; margin-bottom:16px;">🎵</div><div style="font-weight:600; margin-bottom:16px; color:#1e293b;">' + escapeHtml(filename) + '</div><audio controls style="width:100%; max-width:480px;" src="' + contentUrl + '"></audio></div>';
            }} else if (lower.endsWith('.indd')) {{
              var img = document.createElement('img');
              img.src = contentUrl;
              img.alt = filename;
              img.style.maxWidth = '100%';
              img.style.maxHeight = '750px';
              img.style.objectFit = 'contain';
              img.onload = function() {{
                body.innerHTML = '';
                body.appendChild(img);
              }};
              img.onerror = function() {{
                fetch(contentUrl)
                  .then(function(res) {{ return res.text(); }})
                  .then(function(data) {{
                    body.innerHTML = '<div style="width:100%; padding: 20px; background: #fff;">' + data + '</div>';
                  }})
                  .catch(function() {{
                    body.innerHTML = '<div style="color:#ef4444; padding:40px;">プレビューの読み込みに失敗しました。</div>';
                  }});
              }};
            }} else if (lower.endsWith('.prproj') || lower.endsWith('.aep')) {{
              fetch(contentUrl)
                .then(function(res) {{ return res.text(); }})
                .then(function(html) {{
                  body.innerHTML = '<div style="width:100%; padding: 20px; background: #fff;">' + html + '</div>';
                }})
                .catch(function() {{
                  body.innerHTML = '<div style="color:#ef4444; padding:40px;">プロジェクト情報の解析に失敗しました。</div>';
                }});
            }} else {{
              fetch(contentUrl)
                .then(function(res) {{ return res.text(); }})
                .then(function(text) {{
                  var pre = document.createElement('pre');
                  pre.textContent = text;
                  pre.style.cssText = 'width: 100%; height: 600px; margin: 0; padding: 20px; background: #ffffff; color: #1e293b; overflow: auto; font-family: monospace; font-size: 13px; line-height: 1.5;';
                  body.innerHTML = '';
                  body.appendChild(pre);
                }})
                .catch(function() {{
                  body.innerHTML = '<div style="color:#ef4444; padding:40px;">テキストの読み込みに失敗しました。</div>';
                }});
            }}
          }}

          function showPreview(fileId, filename) {{
            var section = document.getElementById('preview-section');
            var label = document.getElementById('preview-filename-label');
            var dlLink = document.getElementById('preview-download-link');
            var layout = document.getElementById('main-layout');
            var container = document.querySelector('.container');
            
            if (layout) layout.classList.add('has-preview');
            if (container) container.classList.add('has-preview');
            
            document.querySelectorAll('.file-row').forEach(function(r) {{ r.classList.remove('file-row-active'); }});
            var activeRow = document.getElementById('file-row-' + fileId);
            if (activeRow) activeRow.classList.add('file-row-active');

            label.textContent = filename;
            dlLink.href = '/share/' + encodeURIComponent(currentToken) + '/file/' + encodeURIComponent(fileId) + '/download';
            section.style.display = 'flex';
            
            if (window.innerWidth < 1024) {{
              section.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }}
            
            var contentUrl = '/share/' + encodeURIComponent(currentToken) + '/file/' + encodeURIComponent(fileId) + '/content';
            renderPreviewContent(contentUrl, filename);
          }}

          function toggleZipContents(fileId, token, zipName) {{
            var row = document.getElementById('zip-row-' + fileId);
            var container = document.getElementById('zip-container-' + fileId);
            if (!row || !container) return;
            
            if (row.style.display !== 'none') {{
              row.style.display = 'none';
              return;
            }}
            
            row.style.display = '';
            if (container.dataset.loaded === 'true') {{
              return;
            }}
            
            container.innerHTML = '<div style="color: #64748b; font-size: 13px; padding: 10px;">📦 Zipアーカイブを解析中...</div>';
            fetch('/share/' + encodeURIComponent(token) + '/file/' + encodeURIComponent(fileId) + '/zip-tree')
              .then(function(res) {{ return res.json(); }})
              .then(function(data) {{
                if (data.error) {{
                  container.innerHTML = '<div style="color: #ef4444; font-size: 13px; padding: 8px;">' + escapeHtml(data.error) + '</div>';
                  return;
                }}
                container.dataset.loaded = 'true';
                if (!data.items || data.items.length === 0) {{
                  container.innerHTML = '<div style="color: #64748b; font-size: 13px; padding: 8px;">Zip内にファイルが見つかりませんでした。</div>';
                  return;
                }}
                
                var wrapper = document.createElement('div');
                var headerDiv = document.createElement('div');
                headerDiv.style.cssText = 'margin-bottom: 10px; font-weight: bold; font-size: 13px; color: #334155; display: flex; align-items: center; justify-content: space-between;';
                headerDiv.innerHTML = '<span>📦 ' + escapeHtml(data.zip_name) + ' の中身 (' + data.items.length + ' 件)</span><span style="font-size: 12px; color: #059669; font-weight: normal;">解凍せずに個別プレビュー・保存が可能です</span>';
                wrapper.appendChild(headerDiv);
                
                var table = document.createElement('table');
                table.className = 'zip-table';
                table.style.cssText = 'width: 100%; border-collapse: collapse; font-size: 13px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden;';
                
                var thead = document.createElement('thead');
                thead.innerHTML = '<tr><th style="padding: 8px 12px; text-align: left; background: #f1f5f9; color: #475569; font-size: 12px;">ファイルパス / 名前</th><th style="padding: 8px 12px; text-align: left; width: 110px; background: #f1f5f9; color: #475569; font-size: 12px;">サイズ</th><th style="padding: 8px 12px; text-align: right; width: 200px; background: #f1f5f9; color: #475569; font-size: 12px;">操作</th></tr>';
                table.appendChild(thead);
                
                var tbody = document.createElement('tbody');
                data.items.forEach(function(item) {{
                  var tr = document.createElement('tr');
                  tr.style.borderTop = '1px solid #e2e8f0';
                  
                  var tdName = document.createElement('td');
                  tdName.style.cssText = 'padding: 8px 12px; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;';
                  tdName.textContent = item.icon + ' ' + item.filename;
                  tr.appendChild(tdName);
                  
                  var tdSize = document.createElement('td');
                  tdSize.style.cssText = 'padding: 8px 12px; color: #64748b; white-space: nowrap;';
                  tdSize.textContent = item.size_str;
                  tr.appendChild(tdSize);
                  
                  var tdActions = document.createElement('td');
                  tdActions.style.cssText = 'padding: 8px 12px; text-align: right; white-space: nowrap;';
                  
                  if (item.previewable) {{
                    var btnPrev = document.createElement('button');
                    btnPrev.type = 'button';
                    btnPrev.className = 'btn btn-primary btn-sm';
                    btnPrev.style.cssText = 'font-size: 12px; padding: 3px 8px; margin-right: 6px;';
                    btnPrev.textContent = '👁️ プレビュー';
                    btnPrev.onclick = function() {{
                      showZipPreview(fileId, item.entry_id, item.filename, token);
                    }};
                    tdActions.appendChild(btnPrev);
                  }}
                  
                  var aDl = document.createElement('a');
                  aDl.href = '/share/' + encodeURIComponent(token) + '/file/' + encodeURIComponent(fileId) + '/zip-file/' + encodeURIComponent(item.entry_id) + '?download=1';
                  aDl.className = 'btn btn-secondary btn-sm';
                  aDl.style.cssText = 'font-size: 12px; padding: 3px 8px; text-decoration: none;';
                  aDl.textContent = '⬇️ 保存';
                  tdActions.appendChild(aDl);
                  
                  tr.appendChild(tdActions);
                  tbody.appendChild(tr);
                }});
                
                table.appendChild(tbody);
                wrapper.appendChild(table);
                container.innerHTML = '';
                container.appendChild(wrapper);
              }})
              .catch(function(err) {{
                container.innerHTML = '<div style="color: #ef4444; font-size: 13px; padding: 8px;">解析エラーが発生しました。</div>';
              }});
          }}

                    function showZipPreview(fileId, entryId, filename, token) {{
            var section = document.getElementById('preview-section');
            var label = document.getElementById('preview-filename-label');
            var dlLink = document.getElementById('preview-download-link');
            
            label.textContent = filename + ' (Zip内)';
            dlLink.href = '/share/' + encodeURIComponent(token) + '/file/' + encodeURIComponent(fileId) + '/zip-file/' + encodeURIComponent(entryId) + '?download=1';
            section.style.display = 'block';
            section.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            
            var contentUrl = '/share/' + encodeURIComponent(token) + '/file/' + encodeURIComponent(fileId) + '/zip-file/' + encodeURIComponent(entryId) + '?preview=1';
            renderPreviewContent(contentUrl, filename);
          }}

          function closePreview() {{
            var section = document.getElementById('preview-section');
            var layout = document.getElementById('main-layout');
            var container = document.querySelector('.container');
            
            if (layout) layout.classList.remove('has-preview');
            if (container) container.classList.remove('has-preview');
            document.querySelectorAll('.file-row').forEach(function(r) {{ r.classList.remove('file-row-active'); }});

            if (section) section.style.display = 'none';
            document.getElementById('preview-body').innerHTML = '';
          }}

          window.addEventListener('DOMContentLoaded', function() {{
            {auto_preview_js}
          }});
        </script>
        """
    elif step == "otp":
        # === ステップ2: 8桁確認コード入力画面 ===
        content = f"""
        <div class="card" style="max-width: 520px; margin: 0 auto;">
          <div class="summary-box" style="margin-bottom: 20px; padding: 14px 18px;">
            <div style="font-size: 28px;">🔒</div>
            <div style="flex: 1;">
              <div style="font-weight: bold; font-size: 15px; color: #0f172a;">{title}</div>
              <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
                ファイル: {file_count} 件 ({total_size_str}) &nbsp;|&nbsp; 期限: 残り{days_left}日
              </div>
            </div>
          </div>
          {err_html}
          {succ_html}
          <div style="text-align: center; margin-bottom: 24px;">
            <div style="font-size: 32px; margin-bottom: 8px;">✉️</div>
            <h2 style="font-size: 18px; margin: 0 0 8px; color: #0f172a;">確認コードを入力してください</h2>
            <p style="font-size: 13px; color: #64748b; margin: 0; line-height: 1.5;">
              <strong>{email_val}</strong> 宛てに送信された<br>8桁の確認コード（有効期限10分）を入力してください。
            </p>
          </div>
          <form method="POST" action="/share/{token}/api/verify-otp">
            <input type="hidden" name="email" value="{email_val}">
            <div class="form-group">
              <input type="text" name="otp" class="form-control" placeholder="12345678" maxlength="8" pattern="[0-9]{{8}}" inputmode="numeric" autocomplete="one-time-code" style="font-size: 24px; text-align: center; letter-spacing: 6px; font-weight: bold;" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; font-size: 15px;">認証してファイルを開く</button>
          </form>
          <div style="text-align: center; margin-top: 20px; padding-top: 16px; border-top: 1px dashed #e2e8f0;">
            <form method="POST" action="/share/{token}/api/request-otp" style="display: inline;">
              <input type="hidden" name="email" value="{email_val}">
              <button type="submit" class="btn btn-secondary" style="font-size: 12px; padding: 6px 14px;">コードを再送する</button>
            </form>
            &nbsp;
            <a href="/share/{token}" style="font-size: 12px; color: #64748b; text-decoration: underline;">メールアドレスを変更</a>
          </div>
        </div>
        """
    else:
        # === ステップ1: メールアドレス入力画面 (社内アカウント不要) ===
        content = f"""
        <div class="card" style="max-width: 520px; margin: 0 auto;">
          <div class="summary-box" style="margin-bottom: 20px; padding: 14px 18px;">
            <div style="font-size: 28px;">📎</div>
            <div style="flex: 1;">
              <div style="font-weight: bold; font-size: 15px; color: #0f172a;">{title}</div>
              <div style="font-size: 12px; color: #64748b; margin-top: 2px;">
                ファイル: {file_count} 件 ({total_size_str}) &nbsp;|&nbsp; 期限: 残り{days_left}日
              </div>
            </div>
          </div>
          {err_html}
          {succ_html}
          <div style="margin-bottom: 20px;">
            <h2 style="font-size: 18px; margin: 0 0 8px; color: #0f172a;">メールアドレスの確認</h2>
            <p style="font-size: 13px; color: #64748b; margin: 0; line-height: 1.6;">
              <strong>社内アカウントの登録は不要です。</strong><br>
              このメールを受信したメールアドレスを入力してください。ご本人様確認用のワンタイムコード（8桁）をお送りします。
            </p>
          </div>
          <form method="POST" action="/share/{token}/api/request-otp">
            <div class="form-group">
              <label for="email">受信したメールアドレス</label>
              <input type="email" id="email" name="email" class="form-control" placeholder="name@example.com" value="{email_val}" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; font-size: 15px;">確認コードを送信</button>
          </form>
          <div style="margin-top: 24px; padding: 12px 16px; background: #f8fafc; border-radius: 8px; font-size: 12px; color: #64748b; line-height: 1.6;">
            🔒 添付ファイルは AES-256-GCM により暗号化保護されています。正しい受信者の方のみ復号・ダウンロードが可能です。
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - OmusuBI 安全ファイル共有</title>
  <style>{style}</style>
</head>
<body>
  <div class="header">
    <div class="logo">
      <span>🍙</span>
      <span>OmusuBI 安全ファイル共有 (Webダウンロードポータル)</span>
    </div>
    <div style="font-size: 12px; color: #64748b;">
      受信者限定アクセス
    </div>
  </div>
  <div class="container">
    {content}
  </div>
  <div class="footer">
    &copy; 2026 nigiri-rice.com | OmusuBI Secure Share Platform
  </div>
</body>
</html>"""

def render_cancel_page(status: str, mail_from: str = "", rcpt_tos: list = None, subject: str = ""):
    """送信取り消しページのレンダリング"""
    rcpt_str = ", ".join(rcpt_tos) if rcpt_tos else ""
    if status == "success":
        icon = "✅"
        title = "メールの送信を取り消しました"
        msg = f"""
        <p style="font-size: 15px; color: #15803d; font-weight: 600;">保留中だった社外宛てメールの送信を中止しました。</p>
        <p style="font-size: 13px; color: #475569; line-height: 1.6;">相手先へのメール配送は行われません。添付ファイルも外部へは公開されません。</p>
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 18px; margin-top: 20px; text-align: left; font-size: 13px;">
          <div><strong>件名:</strong> {subject}</div>
          <div style="margin-top: 4px;"><strong>送信元:</strong> {mail_from}</div>
          <div style="margin-top: 4px;"><strong>宛先:</strong> {rcpt_str}</div>
        </div>
        """
    elif status == "already_cancelled":
        icon = "ℹ️"
        title = "このメールは既に取り消し済みです"
        msg = f"<p style='font-size: 14px; color: #475569;'>この保留メールは既に取り消されています。社外へは配送されていません。</p>"
    else:
        icon = "⌛"
        title = "保留期間が終了しているか、見つかりません"
        msg = f"""
        <p style="font-size: 14px; color: #475569; line-height: 1.6;">
          保留時間（80秒間）が終了し、すでに相手先へ配送完了しているか、対象の保留メールが見つかりませんでした。
        </p>
        """

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - OmusuBI 誤送信防止システム</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background: #f8fafc; color: #1e293b; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); max-width: 520px; width: 100%; padding: 36px 28px; text-align: center; }}
    .icon {{ font-size: 48px; margin-bottom: 16px; }}
    h1 {{ font-size: 20px; color: #0f172a; margin: 0 0 12px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">{icon}</div>
    <h1>{title}</h1>
    {msg}
  </div>
</body>
</html>"""

# === Web ルートハンドラ ===

async def handle_share_page(request: web.Request):
    token = request.match_info.get("token")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404, content_type="text/html")
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    is_auth = (auth_email_hash is not None)
    step = "authenticated" if is_auth else "email"
    html = render_page(token, meta, step=step, is_authenticated=is_auth)
    return web.Response(text=html, content_type="text/html")

async def handle_request_otp(request: web.Request):
    token = request.match_info.get("token")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404, content_type="text/html")
        
    if is_share_expired(meta):
        html = render_page(token, meta)
        return web.Response(text=html, content_type="text/html")
        
    data = await request.post()
    email_addr = (data.get("email") or "").strip().lower()
    client_ip = request.headers.get("X-Real-IP") or request.remote or "unknown"
    
    if not email_addr or "@" not in email_addr:
        html = render_page(token, meta, step="email", error_msg="有効なメールアドレスを入力してください。", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")

    # IPレートリミット（1分間に最大10リクエスト）
    now = time.time()
    ip_history = rate_limits.setdefault(client_ip, [])
    ip_history[:] = [t for t in ip_history if now - t < 60]
    if len(ip_history) >= 10:
        logger.warning(f"Rate limit exceeded for IP {client_ip} on token {token}")
        html = render_page(token, meta, step="email", error_msg="リクエスト頻度が高すぎます。しばらく待ってからお試しください。", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")
    ip_history.append(now)

    salt = bytes.fromhex(meta["recipient_salt"])
    input_hash = hashlib.sha256(salt + email_addr.encode("utf-8")).hexdigest()
    challenge_key = f"{token}:{input_hash}"

    # クールダウンチェック（60秒間は同一アドレスへの再送を防止）
    existing_challenge = otp_challenges.get(challenge_key)
    if existing_challenge and now - existing_challenge.get("last_sent_at", 0) < OTP_RESEND_COOLDOWN:
        remaining = int(OTP_RESEND_COOLDOWN - (now - existing_challenge["last_sent_at"]))
        html = render_page(token, meta, step="otp", error_msg=f"確認コードはすでに送信済みです。再送まであと {remaining} 秒お待ちください。", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")

    # 宛先判定（登録済みか否か）
    is_valid_recipient = input_hash in meta.get("recipients_hashes", [])
    
    if is_valid_recipient:
        # 暗号論的疑似乱数による8桁OTP生成
        otp_code = f"{secrets.randbelow(100000000):08d}"
        kek = get_master_key()
        otp_hmac = hmac.new(kek, otp_code.encode("utf-8"), hashlib.sha256).hexdigest()
        
        otp_challenges[challenge_key] = {
            "hmac": otp_hmac,
            "expires_at": now + OTP_EXPIRY_SECONDS,
            "attempts": 0,
            "last_sent_at": now
        }
        
        try:
            send_otp_email(email_addr, otp_code, meta["title"], file_count=len(meta.get("files", [])))
        except Exception as e:
            logger.error(f"Failed to send OTP email to {email_addr}: {e}")
            html = render_page(token, meta, step="email", error_msg="確認コードの送信に失敗しました。時間をおいて再試行してください。", email_val=email_addr)
            return web.Response(text=html, content_type="text/html")
    else:
        # 未登録アドレスでも再送制限状態を記録 (列挙防止 & DoS防止)
        otp_challenges[challenge_key] = {
            "hmac": None,
            "expires_at": 0,
            "attempts": 0,
            "last_sent_at": now
        }
        # 列挙防止のためのダミースリープ (Timing Attack対策)
        await asyncio.sleep(0.35)
        logger.info(f"Unregistered address requested OTP for token {token} from IP {client_ip} (enumeration prevented)")

    # 登録・未登録問わず、同一の案内画面を表示 (OWASP列挙防止)
    html = render_page(token, meta, step="otp", success_msg="入力されたアドレスが宛先と一致する場合、8桁の確認コードを送信しました。", email_val=email_addr)
    return web.Response(text=html, content_type="text/html")

async def handle_verify_otp(request: web.Request):
    token = request.match_info.get("token")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404, content_type="text/html")
        
    data = await request.post()
    email_addr = (data.get("email") or "").strip().lower()
    otp_code = (data.get("otp") or "").strip()
    
    salt = bytes.fromhex(meta["recipient_salt"])
    input_hash = hashlib.sha256(salt + email_addr.encode("utf-8")).hexdigest()
    challenge_key = f"{token}:{input_hash}"
    
    challenge = otp_challenges.get(challenge_key)
    now = time.time()
    
    if not challenge or now > challenge["expires_at"]:
        html = render_page(token, meta, step="otp", error_msg="確認コードの有効期限（10分）が切れています。再送してください。", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")
        
    if challenge["attempts"] >= OTP_MAX_ATTEMPTS:
        otp_challenges.pop(challenge_key, None)
        html = render_page(token, meta, step="email", error_msg="コードの試行上限（5回）を超えました。最初からやり直してください。", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")
        
    challenge["attempts"] += 1
    
    kek = get_master_key()
    expected_hmac = hmac.new(kek, otp_code.encode("utf-8"), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(challenge["hmac"], expected_hmac):
        remaining = OTP_MAX_ATTEMPTS - challenge["attempts"]
        if remaining <= 0:
            otp_challenges.pop(challenge_key, None)
            html = render_page(token, meta, step="email", error_msg="コードの試行上限（5回）を超えました。最初からやり直してください。", email_val=email_addr)
            return web.Response(text=html, content_type="text/html")
        html = render_page(token, meta, step="otp", error_msg=f"確認コードが正しくありません。（残り試行可能回数: {remaining}回）", email_val=email_addr)
        return web.Response(text=html, content_type="text/html")
        
    # 認証成功！ 単回使用のためチャレンジを即破棄
    otp_challenges.pop(challenge_key, None)
    logger.info(f"OTP verification SUCCESS for token {token} by recipient hash {input_hash[:12]}")
    
    # 短命セッショントークン発行
    session_cookie = create_session_token(token, input_hash, kek)
    
    # 認証完了画面へリダイレクト (HttpOnly, Secure Cookie 付与)
    response = web.HTTPFound(f"/share/{token}")
    response.set_cookie(
        "secure_share_session",
        session_cookie,
        max_age=SESSION_EXPIRY_SECONDS,
        path=f"/share/",
        httponly=True,
        secure=True,
        samesite="Lax"
    )
    return response

async def handle_download_file(request: web.Request):
    """個別ファイルの復号ダウンロード"""
    token = request.match_info.get("token")
    file_id = request.match_info.get("file_id", "0")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404)
        
    if is_share_expired(meta):
        return web.Response(text="共有有効期限が切れています。", status=410)
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    if not auth_email_hash or auth_email_hash not in meta.get("recipients_hashes", []):
        return web.HTTPFound(f"/share/{token}")

    files = meta.get("files", [])
    target_file = None
    for f in files:
        if str(f.get("id")) == str(file_id):
            target_file = f
            break
            
    if not target_file:
        return web.Response(text="指定されたファイルが見つかりません。", status=404)
        
    filename = target_file["filename"]
    ascii_filename = re.sub(r'[^\x20-\x7E]', '_', filename)
    encoded_filename = urllib.parse.quote(filename, encoding='utf-8')
    content_disp = f"attachment; filename=\"{ascii_filename}\"; filename*=UTF-8''{encoded_filename}"
    
    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": target_file.get("mime_type", "application/octet-stream"),
            "Content-Disposition": content_disp,
            "Content-Length": str(target_file["size"]),
            "X-Content-Type-Options": "nosniff"
        }
    )
    await response.prepare(request)
    
    if target_file.get("is_local_file"):
        # フォルダ共有 (ローカルファイル)
        with open(target_file["abs_path"], "rb") as f:
            while True:
                buf = f.read(CHUNK_SIZE)
                if not buf:
                    break
                await response.write(buf)
        await response.write_eof()
    else:
        # 暗号化ストレージファイル
        enc_filename = target_file.get("enc_file", f"{token}.enc")
        enc_path = os.path.join(STORAGE_DIR, enc_filename)
        if not os.path.exists(enc_path):
            return web.Response(text="暗号化データが見つかりません。", status=404)
            
        for chunk in decrypt_file_chunks(enc_path, target_file, kek):
            await response.write(chunk)
        await response.write_eof()
        
    logger.info(f"File {filename} (id={file_id}) downloaded for token {token}")
    return response


CACHE_DIR = "/srv/secure-shares/cache"
os.makedirs(CACHE_DIR, exist_ok=True)

def generate_premiere_card(filename: str, file_path: str) -> str:
    """Premiere Pro (.prproj) プロジェクト構成情報カード生成"""
    xml_data = b""
    try:
        with gzip.open(file_path, "rb") as f:
            xml_data = f.read()
    except Exception:
        try:
            with open(file_path, "rb") as f:
                xml_data = f.read()
        except Exception:
            pass

    sequences = []
    media_items = []
    version_str = "Premiere Pro Project"
    if xml_data:
        try:
            root = ET.fromstring(xml_data)
            version_str = f"Premiere Pro (Project Ver {root.attrib.get('Version', '3')})"
            for seq in root.findall(".//Sequence"):
                name = seq.findtext("Name", "Untitled Sequence")
                fps = seq.findtext("FrameRate", "29.97")
                size = seq.findtext("VideoFrameSize", "1920,1080")
                dur = seq.findtext("Duration", "0")
                try:
                    dur_val = int(dur)
                    dur_sec = dur_val // 254016000000 if dur_val > 1000000 else dur_val
                    dur_str = f"{dur_sec // 60:02d}:{dur_sec % 60:02d}"
                except Exception:
                    dur_str = dur
                sequences.append({"name": name, "fps": fps, "size": size, "duration": dur_str})
                
            for m in root.findall(".//MediaItem"):
                name = m.findtext("Name", "")
                if name and name not in media_items:
                    media_items.append(name)
        except Exception as e:
            logger.warning(f"Error parsing prproj XML: {e}")

    seq_rows = ""
    for s in sequences:
        seq_rows += f"""
        <tr style="border-bottom: 1px solid #334155;">
          <td style="padding: 10px 14px; font-weight: 600; color: #f1f5f9;">🎬 {html.escape(s['name'])}</td>
          <td style="padding: 10px 14px; color: #94a3b8;">{html.escape(s['size'])}</td>
          <td style="padding: 10px 14px; color: #94a3b8;">{html.escape(s['fps'])} fps</td>
          <td style="padding: 10px 14px; color: #38bdf8; text-align: right;">{html.escape(s['duration'])}</td>
        </tr>
        """
    if not seq_rows:
        seq_rows = '<tr><td colspan="4" style="padding: 16px; text-align: center; color: #64748b;">シーケンス情報が検出されませんでした</td></tr>'

    media_badges = ""
    for m in media_items[:12]:
        media_badges += f'<span style="display: inline-block; background: #1e293b; color: #cbd5e1; border: 1px solid #334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; margin: 3px;">📁 {html.escape(m)}</span>'
    if len(media_items) > 12:
        media_badges += f'<span style="color: #64748b; font-size: 11px; margin-left: 6px;">他 {len(media_items) - 12} 件</span>'

    return f"""
    <div style="background: #0f172a; color: #f8fafc; border-radius: 10px; padding: 24px; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);">
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 20px;">
        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="background: #581c87; color: #e9d5ff; width: 52px; height: 52px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 26px; border: 1px solid #7e22ce;">🎬</div>
          <div>
            <div style="font-size: 17px; font-weight: 700; color: #f8fafc;">{html.escape(filename)}</div>
            <div style="font-size: 12px; color: #a855f7; margin-top: 2px;">{html.escape(version_str)}</div>
          </div>
        </div>
        <span style="background: #1e293b; border: 1px solid #475569; color: #94a3b8; font-size: 12px; padding: 4px 10px; border-radius: 20px;">プロジェクト解析完了</span>
      </div>

      <div style="margin-bottom: 20px;">
        <div style="font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px;">シーケンス・タイムライン構成</div>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; background: #1e293b; border-radius: 8px; overflow: hidden;">
          <thead>
            <tr style="background: #0b1120; color: #94a3b8; font-size: 12px; text-align: left;">
              <th style="padding: 10px 14px;">シーケンス名</th>
              <th style="padding: 10px 14px;">解像度</th>
              <th style="padding: 10px 14px;">フレームレート</th>
              <th style="padding: 10px 14px; text-align: right;">再生時間</th>
            </tr>
          </thead>
          <tbody>
            {seq_rows}
          </tbody>
        </table>
      </div>

      <div>
        <div style="font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;">リンク・参照メディア ({len(media_items)} 件)</div>
        <div style="background: #111827; padding: 12px; border-radius: 8px; border: 1px solid #1f2937;">
          {media_badges or '<span style="color: #64748b; font-size: 12px;">直接参照メディアなし</span>'}
        </div>
      </div>
    </div>
    """

def generate_aftereffects_card(filename: str, file_path: str) -> str:
    """After Effects (.aep) プロジェクト構成情報カード生成"""
    creator = "Adobe After Effects"
    comps = []
    try:
        with open(file_path, "rb") as f:
            raw = f.read(500000)
            
        m_creator = re.search(rb'<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>', raw)
        if m_creator:
            creator = m_creator.group(1).decode("utf-8", "ignore")
            
        matches = re.findall(rb'item\[\d+\]/name="([^"]+)"', raw)
        for m in matches:
            cname = m.decode("utf-8", "ignore")
            if cname and cname not in comps:
                comps.append(cname)
    except Exception as e:
        logger.warning(f"Error reading AEP: {e}")

    comp_items = ""
    for c in comps[:10]:
        comp_items += f'<div style="background: #1e1b4b; border: 1px solid #3730a3; padding: 8px 12px; border-radius: 6px; font-size: 12px; color: #c7d2fe; display: flex; align-items: center; gap: 8px;"><span>✨</span><span>{html.escape(c)}</span></div>'
    if not comp_items:
        comp_items = '<div style="color: #64748b; font-size: 12px;">コンポジション情報解析中</div>'

    return f"""
    <div style="background: #090d16; color: #f8fafc; border-radius: 10px; padding: 24px; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);">
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px;">
        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="background: #1e1b4b; color: #a5b4fc; width: 52px; height: 52px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 26px; border: 1px solid #4338ca;">✨</div>
          <div>
            <div style="font-size: 17px; font-weight: 700; color: #f8fafc;">{html.escape(filename)}</div>
            <div style="font-size: 12px; color: #818cf8; margin-top: 2px;">{html.escape(creator)}</div>
          </div>
        </div>
        <span style="background: #1e1b4b; border: 1px solid #3730a3; color: #a5b4fc; font-size: 12px; padding: 4px 10px; border-radius: 20px;">AEプロジェクト</span>
      </div>

      <div>
        <div style="font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">コンポジション構成</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px;">
          {comp_items}
        </div>
      </div>
    </div>
    """

def generate_indesign_card(filename: str, file_path: str) -> str:
    """InDesign (.indd) メタデータカード生成 (プレビュー画像非埋め込み時)"""
    creator = "Adobe InDesign"
    pages = "-"
    fonts = []
    try:
        cmd = ["exiftool", "-j", file_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.stdout:
            data = json.loads(res.stdout)
            if data:
                item = data[0]
                creator = item.get("CreatorTool", creator)
                pages = str(item.get("PageCount", "-"))
                fonts = item.get("Fonts", [])
                if isinstance(fonts, str):
                    fonts = [fonts]
    except Exception as e:
        logger.warning(f"Error reading InDesign metadata: {e}")

    font_badges = "".join([f'<span style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 3px 8px; border-radius: 4px; font-size: 11px; margin: 3px; display: inline-block;">🔤 {html.escape(f)}</span>' for f in fonts[:10]])

    return f"""
    <div style="background: #ffffff; color: #0f172a; border-radius: 10px; padding: 24px; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 20px;">
        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="background: #fce7f3; color: #be185d; width: 52px; height: 52px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 26px; border: 1px solid #fbcfe8;">📰</div>
          <div>
            <div style="font-size: 17px; font-weight: 700; color: #0f172a;">{html.escape(filename)}</div>
            <div style="font-size: 12px; color: #db2777; margin-top: 2px;">{html.escape(creator)}</div>
          </div>
        </div>
        <span style="background: #fdf2f8; border: 1px solid #fbcfe8; color: #be185d; font-size: 12px; padding: 4px 10px; border-radius: 20px;">ページ数: {pages}</span>
      </div>

      <div>
        <div style="font-size: 13px; font-weight: 600; color: #475569; margin-bottom: 10px;">使用フォント</div>
        <div>{font_badges or '<span style="color: #94a3b8; font-size: 12px;">フォント情報なし</span>'}</div>
      </div>
    </div>
    """

async def resolve_preview_data(raw_bytes: bytes, filename: str, cache_key: str) -> tuple:
    """
    ファイルバイナリと拡張子から、ブラウザでインラインプレビュー可能な (data_bytes, mime_type) を生成（またはキャッシュから取得）
    """
    lower = filename.lower()
    
    # 1. 既にプレビュー可能なネイティブ形式
    if lower.endswith(".pdf"):
        return raw_bytes, "application/pdf"
    elif lower.endswith(".png"):
        return raw_bytes, "image/png"
    elif lower.endswith((".jpg", ".jpeg")):
        return raw_bytes, "image/jpeg"
    elif lower.endswith(".svg"):
        return raw_bytes, "image/svg+xml"
    elif lower.endswith(".webp"):
        return raw_bytes, "image/webp"
    elif lower.endswith(".gif"):
        return raw_bytes, "image/gif"
    elif lower.endswith(".ico"):
        return raw_bytes, "image/x-icon"
    elif lower.endswith(".mp4"):
        return raw_bytes, "video/mp4"
    elif lower.endswith((".mov", ".m4v")):
        return raw_bytes, "video/quicktime"
    elif lower.endswith(".webm"):
        return raw_bytes, "video/webm"
    elif lower.endswith(".mp3"):
        return raw_bytes, "audio/mpeg"
    elif lower.endswith(".wav"):
        return raw_bytes, "audio/wav"
    elif lower.endswith((".m4a", ".aac")):
        return raw_bytes, "audio/mp4"
    elif lower.endswith(".flac"):
        return raw_bytes, "audio/flac"
    elif lower.endswith(".ogg"):
        return raw_bytes, "audio/ogg"
    elif lower.endswith(".csv"):
        return raw_bytes, "text/csv; charset=utf-8"
    elif lower.endswith(".tsv"):
        return raw_bytes, "text/tab-separated-values; charset=utf-8"
    elif lower.endswith((".md", ".markdown")):
        return raw_bytes, "text/markdown; charset=utf-8"
    elif lower.endswith((".tex", ".latex", ".bib")):
        return raw_bytes, "text/x-tex; charset=utf-8"
    elif lower.endswith(".json"):
        return raw_bytes, "application/json; charset=utf-8"
    elif lower.endswith(".xml"):
        return raw_bytes, "application/xml; charset=utf-8"
    elif lower.endswith((".yaml", ".yml")):
        return raw_bytes, "text/yaml; charset=utf-8"
    elif lower.endswith(".stl"):
        return raw_bytes, "model/stl"
    elif lower.endswith(".obj"):
        return raw_bytes, "model/obj"
    elif lower.endswith(".ply"):
        return raw_bytes, "model/ply"
    elif lower.endswith(".gltf"):
        return raw_bytes, "model/gltf+json"
    elif lower.endswith(".glb"):
        return raw_bytes, "model/gltf-binary"
    elif lower.endswith((".txt", ".log", ".sql", ".py", ".js", ".sh", ".css", ".html")):
        return raw_bytes, "text/plain; charset=utf-8" 
    # 2. キャッシュチェック
    cache_pdf = os.path.join(CACHE_DIR, f"{cache_key}.pdf")
    cache_png = os.path.join(CACHE_DIR, f"{cache_key}.png")
    cache_jpg = os.path.join(CACHE_DIR, f"{cache_key}.jpg")
    cache_html = os.path.join(CACHE_DIR, f"{cache_key}.html")

    if os.path.exists(cache_pdf):
        with open(cache_pdf, "rb") as f:
            return f.read(), "application/pdf"
    if os.path.exists(cache_png):
        with open(cache_png, "rb") as f:
            return f.read(), "image/png"
    if os.path.exists(cache_jpg):
        with open(cache_jpg, "rb") as f:
            return f.read(), "image/jpeg"
    if os.path.exists(cache_html):
        with open(cache_html, "rb") as f:
            return f.read(), "text/html; charset=utf-8"

    # 3. 変換処理
    with tempfile.TemporaryDirectory() as tmpdir:
        ext = os.path.splitext(filename)[1] or ".bin"
        temp_input = os.path.join(tmpdir, f"input{ext}")
        with open(temp_input, "wb") as f:
            f.write(raw_bytes)

        # A. Office ドキュメント (Word / Excel / PowerPoint) -> PDF
        if lower.endswith((".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt")):
            proc = await asyncio.create_subprocess_exec(
                "libreoffice", "--headless", "--convert-to", "pdf", "--outdir", tmpdir, temp_input,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            converted_pdf = os.path.join(tmpdir, "input.pdf")
            if os.path.exists(converted_pdf):
                with open(converted_pdf, "rb") as f:
                    pdf_data = f.read()
                try:
                    with open(cache_pdf, "wb") as cf:
                        cf.write(pdf_data)
                except Exception as e:
                    logger.warning(f"Failed to write cache {cache_pdf}: {e}")
                return pdf_data, "application/pdf"

        # B. Adobe Illustrator (.ai) / Photoshop (.psd) / TIFF / BMP -> PNG
        elif lower.endswith((".ai", ".psd", ".bmp", ".tiff", ".tif")):
            target_png = os.path.join(tmpdir, "output.png")
            cmd = ["convert"]
            if lower.endswith(".ai"):
                cmd.extend(["-density", "150", f"{temp_input}[0]", "-background", "white", "-flatten", target_png])
            else:
                cmd.extend(["-thumbnail", "1600x", f"{temp_input}[0]", "-background", "white", "-flatten", target_png])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if os.path.exists(target_png):
                with open(target_png, "rb") as f:
                    png_data = f.read()
                try:
                    with open(cache_png, "wb") as cf:
                        cf.write(png_data)
                except Exception as e:
                    logger.warning(f"Failed to write cache {cache_png}: {e}")
                return png_data, "image/png"

        # C. InDesign (.idml, .indd)
        elif lower.endswith(".idml"):
            try:
                with zipfile.ZipFile(temp_input, "r") as zf:
                    if "Thumbnails/thumbnail.png" in zf.namelist():
                        thumb_bytes = zf.read("Thumbnails/thumbnail.png")
                        with open(cache_png, "wb") as cf:
                            cf.write(thumb_bytes)
                        return thumb_bytes, "image/png"
            except Exception as e:
                logger.warning(f"Failed to extract IDML thumbnail: {e}")

        elif lower.endswith(".indd"):
            proc = await asyncio.create_subprocess_exec(
                "exiftool", "-b", "-PreviewImage", temp_input,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_data, _ = await proc.communicate()
            if stdout_data and len(stdout_data) > 200:
                with open(cache_jpg, "wb") as cf:
                    cf.write(stdout_data)
                return stdout_data, "image/jpeg"
            
            proc2 = await asyncio.create_subprocess_exec(
                "exiftool", "-b", "-ThumbnailImage", temp_input,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout_data2, _ = await proc2.communicate()
            if stdout_data2 and len(stdout_data2) > 200:
                with open(cache_jpg, "wb") as cf:
                    cf.write(stdout_data2)
                return stdout_data2, "image/jpeg"

            meta_html = generate_indesign_card(filename, temp_input)
            with open(cache_html, "wb") as cf:
                cf.write(meta_html.encode("utf-8"))
            return meta_html.encode("utf-8"), "text/html; charset=utf-8"

        # D. Premiere Pro (.prproj)
        elif lower.endswith(".prproj"):
            meta_html = generate_premiere_card(filename, temp_input)
            with open(cache_html, "wb") as cf:
                cf.write(meta_html.encode("utf-8"))
            return meta_html.encode("utf-8"), "text/html; charset=utf-8"

        # E. After Effects (.aep)
        elif lower.endswith(".aep"):
            meta_html = generate_aftereffects_card(filename, temp_input)
            with open(cache_html, "wb") as cf:
                cf.write(meta_html.encode("utf-8"))
            return meta_html.encode("utf-8"), "text/html; charset=utf-8"

    return raw_bytes, "application/octet-stream"


async def handle_content_file(request: web.Request):
    """個別ファイルのインラインプレビュー (Office・Adobeマルチフォーマット対応)"""
    token = request.match_info.get("token")
    file_id = request.match_info.get("file_id", "0")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404)
        
    if is_share_expired(meta):
        return web.Response(text="共有有効期限が切れています。", status=410)
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    if not auth_email_hash or auth_email_hash not in meta.get("recipients_hashes", []):
        return web.Response(text="認証が必要です。", status=401)

    files = meta.get("files", [])
    target_file = None
    for f in files:
        if str(f.get("id")) == str(file_id):
            target_file = f
            break
            
    if not target_file:
        return web.Response(text="指定されたファイルが見つかりません。", status=404)
        
    filename = target_file["filename"]
    try:
        raw_bytes = get_decrypted_file_bytes(target_file, token, kek)
        preview_bytes, mime_type = await resolve_preview_data(raw_bytes, filename, cache_key=f"{token}_{file_id}")
        
        ascii_filename = re.sub(r'[^\x20-\x7E]', '_', filename)
        encoded_filename = urllib.parse.quote(filename, encoding='utf-8')
        content_disp = f"inline; filename=\"{ascii_filename}\"; filename*=UTF-8''{encoded_filename}"
        
        ct = mime_type
        cs = None
        if "; charset=" in mime_type:
            parts = mime_type.split("; charset=")
            ct = parts[0].strip()
            cs = parts[1].strip()

        return web.Response(
            body=preview_bytes,
            content_type=ct,
            charset=cs,
            headers={
                "Content-Disposition": content_disp,
                "Content-Length": str(len(preview_bytes)),
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-cache, no-store, must-revalidate"
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate preview for {filename}: {e}")
        return web.Response(text=f"プレビューの生成に失敗しました: {e}", status=500)


def get_decrypted_file_bytes(target_file: dict, token: str, kek: bytes) -> bytes:
    """暗号化ファイルまたはローカルファイルを復号して全バイト列を返却"""
    if target_file.get("is_local_file"):
        with open(target_file["abs_path"], "rb") as f:
            return f.read()
    else:
        enc_filename = target_file.get("enc_file", f"{token}.enc")
        enc_path = os.path.join(STORAGE_DIR, enc_filename)
        if not os.path.exists(enc_path):
            raise FileNotFoundError("暗号化データが見つかりません。")
        buf = io.BytesIO()
        for chunk in decrypt_file_chunks(enc_path, target_file, kek):
            buf.write(chunk)
        return buf.getvalue()

async def handle_zip_tree(request: web.Request):
    """Zipアーカイブ内部のファイル一覧を取得 (API)"""
    token = request.match_info.get("token")
    file_id = request.match_info.get("file_id", "0")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.json_response({"error": "共有ファイルが見つかりません。"}, status=404)
        
    if is_share_expired(meta):
        return web.json_response({"error": "共有有効期限が切れています。"}, status=410)
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    if not auth_email_hash or auth_email_hash not in meta.get("recipients_hashes", []):
        return web.json_response({"error": "認証が必要です。"}, status=401)

    files = meta.get("files", [])
    target_file = None
    for f in files:
        if str(f.get("id")) == str(file_id):
            target_file = f
            break
            
    if not target_file:
        return web.json_response({"error": "指定されたファイルが見つかりません。"}, status=404)
        
    filename = target_file["filename"]
    if not filename.lower().endswith(".zip"):
        return web.json_response({"error": "Zipファイルではありません。"}, status=400)

    try:
        data = get_decrypted_file_bytes(target_file, token, kek)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            items = []
            for entry_id, info in enumerate(zf.infolist()):
                if info.is_dir():
                    continue
                name = info.filename
                if not (info.flag_bits & 0x800):
                    try:
                        name = info.filename.encode('cp437').decode('cp932')
                    except Exception:
                        pass
                
                items.append({
                    "entry_id": entry_id,
                    "filename": name,
                    "size": info.file_size,
                    "size_str": format_size(info.file_size),
                    "icon": get_file_icon(name),
                    "previewable": is_previewable(name)
                })
        return web.json_response({"status": "ok", "items": items, "zip_name": filename})
    except Exception as e:
        logger.error(f"Failed to inspect zip {filename}: {e}")
        return web.json_response({"error": f"Zipの展開に失敗しました: {e}"}, status=500)

async def handle_zip_file_entry(request: web.Request):
    """Zipアーカイブ内部の個別ファイルのプレビューまたは個別ダウンロード"""
    token = request.match_info.get("token")
    file_id = request.match_info.get("file_id", "0")
    entry_id = int(request.match_info.get("entry_id", "0"))
    is_preview = request.query.get("preview") == "1"
    
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404)
        
    if is_share_expired(meta):
        return web.Response(text="共有有効期限が切れています。", status=410)
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    if not auth_email_hash or auth_email_hash not in meta.get("recipients_hashes", []):
        return web.Response(text="認証が必要です。", status=401)

    files = meta.get("files", [])
    target_file = None
    for f in files:
        if str(f.get("id")) == str(file_id):
            target_file = f
            break
            
    if not target_file:
        return web.Response(text="指定されたファイルが見つかりません。", status=404)

    try:
        data = get_decrypted_file_bytes(target_file, token, kek)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            infolist = zf.infolist()
            if entry_id < 0 or entry_id >= len(infolist):
                return web.Response(text="Zip内のファイルが見つかりません。", status=404)
            info = infolist[entry_id]
            file_data = zf.read(info)
            
            name = info.filename
            if not (info.flag_bits & 0x800):
                try:
                    name = info.filename.encode('cp437').decode('cp932')
                except Exception:
                    pass
            base_fname = os.path.basename(name) or "file"
            
            mime_type, _ = mimetypes.guess_type(base_fname)
            if not mime_type or mime_type == "application/octet-stream":
                mime_type = "application/octet-stream"
            if base_fname.lower().endswith(".pdf"):
                mime_type = "application/pdf"
            elif base_fname.lower().endswith(".png"):
                mime_type = "image/png"
            elif base_fname.lower().endswith((".jpg", ".jpeg")):
                mime_type = "image/jpeg"

            if is_preview:
                preview_bytes, mime_type = await resolve_preview_data(file_data, base_fname, cache_key=f"{token}_{file_id}_zip_{entry_id}")
                data_to_send = preview_bytes
            else:
                data_to_send = file_data
                
            ascii_filename = re.sub(r'[^\x20-\x7E]', '_', base_fname)
            encoded_filename = urllib.parse.quote(base_fname, encoding='utf-8')
            disp_mode = "inline" if is_preview else "attachment"
            content_disp = f"{disp_mode}; filename=\"{ascii_filename}\"; filename*=UTF-8''{encoded_filename}"
            
            ct = mime_type
            cs = None
            if "; charset=" in mime_type:
                parts = mime_type.split("; charset=")
                ct = parts[0].strip()
                cs = parts[1].strip()

            return web.Response(
                body=data_to_send,
                content_type=ct,
                charset=cs,
                headers={
                    "Content-Disposition": content_disp,
                    "Content-Length": str(len(data_to_send)),
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "private, no-cache, no-store, must-revalidate"
                }
            )
    except Exception as e:
        logger.error(f"Failed to extract zip entry: {e}")
        return web.Response(text=f"エラーが発生しました: {e}", status=500)

async def handle_download_all(request: web.Request):
    """全ファイルを1つのZIPアーカイブとして一括ストリーミングダウンロード"""
    token = request.match_info.get("token")
    meta = get_normalized_metadata(token)
    if not meta:
        return web.Response(text="共有ファイルが見つかりません。", status=404)
        
    if is_share_expired(meta):
        return web.Response(text="共有有効期限が切れています。", status=410)
        
    kek = get_master_key()
    session_cookie = request.cookies.get("secure_share_session")
    auth_email_hash = verify_session_token(session_cookie, token, kek)
    
    if not auth_email_hash or auth_email_hash not in meta.get("recipients_hashes", []):
        return web.HTTPFound(f"/share/{token}")

    files = meta.get("files", [])
    if not files:
        return web.Response(text="ダウンロード可能なファイルがありません。", status=404)
        
    zip_basename = meta.get("subject") or meta.get("folder_name") or "添付ファイル一式"
    safe_zipname = re.sub(r'[\\/*?:"<>|]', "_", zip_basename).strip() or "attachments"
    zip_filename = f"{safe_zipname}.zip"
    
    ascii_zip = re.sub(r'[^\x20-\x7E]', '_', zip_filename)
    encoded_zip = urllib.parse.quote(zip_filename, encoding='utf-8')
    content_disp = f"attachment; filename=\"{ascii_zip}\"; filename*=UTF-8''{encoded_zip}"

    # 一時ファイルにストリーミング書き出し
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp_zip:
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for f_item in files:
                fname = f_item.get("filename", "file")
                arcname = fname.replace("\\", "/")
                
                with zf.open(arcname, mode="w") as zf_entry:
                    if f_item.get("is_local_file"):
                        with open(f_item["abs_path"], "rb") as local_f:
                            while True:
                                buf = local_f.read(CHUNK_SIZE)
                                if not buf:
                                    break
                                zf_entry.write(buf)
                    else:
                        enc_filename = f_item.get("enc_file", f"{token}.enc")
                        enc_path = os.path.join(STORAGE_DIR, enc_filename)
                        if os.path.exists(enc_path):
                            for chunk in decrypt_file_chunks(enc_path, f_item, kek):
                                zf_entry.write(chunk)
                                
        tmp_zip.seek(0, os.SEEK_END)
        total_zip_size = tmp_zip.tell()
        tmp_zip.seek(0)
        
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "application/zip",
                "Content-Disposition": content_disp,
                "Content-Length": str(total_zip_size),
                "X-Content-Type-Options": "nosniff"
            }
        )
        await response.prepare(request)
        
        while True:
            chunk = tmp_zip.read(CHUNK_SIZE)
            if not chunk:
                break
            await response.write(chunk)
        await response.write_eof()
        
    logger.info(f"Bulk ZIP download completed for token {token} ({file_count} files, {total_zip_size} bytes)")
    return response

async def handle_cancel_outbound(request: web.Request):
    """送信一時保留中のメールをワンクリックで取り消すエンドポイント"""
    cancel_token = request.match_info.get("cancel_token")
    if not cancel_token:
        html = render_cancel_page(status="not_found")
        return web.Response(text=html, content_type="text/html")
        
    pending_file = os.path.join(PENDING_DIR, f"{cancel_token}.json")
    if not os.path.exists(pending_file):
        html = render_cancel_page(status="not_found")
        return web.Response(text=html, content_type="text/html")
        
    try:
        with open(pending_file, "r", encoding="utf-8") as f:
            pending_data = json.load(f)
            
        cur_status = pending_data.get("status", "pending")
        mail_from = pending_data.get("mail_from", "")
        rcpt_tos = pending_data.get("rcpt_tos", [])
        subject = pending_data.get("subject", "")
        
        if cur_status == "cancelled":
            html = render_cancel_page(status="already_cancelled", mail_from=mail_from, rcpt_tos=rcpt_tos, subject=subject)
            return web.Response(text=html, content_type="text/html")
            
        # ステータスを cancelled に更新
        pending_data["status"] = "cancelled"
        pending_data["cancelled_at"] = datetime.now().isoformat()
        with open(pending_file, "w", encoding="utf-8") as f:
            json.dump(pending_data, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Outbound email marked as CANCELLED by sender: token={cancel_token}, from={mail_from}, to={rcpt_tos}, subject='{subject}'")
        html = render_cancel_page(status="success", mail_from=mail_from, rcpt_tos=rcpt_tos, subject=subject)
        return web.Response(text=html, content_type="text/html")
    except Exception as e:
        logger.error(f"Error handling cancel outbound {cancel_token}: {e}")
        html = render_cancel_page(status="error")
        return web.Response(text=html, content_type="text/html")

def init_app():
    app = web.Application()
    # 共有ポータル
    app.router.add_get("/share/{token}", handle_share_page)
    app.router.add_post("/share/{token}/api/request-otp", handle_request_otp)
    app.router.add_post("/share/{token}/api/verify-otp", handle_verify_otp)
    
    # ダウンロード & プレビュー
    app.router.add_get("/share/{token}/download", handle_download_file)  # 単一用
    app.router.add_get("/share/{token}/download-all", handle_download_all)  # 一括Zip用
    app.router.add_get("/share/{token}/file/{file_id}/download", handle_download_file)
    app.router.add_get("/share/{token}/file/{file_id}/content", handle_content_file)
    app.router.add_get("/share/{token}/file/{file_id}/zip-tree", handle_zip_tree)
    app.router.add_get("/share/{token}/file/{file_id}/zip-file/{entry_id}", handle_zip_file_entry)
    app.router.add_get("/share/{token}/api/content", handle_content_file)  # 後方互換
    
    # Active! gate 準拠 送信一時保留取り消し
    app.router.add_get("/outbound/cancel/{cancel_token}", handle_cancel_outbound)
    return app

if __name__ == "__main__":
    app = init_app()
    logger.info(f"Starting OmusuBI Secure Share Gateway on {LISTEN_HOST}:{LISTEN_PORT}...")
    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT)
