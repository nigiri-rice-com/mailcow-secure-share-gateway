import mimetypes
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OmusuBI Outbound Mail Filter (Active! gate 準拠 誤送信防止保留 & 単一バンドル脱PPAPプロキシ)
- ポート 10028 で待機
- 複数添付ファイルの一括バンドル化（1メール1つの共有URLに集約）
- 添付ファイルは AES-256-GCM で暗号化保存（DEK/KEK分離管理）
- 社外宛てメールは 80秒間保留待機 ＆ 送信者へのワンクリック送信取り消しリンク通知
- 社外宛先が 10 件以上の場合は To/Cc を Bcc へ強制変換（個人情報漏洩防止）
- 社内宛て（@nigiri-rice.com, @mail.nigiri-rice.com）は即時配送（時間差配信）
- 件名「-#-」または「X-OmusuBI-Bypass: true」で保留・分離をスキップ（即時通常送信）
- 送信再投入失敗時は必ず 451 を返却してメール消失を完全防止
"""

import os
import re
import sys
import html
import json
import time
import email
import smtplib
import secrets
import hashlib
import asyncio
import logging
import datetime
import subprocess
from email.header import decode_header
from email import policy
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from pathlib import Path

from aiosmtpd.controller import Controller
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === 設定 ===
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 10028
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://share.example.com")
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/srv/secure-shares")
PENDING_DIR = "/srv/secure-shares/pending"
KEY_PATH = os.environ.get("KEY_PATH", "/etc/mailcow-secure-share/master.key")
OUTBOUND_DELAY_SECONDS = 80
BCC_CONVERT_THRESHOLD = 10
EXPIRE_DAYS = 60
LOG_PATH = "/var/log/mailcow-outbound-filter.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [OutboundFilter] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding="utf-8")
    ]
)
logger = logging.getLogger("OutboundFilter")

def get_master_key() -> bytes:
    if not os.path.exists(KEY_PATH):
        raise RuntimeError(f"Master key file not found: {KEY_PATH}")
    with open(KEY_PATH, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise RuntimeError("Master key must be 32 bytes")
    return key

def decode_mime_words(raw_str):
    if not raw_str:
        return ""
    try:
        decoded_fragments = decode_header(raw_str)
        result = []
        for fragment, charset in decoded_fragments:
            if isinstance(fragment, bytes):
                result.append(fragment.decode(charset or 'utf-8', errors='replace'))
            else:
                result.append(str(fragment))
        return "".join(result)
    except Exception:
        return str(raw_str)

def sanitize_filename(filename):
    filename = decode_mime_words(filename)
    filename = re.sub(r'[\\/*?:"<>|]', "_", filename)
    filename = filename.strip(" .\t\r\n")
    return filename or "attachment"

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def reinject_mail(mail_from: str, rcpt_tos: list, message_bytes: bytes) -> bool:
    try:
        cmd = [
            "docker", "exec", "-i", "mailcowdockerized-postfix-mailcow-1",
            "/usr/sbin/sendmail", "-i", "-f", mail_from, "--"
        ] + rcpt_tos
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=message_bytes)
        if proc.returncode != 0:
            logger.error(f"Failed to reinject mail from {mail_from} to {rcpt_tos}: {err.decode('utf-8', errors='replace')}")
            return False
        logger.info(f"Successfully reinjected mail from {mail_from} to {rcpt_tos}")
        return True
    except Exception as e:
        logger.error(f"Failed to reinject mail from {mail_from} to {rcpt_tos}: {e}", exc_info=True)
        return False

def send_sender_notification(mail_from: str, subject: str, text_content: str, html_content: str):
    """送信者へ通知メールを即時配送 (X-OmusuBI-Bypass付きで遅延・リンク化ループ完全防止)"""
    if not mail_from or "@" not in mail_from:
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "no-reply@mail.nigiri-rice.com"
    msg["To"] = mail_from
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="mail.nigiri-rice.com")
    msg["X-OmusuBI-Bypass"] = "true"

    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    cmd = [
        "docker", "exec", "-i", "mailcowdockerized-postfix-mailcow-1",
        "/usr/sbin/sendmail", "-i", "-f", "no-reply@mail.nigiri-rice.com", "--", mail_from
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate(input=msg.as_bytes())

def notify_sender_hold(mail_from: str, rcpt_tos: list, subject: str, cancel_token: str, delay: int, attach_count: int):
    cancel_url = f"{PUBLIC_BASE_URL}/outbound/cancel/{cancel_token}"
    rcpt_str = ", ".join(rcpt_tos)
    
    mail_subject = f"【送信保留中・{delay}秒】社外宛てメールの送信を取り消せます（{subject}）"
    
    text_body = f"""OmusuBI 誤送信防止システムからのお知らせです。

社外宛てのメールを現在 {delay} 秒間、一時保留しています。
宛先や本文、添付ファイルに誤りがある場合は、以下のリンクをクリックすると送信を即座に取り消せます。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■ 件名: {subject}
■ 宛先: {rcpt_str}
■ 添付ファイル: {attach_count} 件
■ 保留時間: {delay} 秒間
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▼ 送信取り消し（キャンセル）リンク:
<{cancel_url}>

※ {delay} 秒経過後は自動的に宛先へ配送されます。取り消す必要がない場合はそのままお待ちください。
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; padding: 20px;">
  <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 24px;">
    <div style="display: flex; align-items: center; gap: 8px; border-bottom: 2px solid #f59e0b; padding-bottom: 12px; margin-bottom: 16px;">
      <span style="font-size: 24px;">⏳</span>
      <h2 style="margin: 0; color: #b45309; font-size: 17px;">社外宛てメールを送信保留しています（誤送信防止）</h2>
    </div>
    <p style="font-size: 14px; margin-bottom: 16px;">
      送信されたメールは <strong>あと {delay} 秒間</strong>、サーバーで一時保留されます。<br>
      宛先の間違いや添付ファイルの誤りに気づいた場合は、下のボタンから送信を取り消すことができます。
    </p>
    <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; margin-bottom: 20px; font-size: 13px;">
      <div><strong>件名:</strong> {subject}</div>
      <div style="margin-top: 4px;"><strong>宛先:</strong> {rcpt_str}</div>
      <div style="margin-top: 4px;"><strong>添付ファイル:</strong> {attach_count} 件</div>
    </div>
    <div style="text-align: center; margin: 24px 0;">
      <a href="{cancel_url}" style="background-color: #dc2626; color: #ffffff !important; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: bold; font-size: 14px; display: inline-block;">
        🛑 このメールの送信を取り消す
      </a>
      <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
        取り消しURL: <a href="{cancel_url}" style="color: #2563eb;">{cancel_url}</a>
      </div>
    </div>
    <p style="font-size: 12px; color: #6b7280; margin-top: 20px; border-top: 1px dashed #e2e8f0; padding-top: 12px;">
      ※ 取り消す必要がない場合は、何もしなくて構いません。{delay} 秒後に自動的に社外へ配送されます。
    </p>
  </div>
</body>
</html>"""

    send_sender_notification(mail_from, mail_subject, text_body, html_body)

def notify_sender_cancelled(mail_from: str, rcpt_tos: list, subject: str):
    rcpt_str = ", ".join(rcpt_tos)
    mail_subject = f"【送信取消完了】社外宛てメールの送信を取り消しました（{subject}）"
    text_body = f"""OmusuBI 誤送信防止システムからのお知らせです。

以下のメールの送信を取り消しました。社外へは配送されておりません。

■ 件名: {subject}
■ 宛先: {rcpt_str}
■ 取消日時: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; padding: 20px;">
  <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 24px;">
    <div style="display: flex; align-items: center; gap: 8px; border-bottom: 2px solid #16a34a; padding-bottom: 12px; margin-bottom: 16px;">
      <span style="font-size: 24px;">✅</span>
      <h2 style="margin: 0; color: #15803d; font-size: 17px;">メールの送信を取り消しました</h2>
    </div>
    <p style="font-size: 14px; margin-bottom: 16px;">
      保留中だった社外宛てメールの送信を中止しました。相手先へのメール配送は行われておりません。
    </p>
    <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; font-size: 13px;">
      <div><strong>件名:</strong> {subject}</div>
      <div style="margin-top: 4px;"><strong>宛先:</strong> {rcpt_str}</div>
    </div>
  </div>
</body>
</html>"""
    send_sender_notification(mail_from, mail_subject, text_body, html_body)

class OutboundHandler:
    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content

        logger.info(f"Incoming submission from={mail_from} to={rcpt_tos} size={len(data)} bytes")

        try:
            msg = email.message_from_bytes(data, policy=policy.default)
            
            # X-OmusuBI-Bypass ヘッダーチェック（内部通知・OTPメール等の無限ループ完全防止）
            is_bypass = (msg.get("X-OmusuBI-Bypass", "").lower() == "true")
            if is_bypass:
                logger.info(f"X-OmusuBI-Bypass detected. Skipping all processing and delay for {mail_from} -> {rcpt_tos}")

            # すでにリンク化済みのメールかチェック
            is_already_linked = (msg.get("X-OmusuBI-Outbound-Linked", "").lower() == "true")
            if is_already_linked:
                is_bypass = True

            # 件名チェック
            subject = decode_mime_words(msg.get("Subject", ""))
            if "-#-" in subject:
                is_bypass = True
                new_subject = subject.replace("-#-", "").strip()
                del msg["Subject"]
                msg["Subject"] = new_subject
                logger.info(f"Bypass prefix '-#-' detected. Skipping conversion and delay. Subject updated: '{new_subject}'")

            # Bcc強制変換チェック (社外宛先が 10 件以上の場合、Active! gate 準拠で Bcc へ変換)
            external_rcpts = [r for r in rcpt_tos if not (r.endswith("@nigiri-rice.com") or r.endswith("@mail.nigiri-rice.com"))]
            if len(external_rcpts) >= BCC_CONVERT_THRESHOLD and not is_bypass:
                logger.info(f"Forcing Bcc conversion: {len(external_rcpts)} external recipients detected (threshold={BCC_CONVERT_THRESHOLD})")
                if "To" in msg:
                    del msg["To"]
                if "Cc" in msg:
                    del msg["Cc"]
                msg["To"] = "undisclosed-recipients:;"
                msg["X-OmusuBI-Bcc-Converted"] = f"true (count={len(external_rcpts)})"

            # 添付ファイルの抽出と一括バンドル化
            if not is_bypass:
                attachments = []
                for part in msg.walk():
                    fname = part.get_filename()
                    cdisp = part.get("Content-Disposition", "")
                    cid = part.get("Content-ID", "")

                    is_attach = False
                    if fname:
                        is_attach = True
                    elif cdisp and "attachment" in cdisp.lower():
                        is_attach = True
                    elif cdisp and "inline" in cdisp.lower() and not cid:
                        is_attach = True

                    if is_attach:
                        payload = part.get_payload(decode=True)
                        if payload and len(payload) > 0:
                            safe_name = sanitize_filename(fname) if fname else f"attachment_{len(attachments)+1}.dat"
                            guessed_mime, _ = mimetypes.guess_type(safe_name)
                            mime_type = part.get_content_type()
                            if not mime_type or mime_type == "application/octet-stream":
                                mime_type = guessed_mime or "application/octet-stream"
                            if safe_name.lower().endswith(".pdf"):
                                mime_type = "application/pdf"
                            elif safe_name.lower().endswith(".png"):
                                mime_type = "image/png"
                            elif safe_name.lower().endswith((".jpg", ".jpeg")):
                                mime_type = "image/jpeg"
                            attachments.append({
                                "filename": safe_name,
                                "content": payload,
                                "size": len(payload),
                                "mime_type": mime_type,
                                "part": part
                            })

                if attachments:
                    logger.info(f"Detected {len(attachments)} attachments to bundle for outbound mail: '{subject}'")
                    
                    kek = get_master_key()
                    kek_aesgcm = AESGCM(kek)
                    
                    # 1通のメールに対して単一の bundle_token を発行
                    bundle_token = secrets.token_urlsafe(18)
                    salt = secrets.token_bytes(16)
                    recipients_hashes = [
                        hashlib.sha256(salt + r.strip().lower().encode("utf-8")).hexdigest()
                        for r in rcpt_tos if r.strip()
                    ]
                    
                    files_meta = []
                    total_bundle_size = 0
                    os.makedirs(STORAGE_DIR, exist_ok=True)
                    
                    # 各添付ファイルを AES-256-GCM で暗号化
                    for idx, item in enumerate(attachments):
                        enc_filename = f"{bundle_token}_{idx}.enc"
                        enc_path = os.path.join(STORAGE_DIR, enc_filename)
                        
                        dek = secrets.token_bytes(32)
                        plain_sha256 = hashlib.sha256(item["content"]).hexdigest()
                        dek_nonce = secrets.token_bytes(12)
                        encrypted_dek = kek_aesgcm.encrypt(dek_nonce, dek, b"DEK_WRAP")
                        
                        dek_aesgcm = AESGCM(dek)
                        file_nonce_prefix = secrets.token_bytes(8)
                        encrypted_chunks = []
                        chunk_index = 0
                        chunk_size = 64 * 1024
                        
                        for i in range(0, len(item["content"]), chunk_size):
                            chunk = item["content"][i:i + chunk_size]
                            chunk_nonce = file_nonce_prefix + chunk_index.to_bytes(4, byteorder="big")
                            aad = chunk_index.to_bytes(4, byteorder="big")
                            enc_chunk = dek_aesgcm.encrypt(chunk_nonce, chunk, aad)
                            encrypted_chunks.append(enc_chunk)
                            chunk_index += 1
                            
                        full_encrypted = file_nonce_prefix + chunk_index.to_bytes(4, byteorder="big") + b"".join(encrypted_chunks)
                        with open(enc_path, "wb") as f:
                            f.write(full_encrypted)
                        os.chmod(enc_path, 0o600)
                        
                        total_bundle_size += len(item["content"])
                        files_meta.append({
                            "id": str(idx),
                            "filename": item["filename"],
                            "size": len(item["content"]),
                            "mime_type": item["mime_type"],
                            "plain_sha256": plain_sha256,
                            "enc_file": enc_filename,
                            "chunk_size": chunk_size,
                            "total_chunks": chunk_index,
                            "dek_nonce": dek_nonce.hex(),
                            "encrypted_dek": encrypted_dek.hex()
                        })
                        
                    # バンドルメタデータの保存
                    bundle_metadata = {
                        "type": "bundle",
                        "token": bundle_token,
                        "subject": subject or "添付ファイル一式",
                        "mail_from": mail_from,
                        "total_size": total_bundle_size,
                        "recipient_salt": salt.hex(),
                        "recipients_hashes": recipients_hashes,
                        "created_at": datetime.datetime.now().isoformat(),
                        "expire_days": EXPIRE_DAYS,
                        "files": files_meta
                    }
                    
                    meta_path = os.path.join(STORAGE_DIR, f"{bundle_token}.meta")
                    with open(meta_path, "w", encoding="utf-8") as f:
                        json.dump(bundle_metadata, f, indent=2, ensure_ascii=False)
                    os.chmod(meta_path, 0o600)
                    
                    logger.info(f"Encrypted and bundled {len(files_meta)} files as token {bundle_token} (total size: {total_bundle_size})")

                    # 単一の案内URL
                    share_url = f"{PUBLIC_BASE_URL}/share/{bundle_token}"
                    total_size_str = format_size(total_bundle_size)
                    file_count = len(files_meta)

                    # プレーンテキスト用案内
                    text_notice = "\n\n" + "=" * 62 + "\n"
                    text_notice += f"📎 添付ファイルのご案内（計 {file_count} 件 / 合計 {total_size_str} / 有効期限: {EXPIRE_DAYS}日間）\n"
                    text_notice += "セキュリティ保護のため、添付ファイルは暗号化保管されております。\n"
                    text_notice += "※ 社内アカウントの登録は不要です。受信したメールアドレスを入力し、\n"
                    text_notice += "届いた確認コード（8桁）で認証すると、全ファイルをまとめて閲覧・ダウンロードできます。\n\n"
                    text_notice += "【添付ファイル一覧】\n"
                    for idx, f_item in enumerate(files_meta, start=1):
                        text_notice += f"  {idx}. {f_item['filename']} ({format_size(f_item['size'])})\n"
                    text_notice += f"\n📥 まとめて確認・ダウンロード:\n<{share_url}>\n"
                    text_notice += "=" * 62 + "\n"

                    # HTML用案内 (Outlookデスクトップ/Web・Gmail・iOS・Mac・Thunderbird完全互換 Bulletproof HTML)
                    file_rows_html = ""
                    for f_item in files_meta:
                        file_rows_html += f"""
        <tr>
          <td style="padding: 7px 0; border-bottom: 1px dashed #cbd5e1; font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 13px; color: #1e293b; vertical-align: middle;">
            📄 {html.escape(f_item['filename'])}
          </td>
          <td align="right" style="padding: 7px 0 7px 12px; border-bottom: 1px dashed #cbd5e1; font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 12px; color: #64748b; white-space: nowrap; vertical-align: middle;">
            ({format_size(f_item['size'])})
          </td>
        </tr>
"""

                    html_notice = f"""
<!--[if mso]>
<table align="left" border="0" cellspacing="0" cellpadding="0" width="620" style="width: 620px;">
<tr>
<td style="padding-top: 20px;">
<![endif]-->
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 620px; margin-top: 20px; border: 1px solid #10b981; border-radius: 8px; background-color: #f0fdf4; font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt;">
  <tr>
    <td style="padding: 18px 20px;">
      <!-- ヘッダー -->
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 10px;">
        <tr>
          <td style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 15px; font-weight: bold; color: #065f46; line-height: 1.4;">
            📎 添付ファイルのご案内（計 {file_count} 件 / 合計 {total_size_str}）
          </td>
        </tr>
      </table>
      
      <!-- 説明文 -->
      <p style="margin: 0 0 12px 0; font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 13px; color: #334155; line-height: 1.6;">
        セキュリティ保護のため、添付ファイルは暗号化ストレージに安全に保管されております。<br>
        <strong style="color: #047857;">※ 社内アカウントの登録は不要です。</strong>メールを受信したアドレスを入力し、届いた確認コード（8桁）で認証すると、すべてのファイルをまとめて閲覧・一括ダウンロードできます。
      </p>

      <!-- ファイル一覧ボックス -->
      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #ffffff; border: 1px solid #a7f3d0; border-radius: 6px; margin-bottom: 14px; border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt;">
        <tr>
          <td style="padding: 12px 14px;">
            <div style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 12px; font-weight: bold; color: #047857; margin-bottom: 6px;">【添付ファイル一覧】</div>
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse;">
              {file_rows_html}
            </table>
          </td>
        </tr>
      </table>

      <!-- ボタン & URL -->
      <table border="0" cellspacing="0" cellpadding="0" align="center" style="margin: 14px auto 6px auto;">
        <tr>
          <td align="center" bgcolor="#059669" style="border-radius: 6px; background-color: #059669; padding: 0;">
            <a href="{share_url}" target="_blank" style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 14px; font-weight: bold; color: #ffffff; text-decoration: none; display: inline-block; padding: 11px 26px; border-radius: 6px; background-color: #059669; border: 1px solid #059669;">
              📥 まとめて確認・一括ダウンロード
            </a>
          </td>
        </tr>
      </table>
      <div style="text-align: center; margin-top: 6px;">
        <a href="{share_url}" target="_blank" style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; color: #0284c7; font-size: 12px; text-decoration: underline; word-break: break-all;">
          {share_url}
        </a>
      </div>

      <!-- 有効期限フッター -->
      <div style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 11px; color: #64748b; text-align: center; margin-top: 10px;">
        ※ 有効期限: {EXPIRE_DAYS}日間（Web上でプレビュー確認・一括ZIPダウンロードが可能です）
      </div>
    </td>
  </tr>
</table>
<!--[if mso]>
</td>
</tr>
</table>
<![endif]-->
"""

                    # 本文パートの更新
                    plain_part = None
                    html_part = None
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        if ctype == "text/plain" and plain_part is None:
                            plain_part = part
                        elif ctype == "text/html" and html_part is None:
                            html_part = part

                    plain_content = ""
                    if plain_part:
                        try:
                            plain_content = plain_part.get_content()
                        except Exception:
                            plain_content = ""
                        try:
                            plain_part.set_content(plain_content + text_notice, cte="quoted-printable")
                        except Exception:
                            plain_part.set_content(plain_content + text_notice)

                    if html_part:
                        try:
                            content = html_part.get_content()
                            if "</body>" in content:
                                new_html = content.replace("</body>", f"{html_notice}</body>")
                            else:
                                new_html = content + html_notice
                            html_part.set_content(new_html, subtype="html")
                        except Exception as e:
                            logger.warning(f"Failed to update HTML part: {e}")
                    elif plain_part:
                        try:
                            escaped_body = html.escape(plain_content).replace("\n", "<br>\n")
                            generated_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: 'Segoe UI', Meiryo, 'Hiragino Sans', 'Yu Gothic', sans-serif; font-size: 14px; line-height: 1.6; color: #1f2937;">
<div>{escaped_body}</div>
{html_notice}
</body>
</html>"""
                            plain_part.add_alternative(generated_html, subtype="html")
                            logger.info("Added auto-generated HTML alternative part with clickable hyperlinks.")
                        except Exception as e:
                            logger.warning(f"Failed to add alternative HTML part: {e}")

                    # 添付パートの分離
                    parts_to_remove = [item["part"] for item in attachments]
                    if msg.is_multipart():
                        new_payload = [p for p in msg.get_payload() if p not in parts_to_remove]
                        msg.set_payload(new_payload)

                    msg["X-OmusuBI-Outbound-Linked"] = "true"

            # 80秒送信遅延 ＆ 送信取り消し（社外宛てかつバイパスでない場合）
            delay = int(os.environ.get("OUTBOUND_DELAY_SECONDS", OUTBOUND_DELAY_SECONDS))
            is_external = any(not (r.endswith("@nigiri-rice.com") or r.endswith("@mail.nigiri-rice.com")) for r in rcpt_tos)
            
            if delay > 0 and is_external and not is_bypass:
                cancel_token = secrets.token_urlsafe(16)
                os.makedirs(PENDING_DIR, exist_ok=True)
                pending_file = os.path.join(PENDING_DIR, f"{cancel_token}.json")
                
                pending_info = {
                    "cancel_token": cancel_token,
                    "mail_from": mail_from,
                    "rcpt_tos": rcpt_tos,
                    "subject": subject,
                    "status": "pending",
                    "created_at": datetime.datetime.now().isoformat(),
                    "expires_at": time.time() + delay
                }
                with open(pending_file, "w", encoding="utf-8") as pf:
                    json.dump(pending_info, pf, indent=2, ensure_ascii=False)
                os.chmod(pending_file, 0o600)

                # 送信者へ送信取り消し通知メールを配送
                attach_count = len(attachments) if 'attachments' in locals() and attachments else 0
                try:
                    notify_sender_hold(mail_from, rcpt_tos, subject, cancel_token, delay, attach_count)
                except Exception as e:
                    logger.warning(f"Failed to notify sender of hold: {e}")

                logger.info(f"Delaying outbound delivery for {delay} seconds (cancel_token={cancel_token}, to={rcpt_tos})")

                # 保留カウントダウン（キャンセル検出ループ）
                elapsed = 0
                is_cancelled = False
                while elapsed < delay:
                    await asyncio.sleep(1.0)
                    elapsed += 1
                    if not os.path.exists(pending_file):
                        is_cancelled = True
                        break
                    try:
                        with open(pending_file, "r", encoding="utf-8") as pf:
                            cur_p = json.load(pf)
                            if cur_p.get("status") == "cancelled":
                                is_cancelled = True
                                break
                    except Exception:
                        pass

                if is_cancelled:
                    logger.info(f"Outbound delivery CANCELLED by sender for {mail_from} -> {rcpt_tos} (cancel_token={cancel_token})")
                    try:
                        if os.path.exists(pending_file):
                            os.remove(pending_file)
                    except Exception:
                        pass
                    try:
                        notify_sender_cancelled(mail_from, rcpt_tos, subject)
                    except Exception as e:
                        logger.warning(f"Failed to notify sender of cancellation: {e}")
                    return "250 2.0.0 Message delivery cancelled by sender"

                # 保留期間終了
                try:
                    if os.path.exists(pending_file):
                        os.remove(pending_file)
                except Exception:
                    pass

            # 再投入
            final_bytes = msg.as_bytes()
            success = reinject_mail(mail_from, rcpt_tos, final_bytes)
            if success:
                return "250 2.0.0 OK: Message accepted and queued for delivery"
            else:
                logger.error(f"reinject_mail failed for modified message ({mail_from} -> {rcpt_tos}). Attempting fallback with original message.")
                fallback_success = reinject_mail(mail_from, rcpt_tos, data)
                if fallback_success:
                    logger.warning(f"Reinjected original unmodified message for {mail_from} -> {rcpt_tos} after modified reinject failure.")
                    return "250 2.0.0 OK: Message accepted with original fallback"
                else:
                    logger.critical(f"FATAL: Both modified and fallback reinject failed for {mail_from} -> {rcpt_tos}! Returning 451 to prevent mail loss.")
                    return "451 4.3.0 Temporary failure reinjecting message"

        except Exception as e:
            logger.error(f"Exception handling outbound email for {mail_from} -> {rcpt_tos}: {e}", exc_info=True)
            fallback_success = reinject_mail(mail_from, rcpt_tos, data)
            if fallback_success:
                logger.warning(f"Reinjected original unmodified message for {mail_from} -> {rcpt_tos} following exception.")
                return "250 2.0.0 OK: Message processed with fallback"
            else:
                logger.critical(f"FATAL: Failed to reinject original message following exception for {mail_from} -> {rcpt_tos}! Returning 451 to prevent mail loss.")
                return "451 4.3.0 Temporary failure: unable to process or reinject message"

if __name__ == "__main__":
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs(PENDING_DIR, exist_ok=True)
    handler = OutboundHandler()
    controller = Controller(handler, hostname=LISTEN_HOST, port=LISTEN_PORT, data_size_limit=2147483648)
    logger.info(f"Starting OmusuBI Outbound Mail Filter on {LISTEN_HOST}:{LISTEN_PORT}...")
    controller.start()
    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        controller.stop()