# Mailcow Secure Share Gateway (脱PPAP・高機能暗号化Web共有)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-success.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Mailcow](https://img.shields.io/badge/Mailcow-Dockerized-0082c9.svg)](https://mailcow.email/)

送信メールの添付ファイルを自動的に迎撃（インターセプト）し、暗号化ファイル共有リンクへと自動変換（脱PPAP）するメール連携セキュアゲートウェイです。
受信者限定のワンタイムパスワード (OTP) 二要素認証と、Office・CSV・Markdown・3D STL・SVG・PDF 等の全方位インラインWebプレビュー機能を備えています。

---

## 🌟 主な特徴

1. **完全自動の脱PPAP（パスワード付きZIP廃止）**
   - 送信メールから添付ファイルを自動分離。メール本文にセキュアな一時共有URL（`/share/{token}`）を自動挿入。ギガバイト級の大容量ファイルも制限なく共有可能。
2. **Active! gate SS 準拠 誤送信防止保留 & 送信取り消し**
   - 社外宛て送信時に80秒間の送信保留を実施。送信者へワンクリック送信取り消しリンク付き通知を即時配送。
3. **上長承認ワークフロー（Approval Portal）**
   - 社外向け重要メール送信時に上長へ承認依頼を発行。専用Web画面（`/outbound/approve/{token}`）で本文・添付を確認し、ワンクリックで承認または理由付き差し戻しが可能。
4. **リンク即時無効化（キルスイッチ）& 送信者専用管理画面**
   - 送信後でも誤送信に気づいた時点で、専用URL（`/share/{token}/manage`）からワンクリックで共有リンクを即時無効化（アクセス完全遮断）。
5. **管理者統合ダッシュボード（`/admin`）**
   - 全共有リンクの稼働状況、保留中メールキューの承認/取消操作、ダウンロード回数や監査ログを一元管理。
6. **AES-256-GCM 暗号化 & マスターキー保護**
   - 分離された添付ファイルはディスク保存時に AES-256-GCM で強力に暗号化。改ざん耐性を確保。
7. **受信者メールOTP二要素認証**
   - 宛先メールアドレスの所有確認（8桁ワンタイムコード送信）に成功したユーザーのみがファイルを復号・ダウンロード可能。
8. **全方位マルチフォーマット Web プレビュー（PC 2ペインスプリットビュー対応）**
   - ダウンロードすることなく、ブラウザ上で直ちに内容を確認：
     - **Office 文書**: docx, xlsx, pptx (PDF自動変換インラインプレビュー)
     - **データ・文書**: CSV / TSV（ソート・検索可能テーブル）、Markdown、TeX
     - **3D & ベクター**: 3D CAD/STL（Three.js 360度インタラクティブ操作・視点リセット対応）、SVG、PDF、WebP/PNG/JPG

---

## 🏛 処理フロー

```mermaid
sequenceDiagram
    autonumber
    actor Sender as 送信者 (社内メーラー)
    participant Postfix as Mailcow Postfix
    participant Filter as outbound_filter.py
    participant Gateway as secure_share_gateway.py
    actor Recipient as 社外受信者 (取引先)

    Sender->>Postfix: 添付ファイル付きメール送信
    Postfix->>Filter: Milter / Webhook 送信時フック
    Filter->>Filter: 添付ファイルを抽出・AES-256-GCM暗号化
    Filter->>Postfix: メール本文を「共有URL付き」に書き換えて配送
    Postfix-->>Recipient: メール受信 (リンクのみ記載)

    Recipient->>Gateway: 共有URLへブラウザアクセス
    Gateway-->>Recipient: メールアドレス確認画面表示
    Recipient->>Gateway: メールアドレス入力
    Gateway->>Recipient: 8桁OTPコードをメール送信
    Recipient->>Gateway: OTPコード入力
    Gateway-->>Recipient: ファイル一覧 & 全方位Webプレビュー表示
```

---

## 📄 ライセンス

本リポジトリは [MIT License](LICENSE) の下で公開されています。
