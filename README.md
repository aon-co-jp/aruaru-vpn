# aruaru-vpn

[Outline VPN](https://getoutline.org/)(Jigsaw/Google製、Shadowsocksベース)・
[Algo VPN](https://github.com/trailofbits/algo)(Trail of Bits製、WireGuard/
IPSecベース)を参考に、**コードを一切流用せず一から**Rust +
[`open-web-server`](https://github.com/aon-co-jp/open-web-server)で再実装する、
**「自分で借りたVPS上に、自分専用のプライバシー中継(VPN)を立てられる」
OSSテンプレート**。

**用途を隠さない、正直な設計**であることが最大の方針(下記「開発の経緯」参照)。
利用者が自分の判断で、自分の借りたVPS(さくらのVPS・ConoHa・AWS等、
どの事業者でも良い)に自分専用の中継を立てて使う。**運営(aon-co-jp)は
中継サーバーを運営しない**——テンプレート(コード)を配布するだけであり、
実際にVPSを借りて中継を稼働させる主体は利用者自身になる。

## 開発の経緯

[`open-tv-chat`](https://github.com/aon-co-jp/open-tv-chat)・
[`open-LiveKit`](https://github.com/aon-co-jp/open-LiveKit)の開発中、
「TV CHAT利用者が安全に通信するには、汎用VPNアプリも同時開発してはどうか」
という提案があった。検討の結果:

1. **独立VPN事業として運営する案**は、各国のVPN法規制(完全禁止国・
   強い規制国・義務的ログ保持国等)により、aon-co-jpが「VPN事業者」として
   単独で法的責任を負うことになるため見送った(詳細は
   [`open-LiveKit`のPORTING.md](https://github.com/aon-co-jp/open-LiveKit/blob/main/PORTING.md)
   「8. 踏み台の用途スコープの検討経緯」参照)。
2. 「本来の目的を隠して別のWebサイトとして配布してはどうか」という案も
   検討したが、**利用者に対して不誠実であり、検知回避ツールと見なされる
   リスクもある**ため見送った。
3. **最終的に、Outline VPN/Algo VPNと同じモデル——「利用者が自分自身の
   VPS上に、自分専用の中継を立てる」ことを前提としたOSSテンプレートを、
   用途を隠さず配布する**方式を採用した。この方式では、中継サーバーを
   実際に運用する主体は利用者自身であり、aon-co-jpは「VPN事業者」には
   ならない(Outline VPN/Algo VPN自体が既に世界中で合法的に配布・利用
   されている実績のある方式)。

## アーキテクチャ概要(構想)

```
[利用者]
   │ 1. 自分の判断でVPSを契約(どの事業者でも良い、aon-co-jpは提供しない)
   ▼
[利用者が契約したVPS]
   │ 2. aruaru-vpnのセットアップスクリプト/コンテナを実行
   ▼
[VPS上で稼働するaruaru-vpnサーバー]
   │  - Rust + open-web-server上に構築
   │  - Shadowsocks的な「検閲されにくい」プロトコル、または
   │    WireGuard的な「軽量・高速」プロトコルのどちらを採るかは
   │    実装時に比較検討する(下記「技術選定(未着手)」参照)
   ▼
[利用者の各端末(Win/Mac/Linux/Android/iPhone)]
   │  aruaru-vpnクライアント経由でVPSに接続、そこから先のインターネットへ
```

- **鍵は利用者自身が管理**(Outline VPNと同様、サーバーを運用する利用者
  自身が鍵を保持し、第三者〈aon-co-jpを含む〉が通信内容をログ収集できない
  設計とする)。
- **1クリック/1コマンドでのセットアップ**を目指す(Outline VPNのDocker
  ベースの手軽さ、Algo VPNのシンプルなインストールスクリプトを参考に)。

## 技術選定(2026-09-27調査完了)

### プロトコル: WireGuard+AmneziaWGとVLESS+REALITYを並行して同時開発(2026-09-27最終決定)

Google検索・GitHub調査で2026年時点の実情を調査した結果を比較する。

| 方式 | 検閲耐性 | 性能 | 備考 |
|---|---|---|---|
| 素のShadowsocks | 2026年時点では単体では強い検閲に対して不十分になってきている | 中(shadowsocks-2022はむしろ高速) | 検出技術の進歩が速く、単体使用は非推奨との指摘あり |
| 素のWireGuard | UDPの通信パターンが中国のGFW等の高度な検閲に検出されやすい | 高(カーネルモード実装で高速・軽量) | 検閲の無い/弱い環境では最有力 |
| AmneziaWG(WireGuardの難読化拡張) | WireGuardの通信を通常のHTTPS風に偽装し、DPI回避に有効 | 高(WireGuardベースを維持) | 2026年時点でDPI対策として有効との評価 |
| VLESS + REALITY(Xray-core等) | 2026年時点の「業界標準」的な検閲回避方式。正規サイト(例: microsoft.com)のTLS証明書・ハンドシェイクをそのまま借用し、認証失敗時はそのターゲットサイトへ普通に転送するため、検閲側は「本物のサイトへのアクセス」と区別できない | 中〜高 | **再調査の結果、Rust実装は既に成熟**(下記参照)。当初「未成熟」と判断していたが誤りだった |

**再調査で判明した事実**: 当初「VLESS+REALITYはGo実装〈Xray-core〉が主体で
Rust実装は未成熟」と判断したが、GitHub上には実際に本番志向のRust実装が
複数存在する: [xray-lite](https://github.com/undead-undead/xray-lite)
(MPL-2.0、197★、348コミット、VLESS+REALITY+XHTTPを完全実装、
eBPF/XDPカーネル最適化版もあり)、
[rust-reality](https://github.com/jacek4yang/rust-reality)、
[xray-rust](https://github.com/aimalygin/xray-rust)。この事実誤認を
ユーザーに指摘され、判断を訂正した。

**最終決定**: **WireGuard+AmneziaWG(高速・軽量、検閲の弱い環境向け)と
VLESS+REALITY(正規サイトへの偽装により最も検出されにくい、検閲の強い
環境向け)を並行して同時開発**し、利用者が自分のネットワーク状況に応じて
プロトコルを選択できるようにする。いずれもboringtun/AmneziaWG/xray-lite等
のコードは流用せず、公開されているプロトコル仕様・設計思想のみを参考に
Rust + `open-web-server`/`RPoem`で一から実装する(既存方針どおり)。

### 配布形態・鍵管理(2026-09-27、鍵管理方針を決定)

- **配布形態**: VPS向けのセットアップスクリプト/コンテナイメージ、
  利用者端末向けのクライアントアプリ(Windows/macOS/Linux/Android/iPhone)。
- **鍵管理・利用者ごとのアクセス制御**: Outline VPNの「鍵ごとの帯域管理・
  失効の容易さ」を参考に設計する。
- **鍵の保存・取り扱い方針**: 秘密鍵・PSK等の実際の値は、**ローカル
  ドライブ上のディレクトリ・ファイル名を明示したファイル**(例:
  `F:\aruaru-vpn\secrets\<peer名>.key`)として管理し、**チャット上への
  コピー&ペーストや値の直接表示は行わない**(ファイルパスのみで参照する)。
  この方針・関連する注意書きは、日本語・英語に加えて利用者が選択している
  表示言語があれば、その言語にも翻訳して表示する。

## 関連リポジトリとの連携(2026-09-27方針、構想段階)

VLESS+REALITY(および将来的にはWireGuard+AmneziaWGも)の「検閲側のAI検知に
対抗する自然な通信」「高速・高セキュリティな暗号化」「クライアント管理UIの
高速描画」を実現するため、以下のaon-co-jpエコシステム内リポジトリと連携する
構想がある(いずれも各リポジトリ側が該当機能を提供できる段階になってから
実際の連携実装に着手する、現時点では構想のみ)。

- **[`aruaru-llm`](https://github.com/aon-co-jp/aruaru-llm)**: AIで通信
  パターン(パケットサイズ・送信タイミング等)を動的に調整し、検閲側の
  AIベースのトラフィック分類器による検知を回避しやすくする
  (「不自然に規則的な通信」を避け、実際の一般的な通信により近づける)。
- **[`open-cuda`](https://github.com/aon-co-jp/open-cuda)**: TLS/AES等の
  暗号処理、および`aruaru-llm`の推論処理をGPUで高速化する。
- **[`open-directx`](https://github.com/aon-co-jp/open-directx)**:
  `open-cuda`と共通の計算基盤を共有しつつ、クライアント管理アプリ
  (設定画面・通信統計表示等)のUIを高速描画する。DirectX互換の
  クロスプラットフォーム抽象化層という位置づけ(構想段階、実装はまだ無い)。

**現状の制約**: `open-cuda`・`open-directx`はいずれも標準構成の
README.md/CLAUDE.md/PORTING.mdが未整備で(`open-directx`はGitHub上に空
リポジトリのみ確認)、実体としての実装がまだ乏しい段階にある。連携実装は
これらのリポジトリ側の成熟を待ってから着手する。

## 開発方針

このリポジトリの開発ルールは[`open-raid-z`](https://github.com/aon-co-jp/open-raid-z)の
`CLAUDE.md`を正本とする、`aon-co-jp`エコシステム共通の運用ルール継承方針に従う。
詳細は[`CLAUDE.md`](CLAUDE.md)を参照。

## 透明性に関するお知らせ(必須表示)

`aruaru-vpn`を使ったWebアプリ/クライアントには、**目立つ場所に
クリックすると読める形で**[`TRANSPARENCY_NOTICE.md`](TRANSPARENCY_NOTICE.md)
(「これはaon-co-jpが運営する中継/VPNサービスではなく、利用者自身が
自分のVPS上に自分専用の中継を立てるためのテンプレートである」旨の説明)
へのリンクを設置すること(2026-09-27ユーザー指示)。日本語・英語が正本、
主要30言語への翻訳済み(`open-tv-chat`のサンプル言語リストと同じ30ヶ国語)、
残りはネイティブ検証を経て順次追加する。

## 現在の到達点

2026-09-27時点: リポジトリ新設、Outline VPN/Algo VPNのアーキテクチャ調査、
開発方針(用途を隠さない、利用者自身がVPSを運用する主体)の決定、
透明性告知文(日英+主要30言語)の作成まで完了。実装は未着手。次回再開
ポイントは[`PORTING.md`](PORTING.md)を参照。
