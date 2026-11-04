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

2026-09-30時点(実装フェーズ18完了、`cargo test`で84テスト全通過):

- REALITY認証(X25519 ECDH)→本物の証明書チェーンを偽装先サイトから
  実際に借用したTLS 1.3ハンドシェイク(`cert_clone`、
  [rustls](https://crates.io/crates/rustls)の公開拡張点を使い、rustls自体は
  フォークせず実装、証明書チェーンはTTL付きキャッシュを使用)→VLESS UUID
  検証→実TCP/UDP/Mux中継、まで実配線・動作確認済み(本物の`rustls`
  クライアントを使ったフルパイプラインend-to-endテストが実際に成功)。
- ブラウザTLS指紋偽装(uTLS相当、部分的): 暗号スイート順序・鍵交換グループ・
  ALPN・署名アルゴリズム一覧をChromeに寄せる(`rustls`の公開APIの限界内、
  拡張の並び順・GREASEは未実現)。[RPoem](https://github.com/aon-co-jp/RPoem)
  の`open-runo-tls-fingerprint`crateとして共通ライブラリ化し、他プロジェクト
  からも再利用可能。
- `Command::Mux`([`src/mux.rs`](src/mux.rs)、`Mux.Cool`風の独自フレーム
  設計)で1本のセッションの中に複数の独立したサブストリームを多重化可能。
- `secure_channel`(独自AEADフレーミング)経由の代替経路も併存
  (`Command::Udp`/`Mux`対応済み)。
- 鍵管理GUI([`src/bin/keys_gui.rs`](src/bin/keys_gui.rs)、egui/eframe+rfd)。
- 透明性告知文(日英+主要30言語、AIによる自己レビュー実施済み・
  ネイティブ検証は未実施)。

未着手・既知の制約は[`CLAUDE.md`](CLAUDE.md)「HANDOFF」節、詳細な設計判断・
実装経緯は[`PORTING.md`](PORTING.md)を参照。

## Current Status (English summary)

As of 2026-09-30 (implementation phase 18, `cargo test`: 84/84 passing):

- REALITY authentication (X25519 ECDH) → a real TLS 1.3 handshake that
  borrows a genuine certificate chain live from the camouflage target site
  (`cert_clone`, built on [rustls](https://crates.io/crates/rustls)'s public
  extension points — `SigningKey`, `ServerCertVerifier`, `SupportedKxGroup` —
  without forking rustls itself, certificate chains are now cached with a
  TTL) → VLESS UUID validation → real TCP/UDP/Mux relaying, all wired up
  and verified end-to-end with a real `rustls` client.
- Browser TLS fingerprint mimicry (uTLS-equivalent, partial): cipher suite
  order, key-exchange groups, ALPN and the signature-algorithm list are
  tuned to look like Chrome, within what rustls's public API allows
  (extension ordering and GREASE remain out of reach). Extracted into the
  `open-runo-tls-fingerprint` crate in
  [RPoem](https://github.com/aon-co-jp/RPoem) so other projects can reuse it.
- `Command::Mux` ([`src/mux.rs`](src/mux.rs), a `Mux.Cool`-inspired custom
  frame design) multiplexes several independent sub-streams over one
  session.
- An alternative path over `secure_channel` (a custom AEAD framing) also
  exists (`Command::Udp`/`Mux` supported there too).
- A native key-management GUI ([`src/bin/keys_gui.rs`](src/bin/keys_gui.rs),
  egui/eframe + rfd).
- The transparency notice (Japanese/English plus ~30 languages), with an
  AI self-review pass completed — native-speaker verification is still
  outstanding for all languages.

See [`CLAUDE.md`](CLAUDE.md) ("HANDOFF") for open items and known
limitations, and [`PORTING.md`](PORTING.md) for the detailed design
history (notably phase 28: why the `craftls` fork wasn't adopted, and the
partial fingerprint-mimicry scope that rustls's public API allows).

---

作者 / Author: 石 塚 正 浩（MASAHIRO ISHIZUKA） (https://github.com/aon-co-jp)

## API 方針: REST 全廃・gRPC / Connect へ (2026-11-04)

### 日本語
- **REST は全廃する。新しい API は REST で作らない。** ブラウザや `curl` から呼ぶ API は **Connect の単純呼び出し**(`POST /<パッケージ>.<Service>/<Method>`、`content-type: application/json`、本文は JSON)、サービス間は **gRPC / gRPC-web**(RPoem の管理API `open_runo.admin.v1.Admin` と同じ流儀)。ストリーミングは、必要になってから。
- **既存の REST は、触るときに順に移す。** 移したら旧 REST の経路は消す。移行が終わるまで残るが、**新規には追加しない**。
- **JSON は RS-JSON に統一**する(読み込みは `from_str_secure` / `parse_secure` でサイズ・深さ・重複キーの上限つき、書き出しは `rust_json::fast`)。ブラウザの WASM に `prost` は入れない(サイズが増えるため)。
- **例外(自分たちの API ではなく、相手の規格が決めているもの)**: ACME、OAuth/OIDC のコールバック、第三者(GitHub など)からの Webhook、ヘルスチェック、静的ファイル配信、OTLP など。これらは規格どおりの HTTP を受ける。
- 参考実装: `RPoem`(`open_runo.admin.v1.Admin`)、`open-easy-web`(`server/src/connect.rs`、`proto/open_easy_web/admin/v1/admin.proto`)。
- ※ このリポジトリのコードが既に方針どおりかどうかは、各リポジトリの現状による。この節は方針の記録であり、コードの変更を意味しない。

### English
- **REST is being abolished. New APIs are not built as REST.** APIs called from browsers or `curl` use **Connect unary calls** (`POST /<package>.<Service>/<Method>`, `content-type: application/json`, JSON body); service-to-service calls use **gRPC / gRPC-web** (the same style as RPoem's admin API `open_runo.admin.v1.Admin`). Streaming only when it is actually needed.
- **Existing REST endpoints are migrated one by one, when they are touched.** The old REST route is removed once migrated. Until migration is finished they remain, but **no new ones are added**.
- **JSON is unified on RS-JSON**: reading with `from_str_secure` / `parse_secure` (size, depth and duplicate-key limits), writing with `rust_json::fast`. `prost` is not put into browser WASM (it would grow the binary).
- **Exceptions (shapes dictated by someone else's standard, not our own API)**: ACME, OAuth/OIDC callbacks, webhooks from third parties (e.g. GitHub), health checks, static file serving, OTLP, and so on. These accept plain HTTP as the standard requires.
- Reference implementations: `RPoem` (`open_runo.admin.v1.Admin`) and `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Note: whether the code in a given repository already follows this policy depends on that repository. This section records the policy; it does not mean the code has been changed.

### Deutsch (KI-Übersetzung, redaktionell überarbeitet; noch nicht von Muttersprachlern geprüft)
- **REST wird vollständig abgeschafft; neue APIs entstehen nicht mehr als REST.** APIs, die aus dem Browser oder per `curl` aufgerufen werden, verwenden **unäre Connect-Aufrufe** (`POST /<Paket>.<Service>/<Methode>`, `content-type: application/json`, JSON-Body). Zwischen Diensten kommen **gRPC bzw. gRPC-web** zum Einsatz, im selben Stil wie die Admin-API von RPoem (`open_runo.admin.v1.Admin`). Streaming wird erst ergänzt, wenn es tatsächlich gebraucht wird.
- **Bestehende REST-Endpunkte werden schrittweise umgestellt, und zwar immer dann, wenn man ohnehin an ihnen arbeitet.** Sobald ein Endpunkt umgestellt ist, wird die alte REST-Route entfernt. Bis zum Abschluss der Migration bleiben die übrigen bestehen, es werden aber **keine neuen mehr hinzugefügt**.
- **JSON wird einheitlich über RS-JSON verarbeitet**: Gelesen wird mit `from_str_secure` bzw. `parse_secure` (mit Obergrenzen für Größe, Verschachtelungstiefe und doppelte Schlüssel), geschrieben mit `rust_json::fast`. `prost` wird nicht in das Browser-WASM aufgenommen, da es die Datei vergrößern würde.
- **Ausnahmen (Schnittstellen, deren Form ein fremder Standard vorgibt und die nicht zu unserer eigenen API gehören)**: ACME, OAuth/OIDC-Callbacks, Webhooks von Drittanbietern (z. B. GitHub), Health-Checks, die Auslieferung statischer Dateien, OTLP und Ähnliches. Diese nehmen, wie vom jeweiligen Standard verlangt, gewöhnliches HTTP entgegen.
- Referenzimplementierungen: `RPoem` (`open_runo.admin.v1.Admin`) und `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Hinweis: Ob der Code eines einzelnen Repositorys diese Richtlinie bereits erfüllt, hängt vom jeweiligen Repository ab. Dieser Abschnitt dokumentiert lediglich die Richtlinie; er besagt nicht, dass der Code schon angepasst wurde.

### Русский (перевод выполнен с помощью ИИ и отредактирован; носителями языка пока не проверен)
- **От REST мы полностью отказываемся; новые API больше не создаются в стиле REST.** API, к которым обращаются из браузера или через `curl`, используют **унарные вызовы Connect** (`POST /<пакет>.<Service>/<Method>`, `content-type: application/json`, тело запроса — JSON). Для взаимодействия между сервисами применяются **gRPC и gRPC-web** — в том же стиле, что и административный API RPoem (`open_runo.admin.v1.Admin`). Потоковая передача данных добавляется лишь тогда, когда в ней действительно возникает необходимость.
- **Существующие REST-эндпоинты переводятся поэтапно — по мере того, как с ними приходится работать.** После перевода старый REST-маршрут удаляется. Пока миграция не завершена, оставшиеся эндпоинты сохраняются, но **новые не добавляются**.
- **Работа с JSON унифицирована на основе RS-JSON**: чтение — через `from_str_secure` или `parse_secure` (с ограничениями на размер, глубину вложенности и повторяющиеся ключи), запись — через `rust_json::fast`. `prost` в браузерный WASM не включается, поскольку это увеличило бы размер файла.
- **Исключения (интерфейсы, форму которых определяет чужой стандарт, а не наш собственный API)**: ACME, обратные вызовы OAuth/OIDC, вебхуки сторонних сервисов (например, GitHub), проверки работоспособности, раздача статических файлов, OTLP и тому подобное. Такие интерфейсы принимают обычный HTTP, как того требует соответствующий стандарт.
- Эталонные реализации: `RPoem` (`open_runo.admin.v1.Admin`) и `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Примечание: соответствует ли код конкретного репозитория этой политике, зависит от самого репозитория. Данный раздел лишь фиксирует политику и не означает, что код уже изменён.

## API 方針の補足: 用語の整理と使い分け (2026-11-04)

### 日本語
**1つに統一するものではなく、別の層の話です。** 「REST の代わり」になるのは Connect・gRPC・GraphQL だけで、WASM は画面を作る技術です。

| 用語 | 何か | REST の代わりか |
|---|---|---|
| REST | URL と HTTP メソッドで操作を表す API の作り方 | 全廃する側 |
| **Connect** | `POST /サービス名/メソッド名` に JSON を送る形式。`curl` でもブラウザの `fetch` でも呼べる | はい(**採用**) |
| **gRPC** | 同じ「サービス/メソッド」の考え方を、バイナリ(protobuf)と HTTP/2 で行う形式。速く、ストリーミングも得意 | はい(**サービス同士に採用**) |
| gRPC-web | gRPC のブラウザ向けの変形版 | はい(必要なら) |
| GraphQL | 欲しい項目を問い合わせる形式 | 一部だけ(**問い合わせ(読み取り)専用**) |
| WASM | Rust をブラウザの中で動かす仕組み | いいえ(画面を作る技術) |

- **ブラウザの画面や `curl` から呼ぶ API は Connect**(POST、JSON を RS-JSON で読み書き)。ブラウザの WASM は素の gRPC を話せず、Connect なら `fetch` のままで、`prost` を足さずに済む(画面のサイズも増えない)。
- **サービス同士の通信(サーバー間、重い処理、ストリーミング)は gRPC。** 多くは Connect で足りるので、ストリーミングが必要になった所だけ gRPC に上げる。
- **GraphQL は、まとめて問い合わせたいときの読み取り専用。** 書き込み(操作)には使わない。
- **WASM は画面を作る技術として、そのまま使う。** 画面から呼ぶ API が Connect になっただけ。
- 外部の規格が形を決めるもの(ACME、OAuth のコールバック、第三者の Webhook、ヘルスチェック、静的ファイル、OTLP)は、規格どおりの HTTP のまま。
- **迷ったら Connect。**

### English
**These are not alternatives to unify; they sit at different layers.** Only Connect, gRPC and GraphQL can replace REST; WASM is a way to build the UI.

| Term | What it is | Replaces REST? |
|---|---|---|
| REST | API style that expresses operations through URLs and HTTP methods | The thing being abolished |
| **Connect** | `POST /Service/Method` with a JSON body; callable from `curl` and from a browser `fetch` | Yes (**adopted**) |
| **gRPC** | The same service/method idea over binary (protobuf) and HTTP/2; fast, good at streaming | Yes (**for service-to-service**) |
| gRPC-web | A browser-friendly variant of gRPC | Yes (if needed) |
| GraphQL | A query language: ask for exactly the fields you want | Partly (**read-only queries**) |
| WASM | Runs Rust inside the browser | No (a UI technology) |

- **APIs called from browser screens or `curl` use Connect** (POST, JSON read and written with RS-JSON). Browser WASM cannot speak plain gRPC; with Connect it stays a `fetch`, and `prost` is not needed (the binary does not grow).
- **Service-to-service calls (server to server, heavy work, streaming) use gRPC.** Connect is enough in most places; move a call to gRPC only where streaming is actually needed.
- **GraphQL is read-only**, for queries that gather several pieces of data. It is not used for writes (operations).
- **WASM stays as the way to build the UI.** The API it calls simply became Connect.
- Interfaces whose shape an outside standard dictates (ACME, OAuth callbacks, third-party webhooks, health checks, static files, OTLP) stay plain HTTP.
- **When in doubt, use Connect.**

### Deutsch (KI-Übersetzung, sprachlich überarbeitet; noch nicht von Muttersprachlern geprüft)
**Es geht nicht darum, eine einzige Technik auszuwählen – die Begriffe liegen auf unterschiedlichen Ebenen.** Als Ersatz für REST kommen nur Connect, gRPC und GraphQL in Frage; WASM dagegen ist eine Technik, mit der die Benutzeroberfläche gebaut wird.

| Begriff | Was ist das? | Ersatz für REST? |
|---|---|---|
| REST | Ein API-Stil, bei dem Operationen über URLs und HTTP-Methoden ausgedrückt werden | wird abgeschafft |
| **Connect** | `POST /Dienst/Methode` mit JSON im Body; aufrufbar mit `curl` ebenso wie mit `fetch` im Browser | ja (**gewählt**) |
| **gRPC** | Dasselbe Prinzip aus Dienst und Methode, aber über binäres protobuf und HTTP/2; schnell und gut für Streaming geeignet | ja (**zwischen Diensten**) |
| gRPC-web | Eine für den Browser angepasste Variante von gRPC | ja (bei Bedarf) |
| GraphQL | Abfragesprache, mit der man genau die benötigten Felder anfordert | teilweise (**nur für lesende Abfragen**) |
| WASM | Führt Rust-Code direkt im Browser aus | nein (Technik für die Oberfläche) |

- **APIs, die von Browseroberflächen oder per `curl` aufgerufen werden, verwenden Connect** (POST; JSON wird mit RS-JSON gelesen und geschrieben). WASM im Browser kann kein reines gRPC sprechen. Mit Connect bleibt es bei einem gewöhnlichen `fetch`, und `prost` ist nicht nötig – die WASM-Datei wird dadurch nicht größer.
- **Für die Kommunikation zwischen Diensten (Server zu Server, rechenintensive Aufgaben, Streaming) wird gRPC eingesetzt.** In den meisten Fällen reicht Connect aus; auf gRPC wird nur dort umgestellt, wo Streaming tatsächlich gebraucht wird.
- **GraphQL dient ausschließlich lesenden Abfragen**, wenn mehrere Informationen gebündelt abgefragt werden sollen. Für Schreibzugriffe (Operationen) wird es nicht verwendet.
- **WASM bleibt die Technik für die Oberfläche.** Geändert hat sich lediglich, dass die aufgerufene API nun auf Connect beruht.
- Schnittstellen, deren Form durch einen externen Standard festgelegt ist (ACME, OAuth-Callbacks, Webhooks von Drittanbietern, Health-Checks, statische Dateien, OTLP), bleiben gewöhnliches HTTP.
- **Im Zweifel: Connect.**

### Русский (перевод выполнен с помощью ИИ и литературно отредактирован; носителями языка пока не проверен)
**Это не варианты, из которых нужно выбрать один, а технологии разных уровней.** Заменить REST могут только Connect, gRPC и GraphQL; WASM же — это способ создания пользовательского интерфейса.

| Термин | Что это | Заменяет REST? |
|---|---|---|
| REST | Стиль построения API, при котором операции выражаются через URL и HTTP-методы | отменяется |
| **Connect** | `POST /Сервис/Метод` с телом в формате JSON; вызывается как из `curl`, так и из браузерного `fetch` | да (**выбран**) |
| **gRPC** | Тот же принцип «сервис — метод», но поверх двоичного формата protobuf и HTTP/2; работает быстро и хорошо подходит для потоковой передачи | да (**для связи между сервисами**) |
| gRPC-web | Адаптированный для браузера вариант gRPC | да (при необходимости) |
| GraphQL | Язык запросов: клиент запрашивает ровно те поля, которые ему нужны | частично (**только запросы на чтение**) |
| WASM | Позволяет выполнять код на Rust прямо в браузере | нет (технология для интерфейса) |

- **API, которые вызываются из браузерных интерфейсов или через `curl`, строятся на Connect** (POST; JSON читается и записывается через RS-JSON). Браузерный WASM не умеет работать с «чистым» gRPC. С Connect достаточно обычного `fetch`, а `prost` не требуется — размер WASM-файла не увеличивается.
- **Для обмена между сервисами (сервер — сервер, ресурсоёмкие задачи, потоковая передача) применяется gRPC.** В большинстве случаев достаточно Connect; на gRPC переходят только там, где потоковая передача действительно необходима.
- **GraphQL используется только для чтения**, когда нужно получить сразу несколько связанных данных. Для записи (операций) он не применяется.
- **WASM по-прежнему остаётся технологией для интерфейса.** Изменилось лишь то, что вызываемый им API теперь построен на Connect.
- Интерфейсы, форма которых задана внешним стандартом (ACME, обратные вызовы OAuth, вебхуки сторонних сервисов, проверки работоспособности, статические файлы, OTLP), остаются обычным HTTP.
- **Если есть сомнения — выбирайте Connect.**
