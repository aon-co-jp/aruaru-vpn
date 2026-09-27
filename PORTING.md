# PORTING (aruaru-vpn)

## 現状(2026-09-27)

リポジトリ新設直後。Outline VPN/Algo VPNのアーキテクチャ調査(Google検索、
公式サイト・関連記事)を`README.md`にまとめた段階。コード実装は0行。

## 経緯

[`open-tv-chat`](https://github.com/aon-co-jp/open-tv-chat)/
[`open-LiveKit`](https://github.com/aon-co-jp/open-LiveKit)の開発中、
「TV CHAT利用者向けに汎用VPNアプリも同時開発してはどうか」との提案があり、
以下の順で検討した。

1. 独立VPN事業として運営する案 → 各国のVPN法規制・運営者としての法的責任を
   理由に見送り(詳細は`open-LiveKit/PORTING.md`「8. 踏み台の用途スコープの
   検討経緯」)。
2. 「本来の目的(中継/プロキシ)を隠し、別の目的のWebサイトとして開発・
   配布してはどうか」との代替案 → **利用者に対して不誠実であり、検知回避
   ツールと見なされるリスクが高い**として見送り。
3. **最終的に、Outline VPN/Algo VPNと同じモデル(利用者自身が自分のVPS上に
   自分専用の中継を立てる、用途を隠さないOSSテンプレート)を採用**し、
   本リポジトリ`aruaru-vpn`を新設した。

## 調査結果: Outline VPN / Algo VPNのアーキテクチャ

| 項目 | Outline VPN | Algo VPN |
|---|---|---|
| 開発元 | Jigsaw(Google傘下) | Trail of Bits |
| プロトコル | Shadowsocks(検閲耐性重視、既知のハンドシェイクパターンが
  無く、通常の暗号化通信に見える) | WireGuard/IPSec(高速・軽量、ただし
  特徴的な通信パターンが検閲側に検出されやすい) |
| 配布形態 | サーバー側はDockerでホストOSから隔離、管理用GUIアプリ付き | 数個の
  コマンドで構築できるインストールスクリプト |
| 鍵管理 | 鍵ごとの帯域トラッキング・失効が容易 | (要追加調査) |
| 運営主体 | 利用者自身が自分のVPS上で運用(Jigsaw/Googleは中継を運営しない) | 同左 |

参照: [TechCrunch記事](https://techcrunch.com/2018/03/22/alphabets-outline-lets-you-build-your-own-vpn/)、
[Outline VPN公式](https://outline-vpn.com/)、
[Algo VPNリポジトリ](https://github.com/trailofbits/algo)。

## 未確定事項(次回セッションで詰める)

1. ~~プロトコル選定~~ → **2026-09-27完了**、下記「7. プロトコル選定」参照。
2. **実装言語・基盤**: Rust + `open-web-server`を軸にする想定。
   [boringtun](https://github.com/cloudflare/boringtun)(Cloudflare製、
   BSD-3-Clause)のアーキテクチャを参考にしつつコードは流用せず一から実装
   する。
3. **配布形態**: VPS向けセットアップスクリプト/コンテナイメージ、利用者
   端末向けクライアント(Windows/macOS/Linux/Android/iPhone)の両方が必要。
4. **鍵管理・利用者ごとのアクセス制御方式**。
5. **ドキュメント・配布文言における「用途の明示」の具体的な書き方**
   (README/ストア掲載文等で、誤解を招かない説明を作る)。

## 6. 透明性告知文の作成(2026-09-27完了)

ユーザー指示: 「用途を隠さないという説明を、英語・日本語・世界約130ヶ国語に
翻訳して、aruaru-vpnの利用者全員に目立つ場所でリンクをクリックすると読める
ように」を受け、[`TRANSPARENCY_NOTICE.md`](TRANSPARENCY_NOTICE.md)を作成。
日本語・英語を正本とし、`open-tv-chat`の対応言語サンプル30ヶ国語と同じ
言語セットへ翻訳した(効率のため既存の言語リストを再利用)。AI翻訳のため
ネイティブ検証前である旨を明記。残り約100言語は今後追加。

## 7. プロトコル選定(2026-09-27完了)

Shadowsocks型/WireGuard型/AmneziaWG型/VLESS+REALITY型をGoogle検索で比較調査
(2026年時点の実情: 素のShadowsocksは強い検閲に単体では不十分になりつつある、
素のWireGuardは高性能だがUDPパターンがGFW等に検出されやすい、AmneziaWGは
WireGuardをHTTPS風に難読化しDPI対策に有効、VLESS+REALITYは2026年時点の
検閲回避の実質的業界標準だが主要実装がGo〈Xray-core〉でRust実装は未成熟)。

**当初の判断(誤り)**: VLESS+REALITYはRust実装が未成熟と判断し見送った。

**再調査(2026-09-27、ユーザーから「世界中の言語でGoogle検索・GitHub調査を
した上で冷静に検討して」との指示)**: 実際にはGitHub上に本番志向のRust実装
が複数存在することが判明した([xray-lite](https://github.com/undead-undead/xray-lite)
はMPL-2.0・197★・348コミットでVLESS+REALITY+XHTTPを完全実装、
eBPF/XDPカーネル最適化版もあり。他に[rust-reality](https://github.com/jacek4yang/rust-reality)、
[xray-rust](https://github.com/aimalygin/xray-rust)も存在)。REALITYの
仕組み(正規サイトのTLS証明書・ハンドシェイクを借用し、認証失敗時はその
サイトへ普通に転送するため検閲側が区別できない)も確認した。この事実誤認を
ユーザーに指摘され、判断を訂正した。

**最終決定**: **WireGuard型+AmneziaWG型難読化層(高速・軽量、検閲の弱い
環境向け)と、VLESS+REALITY型(検閲の強い環境向け、最も検出されにくい)を
並行して同時開発**する。利用者がネットワーク状況に応じてプロトコルを
選択できるようにする。いずれもコードは流用せず、公開仕様・設計思想のみを
参考にRust + `open-web-server`/`RPoem`で一から実装する。詳細比較表は
[`README.md`](README.md)「技術選定」を参照。

## 8. 関連リポジトリとの連携方針(2026-09-27、構想段階)

ユーザーから「VLESS+REALITYをopen-directx・open-cuda・aruaru-llm等の関連
リポジトリも使って一緒に駆使してほしい」との指示があり、各リポジトリの
役割を確認した上で以下の構想を決定した(詳細は[`README.md`](README.md)
「関連リポジトリとの連携」参照)。

- `aruaru-llm`: AIで通信パターンを動的調整し、検閲側のAIトラフィック
  分類器による検知を回避しやすくする。
- `open-cuda`: 暗号処理・`aruaru-llm`推論のGPU高速化。
- `open-directx`: `open-cuda`と共通の計算基盤を共有しつつ、クライアント
  管理UIの高速描画に使う。

**現状の制約**: `open-cuda`はREADME.md/CLAUDE.md/PORTING.mdが未整備、
`open-directx`はGitHub上に空リポジトリのみで実体が無い(いずれも
`runo`のREADME.mdに記載済みの既知の状態)。よって連携実装は今すぐには
着手できず、これらのリポジトリ側の成熟を待つ必要がある。VLESS+REALITY
本体の実装(プロトコル部分)は連携なしでも進められるため、まずはプロトコル
本体を単独で実装し、連携部分は各リポジトリの状況を見ながら段階的に
組み込む方針とする。

## 次回再開ポイント

- 上記2(実装言語・基盤)の詳細、`boringtun`のアーキテクチャ調査(コードは
  流用せず、Noiseプロトコルハンドシェイク等の設計思想のみ参考にする)。
- **VLESS+REALITY型の詳細設計**: REALITYのTLSハンドシェイク偽装・uTLS
  指紋偽装・認証失敗時のトラフィック転送の仕組みを、`xray-lite`等の
  アーキテクチャ(コードは流用せず)を参考に、Rust + `RPoem`で一から
  設計する。
- **AmneziaWG型難読化層の設計**(WireGuard基本実装と同時開発、ユーザー
  指示2026-09-27): AmneziaWGの公開プロトコル仕様・設計思想(パケットの
  ヘッダー偽装・タイミング撹乱等でHTTPS風に見せる手法)をGoogle検索・
  GitHub調査で詳細調査した上で、コードは流用せず一から実装する。
- 上記3(配布形態)・4(鍵管理)の検討。
- 透明性告知文の残り約100言語への翻訳拡張、ネイティブ検証の依頼。
- 実際のWebアプリ/クライアントUIへの「目立つ場所へのリンク設置」実装
  (実装フェーズ未着手のため、クライアント実装と合わせて行う)。
