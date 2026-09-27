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

**決定(2026-09-27、ユーザー指示で同時開発に変更)**: **WireGuard型を基本
として採用**(Rust実装の[boringtun](https://github.com/cloudflare/boringtun)
がCloudflare製・BSD-3-Clauseで、iOS/Android/Cloudflareサーバーに数百万台
規模の実績がありRustエコシステムとして最も成熟しているため)し、
**AmneziaWG型の難読化層(HTTPS風に見せかけDPI/検閲を回避)を第一弾から
同時に開発する**(段階分けせず、最初から両方を一体のスコープとする)。
VLESS+REALITYはRust実装の未成熟さを理由に今回は見送り。詳細比較表は
[`README.md`](README.md)「技術選定」を参照。

## 次回再開ポイント

- 上記2(実装言語・基盤)の詳細、`boringtun`のアーキテクチャ調査(コードは
  流用せず、Noiseプロトコルハンドシェイク等の設計思想のみ参考にする)。
- **AmneziaWG型難読化層の設計**(WireGuard基本実装と同時開発、ユーザー
  指示2026-09-27): AmneziaWGの公開プロトコル仕様・設計思想(パケットの
  ヘッダー偽装・タイミング撹乱等でHTTPS風に見せる手法)をGoogle検索・
  GitHub調査で詳細調査した上で、コードは流用せず一から実装する。
- 上記3(配布形態)・4(鍵管理)の検討。
- 透明性告知文の残り約100言語への翻訳拡張、ネイティブ検証の依頼。
- 実際のWebアプリ/クライアントUIへの「目立つ場所へのリンク設置」実装
  (実装フェーズ未着手のため、クライアント実装と合わせて行う)。
