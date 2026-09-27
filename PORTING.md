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

1. **プロトコル選定**: Shadowsocks型(検閲耐性重視)かWireGuard型
   (速度重視)か、あるいは両対応か。`open-tv-chat`の通話トラフィックとは
   別物(こちらは汎用インターネットアクセス全般が対象)なので、
   `open-LiveKit`の踏み台とは独立した技術選定が必要。
2. **実装言語・基盤**: Rust + `open-web-server`を軸にする想定だが、
   Shadowsocks/WireGuardの既存Rust実装(参考にする範囲・流用しない範囲の
   線引き含む)の調査が必要。
3. **配布形態**: VPS向けセットアップスクリプト/コンテナイメージ、利用者
   端末向けクライアント(Windows/macOS/Linux/Android/iPhone)の両方が必要。
4. **鍵管理・利用者ごとのアクセス制御方式**。
5. **ドキュメント・配布文言における「用途の明示」の具体的な書き方**
   (README/ストア掲載文等で、誤解を招かない説明を作る)。

## 次回再開ポイント

上記1(プロトコル選定)から、Google検索・GitHub調査を経てじっくり検討する
(`open-LiveKit`と同じ開発姿勢)。決め打ちせず、比較表を作ってから決定する。
