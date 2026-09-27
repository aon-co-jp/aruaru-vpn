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

## 技術選定(未着手、次回セッション以降でじっくり検討)

- **プロトコル**: Shadowsocks型(検閲耐性が高いが実装がやや複雑)か
  WireGuard型(高速・軽量だが特徴的な通信パターンが検出されやすい)か、
  実装時に比較検討する。
- **配布形態**: VPS向けのセットアップスクリプト/コンテナイメージ、
  利用者端末向けのクライアントアプリ(Windows/macOS/Linux/Android/iPhone)。
- **鍵管理・利用者ごとのアクセス制御**: Outline VPNの「鍵ごとの帯域管理・
  失効の容易さ」を参考に設計する。

## 開発方針

このリポジトリの開発ルールは[`open-raid-z`](https://github.com/aon-co-jp/open-raid-z)の
`CLAUDE.md`を正本とする、`aon-co-jp`エコシステム共通の運用ルール継承方針に従う。
詳細は[`CLAUDE.md`](CLAUDE.md)を参照。

## 現在の到達点

2026-09-27時点: リポジトリ新設、Outline VPN/Algo VPNのアーキテクチャ調査と
開発方針(用途を隠さない、利用者自身がVPSを運用する主体)の決定のみ。
実装は未着手。次回再開ポイントは[`PORTING.md`](PORTING.md)を参照。
