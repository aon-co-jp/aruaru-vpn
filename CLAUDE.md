# 開発方針＆開発環境ルール(aruaru-vpn)

作業ドライブは`F:\aruaru-vpn`。この節は
[`open-raid-z`](https://github.com/aon-co-jp/open-raid-z)の`CLAUDE.md`を
**正本**とし、各プロジェクトへコピーして同期する既存の運用ルール継承方針に
準じる(比較的新しいフレームワークの参照資料一覧・AI駆動開発ツールに関する
所感・確認不要の自動継続/リミット解除後の自動再開・白画面バグ等を見逃さない
検証徹底、等の全リポジトリ共通ルールは、詳細をここに複製せず
`open-raid-z/CLAUDE.md`を参照すること)。

## このリポジトリの役割

[Outline VPN](https://getoutline.org/)・[Algo VPN](https://github.com/trailofbits/algo)を
参考に、コードを一切流用せず一からRust + `open-web-server`で再実装する、
「利用者が自分で借りたVPS上に、自分専用のプライバシー中継(VPN)を立てられる」
OSSテンプレート。**aon-co-jpは中継サーバーを運営しない**(テンプレートの
配布のみ)。詳細な構想・開発の経緯は[`README.md`](README.md)を参照。

## 最重要方針: 用途を隠さない(2026-09-27決定)

このリポジトリの存在意義は「正直さ」にある。開発・ドキュメント・配布方法の
いずれにおいても、以下を徹底すること:

- **本来の機能を偽装したり、別の目的のアプリであるかのように見せかけたりしない**。
  README・アプリの説明・ストア掲載文等すべてで「これは自分専用のVPN/中継
  サーバーを自分のVPS上に立てるためのツールである」ことを明記する。
- **aon-co-jpが中継サーバー自体を運営することはない**。運営責任は常に
  「自分のVPSに自分でセットアップした利用者本人」にある、という設計・
  説明を崩さないこと。この一線を越えると、`open-LiveKit`側で見送った
  「VPN事業者としての法的責任」の議論が再燃するため、実装時も常に
  この境界を意識すること。

## 開発の経緯(なぜこのリポジトリが生まれたか)

`open-tv-chat`/`open-LiveKit`の開発中に「TV CHAT利用者向けの汎用VPNアプリも
同時開発してはどうか」という提案があり、(1)独立VPN事業として運営する案
(法的リスクで見送り)→(2)本来の目的を隠して別サイトとして配布する案
(不誠実・検知回避ツール認定リスクで見送り)→(3)Outline VPN/Algo VPN型の
「利用者自身がVPSを運用する、用途を隠さないOSSテンプレート」に着地、という
経緯を経ている。詳細は[`README.md`](README.md)「開発の経緯」、
[`open-LiveKit`のPORTING.md](https://github.com/aon-co-jp/open-LiveKit/blob/main/PORTING.md)
「8. 踏み台の用途スコープの検討経緯」を参照。

## 技術方針

- **プロトコル**: **WireGuard+AmneziaWG型(高速・軽量)と
  VLESS+REALITY型(検閲耐性最強、TLS偽装)を並行して同時開発**する
  (2026-09-27最終決定)。当初VLESS+REALITYは「Rust実装未成熟」を理由に
  見送ったが、ユーザーから「世界中の言語でGoogle検索・GitHub調査をして
  冷静に検討して」と再検討を求められ、実際には[xray-lite](https://github.com/undead-undead/xray-lite)
  等の本番志向Rust実装が既に存在することが判明し、判断を訂正した
  (**事実誤認は必ず訂正すること**、というエコシステム共通の教訓)。
- 配布形態・鍵管理方式は未確定。[`README.md`](README.md)「技術選定」を
  参照。決め打ちせず、実装着手時にGoogle検索・GitHub調査を経て決定する
  (`open-LiveKit`と同じ開発姿勢)。

## 関連リポジトリとの連携(構想段階、2026-09-27)

`aruaru-llm`(AIによる通信パターン擬態)・`open-cuda`(暗号処理/AI推論の
GPU高速化)・`open-directx`(クライアント管理UIの高速描画、open-cudaと
計算基盤共有)と連携する構想がある。ただし`open-cuda`/`open-directx`は
現状README/CLAUDE.md/PORTING.mdが未整備・実体が乏しく、連携実装は
これらの成熟を待つ。VLESS+REALITY本体の実装は連携なしで進める。詳細は
[`README.md`](README.md)「関連リポジトリとの連携」、
[`PORTING.md`](PORTING.md)「8. 関連リポジトリとの連携方針」を参照。

## HANDOFF

- **2026-09-27 実装フェーズ1完了**: `cargo init`でRustプロジェクトを作成。
  [`src/reality.rs`](src/reality.rs)にREALITYの核心ロジック(認証判定→
  フォールバック転送)、[`src/integration.rs`](src/integration.rs)に
  `aruaru-llm`/`open-cuda`向けの連携トレイト(既定は何もしないフォール
  バック実装、両リポジトリが育ったら差し替え可能)を実装。`cargo test`で
  8テスト全通過。実TLS層への統合(uTLS指紋偽装等)は未着手。
- **2026-09-27 リポジトリ新設+プロトコル選定(2回改訂)**:
  `aon-co-jp/aruaru-vpn`を新規作成。Outline VPN/Algo VPNのアーキテクチャ
  調査、開発方針(用途を隠さない、aon-co-jpは中継を運営しない)、透明性
  告知文(日英+主要30ヶ国語)を作成。プロトコルは当初WireGuard+AmneziaWG
  のみに決定したが、ユーザーから「VLESS+REALITYもRust+RPoemで世界中の
  言語でGoogle検索・GitHub調査して冷静に検討して」と再調査を求められ、
  「Rust実装は未成熟」という当初判断が誤りだったと判明(xray-lite等の
  本番志向実装が実在)。最終的に**WireGuard+AmneziaWGとVLESS+REALITYを
  並行して同時開発**する方針に確定。実装は未着手。次回再開時は
  [`PORTING.md`](PORTING.md)の「次回再開ポイント」を参照。
