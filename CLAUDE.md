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

## 重要方針: 暗号プリミティブは自作しない(2026-09-27決定)

「既存実装のコードを一切流用せず一から開発する」というエコシステム共通
方針は、**アプリケーション/プロトコルのアーキテクチャ**に適用するもので
あり、**暗号アルゴリズムそのもの(X25519・AES・ChaCha20・SHA-2・Noise
プロトコル等)の独自実装には適用しない**。暗号プリミティブを自作する
ことは、たとえ動いているように見えても重大な脆弱性を生みやすい、
というのが暗号工学における一般的な原則であるため、監査済みの
Rust crate([x25519-dalek](https://crates.io/crates/x25519-dalek)、
[hkdf](https://crates.io/crates/hkdf)、[snow](https://crates.io/crates/snow)
等)に委ねる。参考にする範囲は「これらのライブラリの上にどう
REALITY/WireGuard相当のプロトコルを組み立てるか」というアーキテクチャ
部分のみ。

## 鍵管理方針: ローカルファイル経由、チャットへの貼り付け・表示禁止(2026-09-27決定)

秘密鍵・PSK(事前共有鍵)等の実際の値は、**必ずローカルドライブ上のファイル
として管理し、チャット上にコピー&ペーストしたり、そのまま表示したりしない**
([`feedback_keys_via_files_never_echo.md`]記憶メモの既存方針と同じ)。

- **保存場所**: `F:\aruaru-vpn\secrets\<peer名>.key`のように、ディレクトリと
  ファイル名を明示的に指定する形で保存する(実装時に実際のパス規約を確定)。
- **チャットでのやり取り**: 鍵の値そのものではなく、**ファイルパスだけ**を
  チャット上で参照する。値を貼り付けたり、コミット・ログに残したりしない。
- **多言語表示**: この方針や関連する注意書きを利用者に説明する際、日本語・
  英語に加えて利用者が選択している表示言語がある場合は、その言語にも
  翻訳して表示する(2026-09-27ユーザー指示。`open-tv-chat`の多言語対応
  ポリシーと同じ考え方)。

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

- **2026-09-28 実装フェーズ10完了(独自セキュアトランスポート+実配線、
  致命的バグ2件を発見・修正)**: `rustls`ベースのTLS終端を実配線しようと
  したところ、私たちのREALITY認証(ClientHelloの`session_id`欄への
  非標準な認証タグ埋め込み)が標準TLSライブラリと根本的に非互換だと
  判明。ユーザーと相談し、完全なTLS 1.3準拠(既存ライブラリとの相互
  接続性)は目指さず、**REALITY認証で確立済みのX25519共有鍵からAEAD
  暗号化レコード層を独自導出する「自前の最小限のセキュアトランスポート」**
  ([`src/secure_channel.rs`](src/secure_channel.rs)、ChaCha20-Poly1305は
  監査済みcrateに委ね自作しない)を実装。`accept_and_route`/
  `handle_relay_session_secure`([`src/net.rs`](src/net.rs))へ実配線し、
  フルパイプラインのend-to-endテストを書いたところ、**(1)
  `tokio::io::split`の片方向クローズを誤解した実装によるデッドロック、
  (2)TLSレコード境界を超えた「まとめ読み」によるバイト列消失、という
  致命的なバグ2件**を発見・修正(`SecureWriter::shutdown()`の追加、
  `read_exactly_one_tls_record`への置き換え)。`cargo test`で65テスト
  全通過。証明書クローン・secure_channelのUDP/MUX対応・将来の本物の
  TLS 1.3準拠は引き続き未着手(ロードマップとして`PORTING.md`「20.」に記録)。
- **2026-09-28 実装フェーズ9完了(実TLS終端の試作品)**: [`src/tls_terminate.rs`](src/tls_terminate.rs)
  で`rustls`/`tokio-rustls`を使い、自己署名証明書(`rcgen`で動的生成)に
  よる実際のTLSハンドシェイク完了を実装。`PrefixedStream`で
  「既に読み取り済みのClientHello先頭バイトを巻き戻す」仕組みを作り、
  `accept_and_route`のような「最初に覗き見てから処理を続ける」設計と
  実TLSハンドシェイクが両立することを確認。ユーザーとの合意により、
  証明書クローン(偽装先サイトの本物証明書の流用)は次フェーズ、まずは
  自己署名証明書からスタート。`cargo test`で59テスト全通過。
- **2026-09-28 実装フェーズ8完了**: [`src/vless.rs`](src/vless.rs)に
  `AllowedUuids`/`validate_uuid`を追加し、VLESS自身のUUIDによる二段構え
  認証(輸送路のREALITY/TLSとは別)を実装。`net.rs`の
  `handle_relay_session`にUUID検証を組み込み(未登録UUIDは宛先接続前に
  拒否)、`Command::Udp`の実処理(`relay_udp`)を追加して実UDPソケットでの
  往復をend-to-endで確認。`Command::Mux`は引き続き未対応。`cargo test`で
  58テスト全通過。
- **2026-09-28 実装フェーズ6・7完了**: [`src/key_storage.rs`](src/key_storage.rs)
  で秘密鍵/公開鍵の保存先ドライブ/ディレクトリを利用者が任意に選択できる
  ようにした(`KeyStorageConfig`)。「保存先を平文メモに自動記録する」機能は
  一度実装したがセキュリティ上の懸念(鍵ファイルの場所の手がかりを与える)
  でユーザー指摘により撤回・削除済み。続けて[`src/vless.rs`](src/vless.rs)
  にVLESSリクエストヘッダのパーサーを実装し、`net.rs`の`handle_relay_session`
  でREALITY認証通過後の接続が実際にVLESSの指定する宛先へ中継されることを
  end-to-endで確認。`cargo test`で53テスト全通過。UUID検証・UDP/MUX対応・
  実TLS終端との統合は未着手。
- **2026-09-28 実装フェーズ5完了+鍵管理方針決定**: [`src/net.rs`](src/net.rs)
  で全モジュールを実際のTCP/UDPソケットに統合。`accept_and_route`で
  REALITY判定→認証失敗時は実TCP接続で偽装先へ双方向中継、
  `perform_handshake_over_udp`でWireGuard相当のハンドシェイクを実UDP越しに
  実施。テスト中に発見したバグ(モックサーバーの早期切断でWindows上
  `ConnectionReset`が発生)を、クライアント側の`shutdown()`を待ってから
  閉じる実装に修正。`cargo test`で39テスト全通過。あわせてユーザー指示
  により鍵管理方針(秘密鍵/PSKはローカルファイルのみで管理、チャットに
  値を貼り付け・表示しない、説明は日英+選択言語に翻訳)を決定。
- **2026-09-27 実装フェーズ4完了**: 未統合だった3項目を統合。(1)
  `tls_clienthello.rs`に`key_share`拡張パースを追加し
  `reality::decide_from_client_hello_record_x25519`でTLS層とX25519認証を
  接続、(2)`amnezia.rs`に`build_obfuscated_send_sequence`/
  `extract_real_handshake_message`を追加しWireGuardハンドシェイク
  メッセージをジャンクパケットに埋め込むend-to-end統合、(3)
  `wireguard_handshake.rs`にPSK(`Noise_IKpsk2`)対応を追加。`cargo test`で
  36テスト全通過。次は実ネットワークI/O統合・配布形態/鍵管理の検討。
- **2026-09-27 実装フェーズ3完了**: [`src/reality_auth.rs`](src/reality_auth.rs)
  にX25519 ECDH+HKDFによるREALITY本来の認証タグ検証(暗号プリミティブは
  x25519-dalek/hkdf crateに委ねる)、[`src/wireguard_handshake.rs`](src/wireguard_handshake.rs)
  にWireGuard相当のNoise_IKハンドシェイク(snow crateを土台)を実装。
  `cargo test`で26テスト全通過。TLS層(key_share拡張)への統合、
  AmneziaWGジャンクパケットとの組み合わせ、PSK追加は未着手。
- **2026-09-27 実装フェーズ2完了**: [`src/tls_clienthello.rs`](src/tls_clienthello.rs)
  にTLS ClientHelloの最小パーサー(SNI・session_id抽出)、
  [`src/amnezia.rs`](src/amnezia.rs)にAmneziaWGの核心機構(ジャンク
  パケット送信計画)を実装。`reality.rs`に`decide_from_client_hello_record`
  を追加しTLS層と統合。`cargo test`で19テスト全通過。X25519鍵共有への
  認証情報埋め込み・uTLS指紋偽装・WireGuard本体の暗号処理は未着手。
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
