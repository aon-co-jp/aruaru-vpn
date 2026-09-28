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

## 9. 実装フェーズ1(完了・2026-09-27): REALITY核心ロジック+連携インターフェース

`cargo init`でRustプロジェクトを作成。以下2モジュールを実装、`cargo test`
で8テスト全通過。

- [`src/reality.rs`](src/reality.rs): REALITYの核心である「認証成功/失敗
  判定→フォールバック転送」ロジックを最小実装。`RealityAuthChecker`が
  short_id(利用者ごとの短い識別子)を検証し、`decide_connection_action`が
  認証成功なら`ConnectionAction::Relay`(プロキシとして処理)、失敗なら
  `ConnectionAction::Fallback { camouflage_target }`(偽装先サイトへの
  そのままの転送)を返す。実際のTLS ClientHelloの偽装・uTLS指紋偽装は
  未実装(次フェーズ)。
- [`src/integration.rs`](src/integration.rs): `aruaru-llm`(通信パターン
  擬態)・`open-cuda`(GPU高速化)との連携を、**トレイト(契約)として先に
  定義**した。既定実装(`NoOpTrafficShaper`/`CpuOnlyCryptoAccelerator`)は
  何もしないフォールバックとして機能するため、`aruaru-llm`/`open-cuda`が
  未成熟な現時点でもビルド・テストが通る。両リポジトリ側の実装が育ったら、
  これらのトレイトを実装する型に差し替えるだけで実際の連携に移行できる
  設計。

## 10. 実装フェーズ2(完了・2026-09-27): TLS ClientHello解析+AmneziaWG核心機構

ユーザー指示「TLS層への統合(xray-lite参考)+WireGuard/AmneziaWG側の実装を
同時に進めて」を受け、以下2モジュールを実装。`cargo test`で19テスト全通過
(既存8+新規11)。

- [`src/tls_clienthello.rs`](src/tls_clienthello.rs): TLS `ClientHello`の
  ワイヤーフォーマットを手作業で最小限パースし、**SNI(接続先ホスト名)**と
  **session_id(REALITYが認証情報を埋め込む場所)**を抽出する。`rustls`等の
  完全なTLS実装には頼らない(認証前に通常のTLSサーバーとして応答しては
  ならないため、生バイトを覗き見る必要がある、というREALITYの本質的な
  要件による設計判断)。
- [`src/reality.rs`](src/reality.rs): `decide_from_client_hello_record`を
  追加し、生のTLSレコードから直接、認証判定→接続アクション決定まで一気通貫
  で行えるようにした(`tls_clienthello`との統合)。SNIが取れた場合は偽装先
  としてそのSNI自体を使う(利用者が実際にアクセスしようとしたサイトへ
  転送する方が検閲側から見て一貫性がある、という設計判断)。
- [`src/amnezia.rs`](src/amnezia.rs): AmneziaWGの核心機構である
  「ハンドシェイクパケットの前にランダムな個数・サイズのジャンクパケットを
  挟む」という送信計画(`Jc`/`Jmin`/`Jmax`相当)を、乱数は外部注入・
  決定的にテスト可能な形で実装(`open-LiveKit`の`NodePool::pick`と同じ
  設計パターン)。WireGuard本体の暗号処理(Noiseハンドシェイク)には
  まだ踏み込んでいない。

## 11. 実装フェーズ3(完了・2026-09-27): X25519認証+WireGuard Noiseハンドシェイク

ユーザー指示「未実装(X25519鍵共有・WireGuard暗号処理)を実装して」を受け、
以下2モジュールを実装。`cargo test`で26テスト全通過(既存19+新規7)。
**暗号プリミティブ(X25519・HKDF・Noiseハンドシェイク)は自作せず、
監査済みのRust crate([x25519-dalek](https://crates.io/crates/x25519-dalek)、
[hkdf](https://crates.io/crates/hkdf)、[snow](https://crates.io/crates/snow))
を使用する**(暗号アルゴリズムの独自実装は「他プロジェクトのコードを
流用しない」方針の対象外とする一般的ベストプラクティス、詳細は
[`CLAUDE.md`](CLAUDE.md)参照)。

- [`src/reality_auth.rs`](src/reality_auth.rs): REALITY本来の認証方式
  (X25519 ECDH → HKDFで認証タグ導出 → 定数時間比較で検証)を実装。
  `reality.rs`の簡略版(`session_id`を`short_id`としてそのまま比較)を
  置き換える本格実装。「正規クライアントの公開鍵は見えても対応する秘密鍵を
  持たない攻撃者は正しいタグを計算できない」ことをテストで確認。
  **未統合**: TLS ClientHelloの`key_share`拡張から実際にクライアントの
  エフェメラル公開鍵を抽出する処理(`tls_clienthello.rs`側の拡張が必要)は
  次フェーズ。
- [`src/wireguard_handshake.rs`](src/wireguard_handshake.rs): WireGuardが
  使う`Noise_IK`パターンによるハンドシェイクを、`snow`クレートを土台に
  実装。イニシエーター・レスポンダー間で実際にメッセージを往復させ、
  `TransportState`(暗号化データ通信状態)への遷移・実際の暗号化/復号まで
  確認。ただしNoise IK単体では「見知らぬイニシエーターの拒否」はできない
  (誰でもレスポンダーと鍵交換自体はできてしまう)ことをテストで明示し、
  上位層(REALITY相当の認証・許可リスト)との役割分担を設計として記録。
  **未統合**: `amnezia.rs`のジャンクパケット送信計画との組み合わせ、
  PSK(事前共有鍵、`Noise_IKpsk2`)の追加は次フェーズ。

## 12. 実装フェーズ4(完了・2026-09-27): 次フェーズ3項目を統合

ユーザー指示「未統合の3項目(key_share抽出、AmneziaWG+WireGuard統合、
PSK追加)を次フェーズとして統合して」を受け実装。`cargo test`で36テスト
全通過(既存26+新規10)。

1. **key_share拡張のパース+REALITY認証のTLS層統合**:
   [`src/tls_clienthello.rs`](src/tls_clienthello.rs)にTLS 1.3
   `key_share`拡張(extension type 0x0033)のパースを追加し、X25519
   (NamedGroup 0x001d)エントリの32バイト鍵交換値を抽出できるようにした。
   [`src/reality.rs`](src/reality.rs)に`decide_from_client_hello_record_x25519`
   を追加し、抽出した公開鍵+`session_id`(認証タグ)を
   `reality_auth::verify_auth_tag`で検証する本格版の判定フローを実装
   (`key_share`が無いクライアントは常にFallbackとする設計)。
2. **WireGuard+AmneziaWGの統合**: [`src/amnezia.rs`](src/amnezia.rs)に
   `build_obfuscated_send_sequence`(送信計画に沿ってジャンク+実メッセージの
   バイト列を組み立てる)と`extract_real_handshake_message`(送受信で
   事前共有した`junk_packet_count`を使い、パケット内容を解析せず単純に
   位置で本物を取り出す、実際のAmneziaWGと同じ設計)を追加。実際に
   `wireguard_handshake`が生成したハンドシェイクメッセージをジャンクに
   埋もれさせ、レスポンダー側で正しく取り出して処理できることをend-to-end
   テストで確認。
3. **PSK(`Noise_IKpsk2`)の追加**: [`src/wireguard_handshake.rs`](src/wireguard_handshake.rs)
   に`build_initiator_with_psk`/`build_responder_with_psk`を追加。両者が
   同じPSKを使えばハンドシェイク・データ通信とも成功し、PSKが食い違うと
   (ハンドシェイク自体は形の上で進んでも)実データの復号が必ず失敗する
   ことをテストで確認。

## 13. 実装フェーズ5(完了・2026-09-28): 実ネットワークI/O統合

ユーザー指示「進めて」を受け、これまでメモリ上のバイト列だけでテスト
していた各モジュールを、実際のTCP/UDPソケットに統合。`cargo test`で
39テスト全通過(既存36+新規3)。

- [`src/net.rs`](src/net.rs): `accept_and_route`がTCP接続を1本受け付け、
  最初のTLSレコードを読み取ってREALITY判定(`decide_from_client_hello_record_x25519`)
  を行い、認証成功なら`TcpStream`をそのまま呼び出し側に返し(以降のVLESS
  セッション処理は次フェーズ)、認証失敗なら実際に偽装先へTCP接続して
  `tokio::io::copy_bidirectional`で双方向中継する。`perform_handshake_over_udp`は
  WireGuard相当のNoiseハンドシェイクを実際のUDPソケット越しに行う。
- **見つけたバグとその修正**: フォールバック転送のテストで、モックの
  偽装先サーバーが応答後すぐに接続をドロップしたところ、Windows上で
  `ConnectionReset`(強制切断)が発生し中継がエラー終了する問題があった。
  クライアント側が明示的に`shutdown()`するまで待ってから接続を閉じる
  よう修正(TCP接続を片方が乱暴にドロップすると、まだやり取りが終わって
  いない相手側にRSTが飛ぶことがある、という実践的な教訓)。

## 次回再開ポイント(2026-09-28更新、実装フェーズ10完了時点)

**注意**: この節の内容は実装フェーズ6〜10の完了により大きく進捗している。
最新の到達点・詳細な引き継ぎは`CLAUDE.md`冒頭の「🛑 再開用メッセージ」、
本ファイル「20. 実装フェーズ10」末尾の「残る制約・将来のロードマップ」を
正本とする。以下は現時点で未着手の項目のみ列挙(優先順ではない):

- `secure_channel`経由の`Command::Udp`/`Command::Mux`対応
  (現状UDPは旧来の平文`handle_relay_session`側のみ対応、20.参照)。
- REALITY本来の証明書クローン(偽装先サイトの本物証明書の流用)。
  `session_id`埋め込み認証設計と根本的に相性が悪いことが判明済み
  (20.参照)、再検討には設計変更が必要。
- 将来の本物のTLS 1.3完全準拠・「TLS 1.4」的な将来動向への対応
  (アイデア・方向性の域を出ず、実装着手の判断は都度の技術動向・
  必要性を見て行う、20.参照)。
- 配布形態(上記3)の検討、鍵管理UI(ファイルピッカー等、下記14参照)の詳細。
- 透明性告知文の残り約100言語への翻訳拡張、ネイティブ検証の依頼。
- 実際のWebアプリ/クライアントUIへの「目立つ場所へのリンク設置」実装
  (クライアント実装と合わせて行う、いずれも未着手)。

次回セッション開始時は、上記のどれから着手するかをユーザーに確認してから
進めること(このセッション内でユーザーから明示的に指示された運用)。

## 14. 鍵管理方針(2026-09-27決定)

秘密鍵・PSK等の実際の値は、**ローカルドライブ上のディレクトリ・ファイル名を
明示したファイル**(例: `F:\aruaru-vpn\secrets\<peer名>.key`)として管理し、
**チャット上へのコピー&ペーストや値の直接表示は行わない**(ファイルパスの
みで参照する)。この方針・関連する注意書きは、日本語・英語に加えて利用者が
選択している表示言語があれば、その言語にも翻訳して表示する。詳細は
[`CLAUDE.md`](CLAUDE.md)「鍵管理方針」を参照。

## 15. 実装フェーズ6(完了・2026-09-28): 鍵の保存先ドライブ/ディレクトリを利用者が選択可能に

ユーザー指示「秘密鍵と公開鍵のドライブは選択可能として」を受け、保存先を
固定パスに決め打ちせず、**利用者が任意のドライブ/ディレクトリを指定
できる**形で実装。`cargo test`で45テスト全通過(既存39+新規6)。

- [`src/key_storage.rs`](src/key_storage.rs): `KeyStorageConfig { directory:
  PathBuf }`が保存先を表す(例: `D:\my-keys`のような別ドライブでも、
  `F:\aruaru-vpn\secrets`のような既定候補でも、利用者が選んだ任意のパスを
  設定できる)。`save_keypair`/`load_private_key`/`load_public_key`は
  鍵の値そのものをログ・戻り値に含めず、ファイルパスのみを扱う。
  既存鍵の誤上書き防止(`overwrite: bool`)、保存先ディレクトリの書き込み
  可否を事前確認する`verify_directory_is_usable`(実際の鍵は書き込まない
  プローブ)も実装。異なるディレクトリ(=異なるドライブを模擬)を指定
  すれば、それぞれ独立して鍵を保存・読み込みできることをテストで確認。

**未実施(次フェーズ)**: 実際にクライアントUIで「保存先ドライブ/
ディレクトリを選ぶ」操作(ファイル選択ダイアログ等)、`reality_auth`/
`wireguard_handshake`が生成した鍵をこの`key_storage`経由で実際に保存/
読み込みする配線、パーミッション(ファイルの読み取り権限を所有者のみに
絞る等、OS別の実装)。

## 16. 鍵の保存先一覧メモ機能: 提案→実装→撤回(2026-09-28)

ユーザーから「後で、どこのドライブの何処のディレクトリに保存したかを
一番上のディレクトリに分かりやすいタイトルのテキストメモか何かで自動で
保存して」との指示を受け、`save_keypair_with_location_memo`(保存先の
ドライブ・ディレクトリ・鍵の名前だけを記録し、鍵の値自体は書かない
テキストメモをプロジェクト直下に自動作成する機能)を一度実装したが、
**ユーザーから直後に「セキュリティ上あまり良くないので辞めます」との
指摘があり撤回した**。

**撤回の理由**: 鍵の値自体は書かなくても、「鍵ファイルがどこに保存されて
いるか」を分かりやすい固定ファイル名でプロジェクト直下に平文記録すると、
攻撃者が鍵ファイルを探す際の手がかりを与えてしまう(値と場所を分離しても、
場所の一覧化自体がリスクになりうる)。この判断は`CLAUDE.md`「鍵管理方針」
の「値も場所も安易に残さない」という考え方に沿ったものとして記録する。

実装は完全に削除済み(`save_keypair_with_location_memo`・関連テストは
`src/key_storage.rs`に存在しない)。`cargo test`は45テスト(実装フェーズ6
時点と同数)で全通過を維持。

## 17. 実装フェーズ7(完了・2026-09-28): VLESSプロトコル本体(リクエストヘッダ解析)

ユーザー指示「続けて」を受け、次回再開ポイントに残っていた「VLESSプロトコル
本体(認証成功後のセッション処理)の実装」に着手。`cargo test`で53テスト
全通過(既存45+新規8)。

- [`src/vless.rs`](src/vless.rs): VLESSリクエストヘッダ
  (`[version][UUID 16B][addons][command][port][address_type][address]`、
  Xray-coreが定義する公開プロトコル仕様のみ参考、コードは流用せず一から
  実装)のパーサーを実装。IPv4/ドメイン名/IPv6の3種類のアドレス指定、
  TCP/UDP/MUXの3種類のコマンドに対応。サーバー応答ヘッダの組み立ても実装。
- [`src/net.rs`](src/net.rs): `handle_relay_session`を追加し、
  `accept_and_route`が`Relay`と判定した接続から実際にVLESSリクエストを
  読み取り、指定された宛先へ実際にTCP接続して双方向中継する
  end-to-endテストを追加(モックの宛先echoサーバーへ実際にペイロードが
  届き、折り返されてくることを確認)。
- **重要な簡略化(引き続き未解決)**: 本来のREALITYはTLSハンドシェイク
  完了後の暗号化通信路の中をVLESSリクエストが流れるが、このプロトタイプは
  まだTLS終端(実際の暗号化/復号)を実装していないため、平文のバイト列を
  そのままVLESSリクエストとして扱っている。実TLS終端の統合は次フェーズ。

**未実施(次フェーズ)**: UUID(クライアント識別子)の検証(現状はパースする
だけで値のチェックをしていない)、UDPコマンド・MUXコマンドの実際の処理
(現状はTCP相当の中継のみ実装)、実TLS終端との統合。

## 18. 実装フェーズ8(完了・2026-09-28): UUID検証+UDPコマンドの実処理

ユーザー指示「UUID検証・UDP/MUX処理を進めて」を受け実装。`cargo test`で
58テスト全通過(既存53+新規5)。

- [`src/vless.rs`](src/vless.rs): `AllowedUuids`(許可されたクライアント
  UUIDの集合)と`validate_uuid`を追加。REALITY/TLSの認証(輸送路レベル)
  とは別に、VLESS自身が持つUUIDで利用者を識別・検証する二段構えの認証を
  実装(実際のXray-coreと同じ設計)。
- [`src/net.rs`](src/net.rs): `handle_relay_session`にUUID検証を組み込み、
  未登録UUIDのリクエストは**宛先への接続を試みる前に**拒否するように
  した。あわせて`Command::Udp`の実処理(`relay_udp`)を追加し、実際の
  UDPソケットで宛先(モックのUDP echoサーバー)まで往復できることを
  end-to-endテストで確認。`Command::Mux`は引き続き未対応
  (`Unsupported`エラーを返す)。
- **UDP実装の簡略化**: 本来のVLESS UDPは1本のTCP接続の中に、2バイト長
  プレフィックス付きで複数のUDPデータグラムを表現するフレーミング方式を
  使うが、今回は「最初のペイロードを1個のデータグラムとして送り、応答を
  1回受け取って返す」という往復1回分の最小疎通確認に留めた。複数
  データグラムのフレーミングは次フェーズ。

**未実施(次フェーズ)**: MUXコマンドの実処理、UDP複数データグラムの
フレーミング、実TLS終端。

## 19. 実装フェーズ9(試作品完成・2026-09-28): 実TLS終端(自己署名証明書)

ユーザーとの合意通り、「証明書のクローン(偽装先サイトの証明書をそのまま
流用)」という本格実装はいったん置き、**自己署名証明書での実TLS終端**の
試作品からスタートした。`cargo test`で59テスト全通過(既存58+新規1)。

- [`src/tls_terminate.rs`](src/tls_terminate.rs): [rustls](https://crates.io/crates/rustls)/
  [tokio-rustls](https://crates.io/crates/tokio-rustls)(監査済み)を使い、
  実際にTLSハンドシェイクを完了させる仕組みを実装。
  - `generate_self_signed_cert`: [rcgen](https://crates.io/crates/rcgen)で
    その場で自己署名証明書+秘密鍵を生成(開発・テスト用、実運用では固定
    ファイルを読み込む形に置き換える)。
  - `PrefixedStream<S>`: `accept_and_route`が最初の読み取りで既に消費して
    しまったClientHelloの先頭バイト列を「巻き戻す」ためのAsyncRead/
    AsyncWriteラッパー。まず`prefix`の残りを返し、使い切ったら実ソケット
    からの読み取りに切り替える。
  - `terminate_tls_with_prefix`: 上記`PrefixedStream`を使い、実際に
    `TlsAcceptor`でTLSサーバーハンドシェイクを完了させる。
  - end-to-endテストで、サーバー側が数バイトを先読みして消費した後でも
    TLSハンドシェイクが最後まで完了し、暗号化されたアプリケーション
    データ(実際のTLSレコードとして暗号化・復号)を送受信できることを確認。

**残る制約(次フェーズ)**: 証明書は自己署名であり、REALITY本来の
「偽装先サイトの本物の証明書をそのまま使う」偽装(証明書クローン)は
未実装。`accept_and_route`/`handle_relay_session`との実際の配線(今は
独立したモジュールとして動作確認しただけ)も未着手。

## 20. 実装フェーズ10(完了・2026-09-28): 独自セキュアトランスポート+実配線、致命的バグ2件を発見・修正

**技術的な行き詰まりと方針転換**: `rustls`ベースのTLS終端を
`accept_and_route`/`handle_relay_session`に実配線しようとしたところ、
根本的な壁に突き当たった。私たちのREALITY認証はTLSの`ClientHello`
`session_id`欄に独自の認証タグを埋め込む設計だが、`rustls`(標準準拠の
TLS実装)はこの非標準な構造を受け付けない。本物のREALITY(Xray-core)は
TLS実装自体を改造(uTLS等)することでこれを解決しているが、それは
非常に大規模な作業になる。

ユーザーと相談の上、2つの選択肢(A: 認証とTLSを分離する2段階方式、
B: 自前のTLS 1.3相当レコード層を書く)を比較し、**ユーザーの意向により
案B**を採用。ただし完全なTLS 1.3仕様準拠(既存TLSライブラリとの相互
接続性)は目指さず、**REALITY認証(X25519 ECDH)で既に確立済みの共有鍵を
そのまま使い、そこから独自にAEAD暗号化レコード層を導出する「自前の
最小限のセキュアトランスポート」**として実装した。`cargo test`で
65テスト全通過(既存59+新規6)。

- [`src/reality_auth.rs`](src/reality_auth.rs): `derive_channel_keys`を
  追加。認証タグの導出と**同じX25519 ECDH共有シークレット**から、HKDFで
  「別の`info`文字列」を使って独立した`ChannelKeys`(送信方向ごとに2本の
  鍵)を導出する(暗号学的な用途分離)。
- [`src/secure_channel.rs`](src/secure_channel.rs): `ChannelKeys`を使い、
  [ChaCha20-Poly1305](https://crates.io/crates/chacha20poly1305)
  (監査済み、暗号プリミティブ自体は自作しない)による独自のAEAD
  フレーミング(`[4バイト長][暗号文+認証タグ]`)を実装。`SecureWriter`/
  `SecureReader`が送受信を担い、ノンスは接続ごとに0から単調増加させる
  カウンタで管理(同じ鍵・同じノンスの再利用を防ぐ)。
- [`src/net.rs`](src/net.rs): `accept_and_route`が認証成功時に
  `ChannelKeys`も導出して返すように変更(`AuthenticatedConnection`型を
  新設)。`handle_relay_session_secure`を追加し、`secure_channel`経由で
  実際に暗号化されたVLESSセッションを処理できるようにした
  (`Command::Tcp`のみ対応)。

**開発中に見つけた致命的なバグ2件(ユーザー指示どおりTEST→DEBUGを反復して発見)**:

1. **`tokio::io::split`の片方向クローズの誤解によるデッドロック**:
   テストで`drop(writer)`により送信終了を伝えようとしたが、`split()`は
   下層ストリームをArcで共有しているだけなので、`reader`側がまだ生きて
   いる限り実際のソケットはクローズされず、相手はEOFを検知できずに
   永久に待機し続けた。`SecureWriter::shutdown()`を追加し、明示的に
   書き込み方向をシャットダウンすることで解決。
2. **TLSレコード境界を超えた「まとめ読み」によるバイト列の消失**:
   `accept_and_route`が「最大4096バイトを1回読み取る」実装のままだった
   ため、クライアントがClientHelloの直後に続けてsecure_channelの
   フレームを送ると、TCPがそれらを1回の読み取りにまとめてしまい、
   ClientHelloを超えた分(VLESSリクエストの先頭)を読み捨ててしまう
   欠陥があった。これが1と組み合わさり、`secure_channel`側が「新しい
   バイトが来るのを待ち続ける」デッドロックとして顕在化していた。
   TLSレコードヘッダの5バイトから実際の長さを読み取り、**ちょうど1
   レコード分だけ**読む`read_exactly_one_tls_record`に置き換えて解決。

**この2件のバグは、フルパイプラインのend-to-endテスト
(`full_pipeline_reality_auth_to_encrypted_vless_relay`: 実TCP接続で
REALITY認証→`secure_channel`確立→VLESS解析→実宛先への中継、を一気通貫で
検証)を書いて初めて発覚した**。個々のモジュール単体のテストだけでは
見つからない類のバグであり、「実配線してテストする」ことの重要性を
実地で確認した。

**残る制約・将来のロードマップ**: 現在の`secure_channel`は独自プロトコル
であり、既存のTLSライブラリ・ブラウザ等とは相互接続できない。将来的な
発展の方向性としては、(a) 短期: `Command::Udp`/`Mux`のsecure_channel対応、
証明書クローンの検討再開、(b) 中期: 本物のTLS 1.3への準拠(uTLS相当の
ClientHello偽装をゼロから実装するか、`key_share`に頼らない別の認証埋め込み
方式を検討)、(c) 長期: 将来のTLSプロトコルの仕様改定(仮に「TLS 1.4」的な
ものが登場した場合)への追従、を見据える。ただし(b)(c)は現時点では
「アイデア・方向性」の域を出ず、実装着手の判断は都度の技術動向・
必要性を見て行う。

## 21. 実装フェーズ11(完了・2026-09-28): secure_channel経由のCommand::Udp対応

[`src/net.rs`](src/net.rs)の`handle_relay_session_secure`に`Command::Udp`の
処理(`relay_udp_secure`)を追加。`secure_channel`のメッセージ単位フレーミング
がそのままUDPデータグラム境界に対応するため、平文版(TCP埋め込み)のVLESS UDPが
本来必要とする2バイト長プレフィックスは不要。平文版`relay_udp`は往復1回のみで
打ち切る最小疎通確認だったが、暗号化版は`tokio::select!`でクライアント→宛先/
宛先→クライアントの両方向を継続的にポンピングし、複数データグラムに対応する
よう拡張した。`cargo test`で66テスト全通過(既存65+新規1:
`relay_session_secure_forwards_udp_command_to_real_destination`、2個の
データグラムを同一セッションで往復させて複数回対応を確認)。

`Command::Mux`は引き続き未対応。VLESS本来のMux(V2Ray Mux.Coolプロトコル
相当、1本のセッションの中に複数の独立したサブストリームをID+ステータス
〈New/Keep/End/KeepAlive〉付きフレームで多重化する仕組み)は、`Command::Tcp`/
`Udp`とは別次元の独立したサブプロトコル設計が必要で、今回のUDP対応とは
スコープが異なるため見送った。着手する場合は改めてユーザーに相談する。

## 22. 実装フェーズ12(分析完了・2026-09-28): REALITY本来の証明書クローンの再検討

**結論: 現在のアーキテクチャでは証明書クローンは不要であり、実装しない
という判断に至った。** 理由を以下に記録する(次回「なぜやらなかったか」を
再調査せずに済むように)。

本物のXray-core REALITYにおける「証明書クローン」とは、認証成功時に
サーバーが自ら生成するTLS ServerHello/証明書を、偽装先サイト本来の証明書と
統計的に見分けがつかない形に似せる技術を指す(秘密鍵は持たないので、
署名自体はサーバー自身の鍵で行う)。これが必要になるのは、**クライアント側が
uTLS等でパッチされた「本物のTLSクライアント」として振る舞い、通常のTLS
証明書チェーン検証をパスさせる必要がある**という前提があるからである
(検証をスキップすると、パケット解析されたときに「証明書チェーンを検証して
いない怪しいTLSクライアント」だと外部の観測者に気づかれてしまう)。

しかし、このリポジトリの設計は実装フェーズ10の時点で**既に標準TLSへの
準拠を放棄し、`secure_channel`という独自の(TLSではない)AEAD暗号化
レコード層に置き換えている**(`session_id`欄への認証タグ埋め込みが標準TLS
ライブラリと根本的に非互換だったため)。つまり:

- **認証成功パス**: クライアントは最初から`secure_channel`の専用クライアント
  実装であり、標準TLSの証明書チェーン検証という概念自体が存在しない
  (信頼はX25519 ECDHの共有シークレットで確立され、PKI証明書には一切
  依存しない)。したがって「本物らしく見せかける証明書」を用意する動機が
  そもそも無い。
- **認証失敗(フォールバック)パス**: [`src/net.rs`](src/net.rs)の
  `accept_and_route`は、`dial_camouflage`で偽装先サイトへ実際にTCP接続し、
  クライアントの最初のバイト列(ClientHelloそのもの)をそのまま転送した
  上で`tokio::io::copy_bidirectional`により生バイトを双方向中継している。
  これは「本物の証明書を**クローンする**」以上に確実な擬態であり
  (クローンではなく本物のTLSハンドシェイクそのものが素通りする)、
  この経路については実装フェーズ5時点で既に対応済みである。

したがって証明書クローンが解決すべき問題(「外部の観測者から見て偽装先
サイトへの普通のTLS接続に見えること」)は、(a)フォールバックパスの完全な
生バイト転送、(b)認証成功パスでのTLS自体の非使用、という2つの既存の設計
判断によって、証明書クローンという追加実装なしに既に満たされている。

**再検討が必要になる条件**(将来この判断を覆す可能性がある場合、以下を
確認すること): 将来、認証成功パスを本物のTLS 1.3準拠(uTLS相当の
ClientHello偽装)へ作り直す方針に転換した場合(「20.」の中期ロードマップ
(b))には、その時点で初めて証明書クローンが必要になる。現時点ではその
転換の予定は無い。

## 23. 実装フェーズ13(完了・2026-09-28): 鍵管理GUI([`src/bin/keys_gui.rs`](src/bin/keys_gui.rs))

これまで`aruaru-vpn`はバイナリクレート単独(`src/main.rs`直下にモジュール)
だったが、GUIバイナリからも`key_storage`/`reality_auth`を再利用できるよう
[`src/lib.rs`](src/lib.rs)を新設してライブラリターゲットへ切り出し、
`main.rs`は`aruaru_vpn::`経由で参照するよう変更(振る舞いは無変更)。

ユーザーの選択(ネイティブGUI採用)に基づき、[egui](https://github.com/emilk/egui)/
`eframe`(Rust純正、依存追加は最小限)+[rfd](https://github.com/PolyMeilex/rfd)
(ネイティブのフォルダ選択ダイアログ)で`aruaru-vpn-keys`バイナリを新設:

- フォルダ選択ダイアログで保存先ディレクトリを選び、
  `key_storage::verify_directory_is_usable`で書き込み可能かをその場で確認
- REALITYサーバーの長期鍵ペアを`rand::random::<[u8; 32]>()`(OS乱数)で
  生成し、`key_storage::save_keypair`でファイルへ保存
- **秘密鍵の値は画面に一切表示しない**([`feedback_keys_via_files_never_echo`]
  方針どおり)。表示するのは保存先パスと公開鍵(16進数、コピー用ボタン付き)
  のみ
- 上書き保護(`SaveError::AlreadyExists`)はチェックボックスで明示的に
  同意した場合のみ解除

実際に`cargo build --bin aruaru-vpn-keys`でビルドし、`target\debug\
aruaru-vpn-keys.exe`を実際に起動してクラッシュせず待機し続けることを確認
(GUI操作の自動テストまでは行っていない、次回セッションでフォルダ選択→
生成→保存の実際の手動操作確認を推奨)。`cargo test`は変わらず66テスト
全通過(ライブラリ切り出しによる既存モジュールの挙動変更は無し)。

## 24. 実装フェーズ14(完了・2026-09-29): 透明性告知文のAI自己レビュー(ネイティブ検証の代替ではない)

**前提の確認**: ネイティブ話者による検証は、本質的に人間が行う必要がある
作業であり、AIが代行して「検証済み」と主張することはできない。ユーザーに
方針を確認したところ、**「ネイティブ検証の代替にはならない」と明記した
上でのAI自己レビューのみ実施**することで合意した。

**実施内容**: [`TRANSPARENCY_NOTICE.md`](TRANSPARENCY_NOTICE.md)の正本
(日本語・英語)が主張する4つの核心的要素——(1)aon-co-jp運営の中継/VPN
サービスではない、(2)VPS上に利用者自身の責任で構築する専用プライバシー
中継、(3)暗号鍵は利用者自身が管理、(4)自国法令への適合確認は利用者
自身の責任——が、各言語版の段落から欠落・逆転(誤って「aon-co-jpが運営
している」と読めてしまう等)していないかを、AIが1言語ずつ逆翻訳して確認した。

**発見事項**: 意味の欠落・逆転は30言語すべてで見つからなかった。文法上の
軽微な不自然さを2件発見し修正:
- ペルシア語: 否定辞「نیست」の位置が関係節の後ろに来ており不自然だった
  (`نیست`を関係節の前に移動、動詞法も直説法へ整合)。
- アラビア語: 「暗号鍵(複数・非人称)」に対する動詞の性・数一致が誤って
  いた(`يديرها`→`تديرها`)。

**既知の限界**: ミャンマー語・クメール語・モンゴル語・ネパール語・
シンハラ語は、AI自身の習熟度が他言語より低く、このレビューの信頼度は
相対的に低い。これらの言語を含め、**全言語について正式なネイティブ検証は
未実施のまま**であることに変わりはなく、`TRANSPARENCY_NOTICE.md`冒頭の
注意書きは変更していない(AI自己レビュー実施の旨のみ追記)。

## 25. 実装フェーズ15(完了・2026-09-29): 証明書クローン、訂正と本実装

「22.」で「現在のアーキテクチャでは証明書クローンは不要」と結論づけたが、
ユーザーからの指示を受けて世界中の技術文書([XTLS/REALITY](https://github.com/XTLS/REALITY)、
[Xray-core](https://github.com/XTLS/Xray-core)のソース・Issue・中国語/英語の
技術解説記事)を多数調査した結果、**その結論は誤りだった**と判明したため
訂正する。

**訂正内容**: 本物のREALITYが証明書クローンをする理由は「クライアント
自身がTLS証明書検証をするかどうか」ではなく、**「第三者の検閲装置(DPI)が
ワイヤー上のバイト列を観測したときに、本物のサイトへの普通のTLS接続と
区別がつくかどうか」**である。実装フェーズ10で導入した`secure_channel`
(独自の`[4バイト長][暗号文]`フレーミング)は、ClientHelloの直後から
明らかに非TLS構造のバイト列に切り替わるため、この脅威モデルに対して
脆弱だった。

**本物のREALITYの仕組み(調査結果)**:
1. サーバーは偽装先サイトへ実際にライブ接続し(または過去のハンドシェイク
   結果をキャッシュし)、本物のServerHello/証明書チェーンを取得する
   (「盗む」対象は秘密鍵ではなく、公開情報である証明書バイト列)。
2. その証明書の**署名フィールドだけ**を、X25519 ECDH由来の`AuthKey`による
   HMAC-SHA512値に差し替える(「一時証明書」、Ed25519署名〈64バイト〉と
   同じ長さになるようスキームを偽装)。
3. 正規クライアント(uTLS改造TLSクライアント)は通常の証明書チェーン検証を
   行わず、このHMAC値を自分で再計算して照合する。
4. 鍵交換・レコード層の暗号化・ハンドシェイクの全体構造は標準のTLS 1.3の
   まま変更しないため、ワイヤー上のバイト列が本物のTLS 1.3と区別できない。

**実装方針**: 本物のXray-core REALITYはGoの`crypto/tls`標準ライブラリ自体を
フォークする大規模な実装になっている(Go標準ライブラリが十分な拡張点を
公開していないため)。調査の結果、Rustには同等のREALITY実装は存在しない
ことを確認したが、[rustls](https://crates.io/crates/rustls)はこの目的に
必要な拡張点(`SigningKey`/`Signer`/`ResolvesServerCert`/`ServerCertVerifier`)
を標準APIとして公開しているため、**rustls自体をフォークせずに実装できる**
ことが分かった。新設した[`src/cert_clone.rs`](src/cert_clone.rs)で:

- `fetch_real_certificate_chain`: 偽装先サイトへ実際にTLS接続し、本物の
  公開証明書チェーンを取得する。
- `AuthKeySigner`/`AuthKeySigningKey`(`SigningKey`/`Signer`実装): 本物の
  秘密鍵の代わりにHMAC-SHA512値を「署名」として返す。
- `ClonedCertResolver`(`ResolvesServerCert`実装): 借用した本物の証明書
  チェーン+上記の署名鍵を常に返す。
- `AuthKeyVerifier`(クライアント側`ServerCertVerifier`実装): 通常の
  チェーン検証をせず、同じHMAC-SHA512値を再計算して照合する。

`reality_auth.rs`に`derive_cert_clone_auth_key`(64バイトのHMAC鍵をHKDFで
導出、認証タグ・`ChannelKeys`とは別の`info`文字列で暗号学的に分離)を追加。

`cargo test`で、実際に自己署名証明書のモックTLSサーバーから本物の証明書
チェーンを取得し、それを借用してTLS 1.3ハンドシェイクが実際に成立し、
暗号化されたアプリケーションデータの往復ができることを確認(4テスト:
証明書取得・フルハンドシェイク成立・誤ったAuthKeyでの失敗確認・AuthKey
導出の対称性)。

## 26. 実装フェーズ16(完了・2026-09-29): rustls標準クライアントとの統合、認証方式の設計変更

「25.」の`cert_clone`を`net.rs`(`accept_and_route`/`handle_relay_session`)へ
実配線し、本物の`rustls`クライアントを使ったフルパイプラインend-to-end
テストを書く過程で、**もう1つの根本的な非互換性**を発見した。

**発見した問題**: `accept_and_route`(`secure_channel`版)と同じ「ClientHello
の`session_id`にECDH認証タグを埋め込み、送信後に後から書き換える」方式
(`SessionIdPatchingStream`として実装、`patch_session_id_prefix`)を試した
ところ、TLSハンドシェイクが`DecryptError`で失敗した。原因: **TLS 1.3の
ハンドシェイク鍵は、ClientHelloの生バイト列全体(`legacy_session_id`
フィールドを含む)のトランスクリプトハッシュから導出される**。`rustls`が
内部で構築したClientHelloの`session_id`を送信後に書き換えると、クライアント
側が内部的に計算したトランスクリプトハッシュ(未パッチのバイト列で計算済み)
と、サーバーが実際に受信したバイト列のハッシュ(パッチ済み)が食い違い、
`Finished`メッセージの検証が失敗する。本物のREALITY(Xray-core)がGoの
`crypto/tls`を丸ごとフォークしている理由はまさにこれで、uTLSは「トランス
クリプトハッシュが計算される**前**に」ClientHelloへ認証情報を埋め込める。
`rustls`の公開APIには同等のフック(ハッシュ計算前に生バイト列を差し替える
手段)が無い。

**解決策**: `session_id`への埋め込みをやめ、**`key_share`拡張のX25519公開鍵
そのものをクライアントの固定識別子として使う**方式に設計変更した。
`key_share`はClientHello構築時から一貫して使われる値であり、後から書き
換える必要が無いため、トランスクリプトハッシュの問題を回避できる。

- [`rustls::crypto::SupportedKxGroup`]/`ActiveKeyExchange`を自前実装
  (`FixedX25519ActiveKeyExchange`/`FixedX25519KxGroup`、`cert_clone.rs`):
  rustlsが本来ランダムに生成するエフェメラル鍵の代わりに、呼び出し側が
  指定したX25519秘密鍵を使わせる。TLS1.3セッション自体の前方秘匿性は
  損なわれない(サーバー側エフェメラル鍵は`rustls`が生成する通常の
  ランダム値のまま)。
- `reality_auth::AllowedClientKeys`(新設): 事前登録済みクライアント公開鍵
  の許可リスト(`vless::AllowedUuids`と同じ設計)。`accept_and_route_cert_cloned`
  は、`key_share`から読み取った公開鍵がこのリストに含まれるかどうかで
  認証を判定する。
- **既知のトレードオフ**: TLS1.3の`key_share`は本来エフェメラル(接続毎に
  使い捨て)であるべきだが、この設計ではクライアントが固定の識別鍵を
  繰り返し使うため、観測者が複数接続にわたってクライアントを追跡できて
  しまう(プライバシー上の弱化)。`wireguard_handshake.rs`の`Peer`が既に
  同種の固定長期鍵を使っているのと同じ設計判断であり、TLS1.3セッション
  自体の前方秘匿性(サーバー側は毎回新規のエフェメラル鍵)は失われない。

[`src/net.rs`](src/net.rs)に`accept_and_route_cert_cloned`/
`handle_relay_session_cert_cloned`を追加(`handle_relay_session`を
`TcpStream`固定から`AsyncRead + AsyncWrite`ジェネリックへ一般化し、
`secure_channel`版と`cert_clone`版の両方で共通のVLESS中継ロジックを
再利用)。

`cargo test`で74テスト全通過。新規の
`full_pipeline_cert_cloned_reality_auth_to_real_tls13_vless_relay`
(本物の`rustls`クライアント+`FixedX25519`で固定したエフェメラル鍵→
`accept_and_route_cert_cloned`の認証判定→本物の証明書チェーンを偽装先
から借用したTLS 1.3ハンドシェイクの実際の完了→VLESSリクエストの解析→
実際の宛先への中継、を一気通貫で確認)が正しく成功することを確認済み。

**残る簡略化**: (1) 証明書チェーンの取得は接続毎にライブ接続(本物の
Xray-coreのような`CacheManager`によるキャッシュは未実装、次フェーズ
候補)、(2) `key_share`固定によるプライバシートレードオフ(上記)、
(3) `Command::Udp`/`Mux`の`cert_clone`経由対応は未着手(`Command::Tcp`のみ)。
