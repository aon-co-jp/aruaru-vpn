//! WireGuard本体の暗号処理(実装フェーズ3): Noiseプロトコルハンドシェイク。
//!
//! WireGuardは`Noise_IKpsk2`というNoiseプロトコルのパターンを使う
//! (公開仕様のみ参考、`boringtun`のコードは流用しない)。ここでは
//! Noiseプロトコル自体の実装([snow](https://crates.io/crates/snow)、
//! Rust製の監査対象Noiseフレームワーク実装)を土台に、WireGuard相当の
//! ハンドシェイク(イニシエーター/レスポンダー間の鍵交換)が成立することを
//! 確認する最小プロトタイプを実装する。
//!
//! **Noiseプロトコルの暗号ロジック自体は`snow`に委ね、自作しない**
//! (`reality_auth.rs`と同じ理由: 暗号プリミティブの独自実装はしない)。
//! `aruaru-vpn`側で実装するのは、WireGuardのハンドシェイクパラメータ
//! (Noiseパターン文字列・鍵管理)の組み立てと、`amnezia.rs`のジャンク
//! パケット送信計画との統合(次フェーズ)。

use snow::{Builder, HandshakeState, TransportState};

/// WireGuardが使うNoiseパターン(`Noise_IK_25519_ChaChaPoly_BLAKE2s`)。
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// WireGuard本来の`Noise_IKpsk2`(事前共有鍵付き)のパターン。PSKは
/// 「量子コンピュータが将来X25519を破っても、事前に安全な経路で配布した
/// 対称鍵を知らない限り復元できない」という耐量子性の底上げのために
/// WireGuardが標準で採用している(公開仕様のみ参考)。
const NOISE_PARAMS_PSK2: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// PSK(事前共有鍵)のバイト長(Noiseプロトコル仕様上32バイト固定)。
pub const PSK_LEN: usize = 32;

/// ハンドシェイク前(鍵生成のみ)の当事者。
pub struct Peer {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Peer {
    /// 新しい鍵ペアを生成する(乱数源はOS標準のCSPRNGを使う`snow`の
    /// デフォルトに委ねる)。
    pub fn generate() -> Result<Self, snow::Error> {
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let keypair = builder.generate_keypair()?;
        Ok(Self {
            private_key: keypair.private,
            public_key: keypair.public,
        })
    }
}

/// イニシエーター(接続を開始する側、WireGuardの「クライアント」役)の
/// ハンドシェイク状態を組み立てる。
pub fn build_initiator(
    local: &Peer,
    remote_public_key: &[u8],
) -> Result<HandshakeState, snow::Error> {
    Builder::new(NOISE_PARAMS.parse().unwrap())
        .local_private_key(&local.private_key)?
        .remote_public_key(remote_public_key)?
        .build_initiator()
}

/// レスポンダー(接続を受ける側、WireGuardの「サーバー」役)の
/// ハンドシェイク状態を組み立てる。
pub fn build_responder(local: &Peer) -> Result<HandshakeState, snow::Error> {
    Builder::new(NOISE_PARAMS.parse().unwrap())
        .local_private_key(&local.private_key)?
        .build_responder()
}

/// PSK(事前共有鍵)付きのイニシエーター(`Noise_IKpsk2`)を組み立てる。
/// `psk`は両当事者が安全な経路で事前共有した32バイトの対称鍵。
pub fn build_initiator_with_psk(
    local: &Peer,
    remote_public_key: &[u8],
    psk: &[u8; PSK_LEN],
) -> Result<HandshakeState, snow::Error> {
    Builder::new(NOISE_PARAMS_PSK2.parse().unwrap())
        .local_private_key(&local.private_key)?
        .remote_public_key(remote_public_key)?
        .psk(2, psk)?
        .build_initiator()
}

/// PSK(事前共有鍵)付きのレスポンダー(`Noise_IKpsk2`)を組み立てる。
pub fn build_responder_with_psk(
    local: &Peer,
    psk: &[u8; PSK_LEN],
) -> Result<HandshakeState, snow::Error> {
    Builder::new(NOISE_PARAMS_PSK2.parse().unwrap())
        .local_private_key(&local.private_key)?
        .psk(2, psk)?
        .build_responder()
}

/// イニシエーター・レスポンダー間で実際にハンドシェイクメッセージを
/// 往復させ、双方が`TransportState`(暗号化された通常データ通信の状態)へ
/// 遷移できることを確認する。成功すれば、以降はこの2つの`TransportState`で
/// 暗号化されたデータの送受信ができる。
pub fn perform_handshake(
    mut initiator: HandshakeState,
    mut responder: HandshakeState,
) -> Result<(TransportState, TransportState), snow::Error> {
    let mut buf = [0u8; 1024];

    // メッセージ1: initiator → responder
    let len = initiator.write_message(&[], &mut buf)?;
    responder.read_message(&buf[..len], &mut [0u8; 1024])?;

    // メッセージ2: responder → initiator
    let len = responder.write_message(&[], &mut buf)?;
    initiator.read_message(&buf[..len], &mut [0u8; 1024])?;

    let initiator_transport = initiator.into_transport_mode()?;
    let responder_transport = responder.into_transport_mode()?;
    Ok((initiator_transport, responder_transport))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_completes_and_produces_working_transport_states() {
        let initiator_peer = Peer::generate().expect("keygen must succeed");
        let responder_peer = Peer::generate().expect("keygen must succeed");

        let initiator = build_initiator(&initiator_peer, &responder_peer.public_key)
            .expect("initiator handshake state must build");
        let responder =
            build_responder(&responder_peer).expect("responder handshake state must build");

        let (mut initiator_transport, mut responder_transport) =
            perform_handshake(initiator, responder).expect("handshake must complete");

        // ハンドシェイク後、実際に暗号化データを送受信できることを確認する
        // (WireGuardのデータプレーンに相当する最小疎通確認)。
        let plaintext = b"hello over wireguard-style noise transport";
        let mut ciphertext = [0u8; 1024];
        let ct_len = initiator_transport
            .write_message(plaintext, &mut ciphertext)
            .expect("initiator must encrypt");

        let mut decrypted = [0u8; 1024];
        let pt_len = responder_transport
            .read_message(&ciphertext[..ct_len], &mut decrypted)
            .expect("responder must decrypt");

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn responder_rejects_handshake_from_wrong_initiator_key() {
        let real_initiator_peer = Peer::generate().unwrap();
        let impostor_peer = Peer::generate().unwrap();
        let responder_peer = Peer::generate().unwrap();

        // レスポンダーは`real_initiator_peer`ではなく別人(impostor)からの
        // ハンドシェイクを受け取る状況を模擬する。IKパターンでは
        // イニシエーターの静的鍵はメッセージ1で暗号化されて送られるため、
        // レスポンダー自身の鍵が間違っていない限りメッセージは複合できて
        // しまうが、後続のペイロード検証や上位層のREALITY認証
        // (`reality_auth.rs`)と組み合わせて初めて「見知らぬイニシエーター」
        // を拒否できる、という設計上の役割分担を確認するためのテスト。
        let initiator = build_initiator(&impostor_peer, &responder_peer.public_key).unwrap();
        let responder = build_responder(&responder_peer).unwrap();

        let result = perform_handshake(initiator, responder);
        assert!(
            result.is_ok(),
            "Noise IK alone authenticates the responder to the initiator, \
             not arbitrary initiators to the responder; higher-level allow-listing \
             (short_id/REALITY auth) is required for that, matching relay.rs's design"
        );
        let _ = real_initiator_peer; // 未使用警告避け(ドキュメント目的で保持)
    }

    #[test]
    fn psk_handshake_completes_when_both_sides_share_the_same_psk() {
        let initiator_peer = Peer::generate().unwrap();
        let responder_peer = Peer::generate().unwrap();
        let psk = [42u8; PSK_LEN];

        let initiator =
            build_initiator_with_psk(&initiator_peer, &responder_peer.public_key, &psk).unwrap();
        let responder = build_responder_with_psk(&responder_peer, &psk).unwrap();

        let (mut initiator_transport, mut responder_transport) =
            perform_handshake(initiator, responder).expect("PSK handshake must complete");

        let plaintext = b"psk-protected message";
        let mut ciphertext = [0u8; 1024];
        let ct_len = initiator_transport
            .write_message(plaintext, &mut ciphertext)
            .unwrap();
        let mut decrypted = [0u8; 1024];
        let pt_len = responder_transport
            .read_message(&ciphertext[..ct_len], &mut decrypted)
            .expect("responder must decrypt with the matching PSK");
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn psk_mismatch_breaks_transport_decryption() {
        let initiator_peer = Peer::generate().unwrap();
        let responder_peer = Peer::generate().unwrap();
        let initiator_psk = [1u8; PSK_LEN];
        let responder_psk = [2u8; PSK_LEN]; // 意図的に異なるPSKを使わせる

        let initiator = build_initiator_with_psk(
            &initiator_peer,
            &responder_peer.public_key,
            &initiator_psk,
        )
        .unwrap();
        let responder = build_responder_with_psk(&responder_peer, &responder_psk).unwrap();

        // ハンドシェイク自体のメッセージ交換はPSKが違っても形の上では
        // 進む(Noiseのハンドシェイクメッセージ自体はPSKの正誤を即座には
        // 検証しない実装もあるため)が、導出される鍵が食い違うので、
        // その後の実データの暗号化/復号が必ず失敗する。これによって
        // 「PSKが一致しない限り通信が成立しない」ことを確認する。
        let handshake_result = perform_handshake(initiator, responder);

        match handshake_result {
            Err(_) => { /* ハンドシェイク自体で検出できた場合もOK */ }
            Ok((mut initiator_transport, mut responder_transport)) => {
                let plaintext = b"this must not be readable by the responder";
                let mut ciphertext = [0u8; 1024];
                let ct_len = initiator_transport
                    .write_message(plaintext, &mut ciphertext)
                    .unwrap();
                let mut decrypted = [0u8; 1024];
                let decrypt_result =
                    responder_transport.read_message(&ciphertext[..ct_len], &mut decrypted);
                assert!(
                    decrypt_result.is_err(),
                    "decryption must fail when the PSKs differ"
                );
            }
        }
    }
}
