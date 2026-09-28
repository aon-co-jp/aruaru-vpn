//! REALITYの本来の認証方式: X25519鍵共有 + HKDFによる認証タグ検証
//! (実装フェーズ3、`reality.rs`の簡略版session_id直接比較を置き換える)。
//!
//! 実際のREALITY([XTLS/REALITY](https://github.com/xtls/reality)の
//! 公開仕様のみ参考、コードは流用せず設計)は、クライアントが自分の
//! エフェメラル鍵とサーバーの公開鍵からX25519 ECDHで共有シークレットを
//! 導出し、そこからHKDFで認証タグを作る。サーバー側は同じ計算をして
//! タグが一致するかどうかで「正規のREALITYクライアントか、無関係な
//! 接続か」を判定する。
//!
//! **暗号プリミティブ(X25519・HKDF・SHA-256)は自作せず、監査済みの
//! Rust crate([x25519-dalek](https://crates.io/crates/x25519-dalek)、
//! [hkdf](https://crates.io/crates/hkdf))を使う。** 暗号アルゴリズムを
//! 独自実装することは、たとえ「他プロジェクトのコードを流用しない」という
//! エコシステム方針であっても重大なセキュリティリスクになるため、この方針
//! の対象外とする(一般的なベストプラクティス)。

use std::collections::HashSet;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 認証タグの長さ(バイト)。REALITY同様、TLSの`session_id`フィールド
/// (最大32バイト)に収まる長さにする。
pub const AUTH_TAG_LEN: usize = 16;

/// HKDFの`info`パラメータ(用途を明示し、他の鍵導出との混同を防ぐ)。
const HKDF_INFO: &[u8] = b"aruaru-vpn/reality/auth-tag/v1";

/// サーバーの長期鍵ペア(REALITYの「偽装先サイトの裏にある本当の秘密鍵」)。
pub struct ServerIdentity {
    secret: StaticSecret,
}

impl ServerIdentity {
    pub fn generate(csprng_seed: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(csprng_seed),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// クライアントのエフェメラル公開鍵とX25519 ECDHを行い、認証タグを導出する。
    ///
    /// サーバー・クライアント双方が同じ計算(自分の秘密鍵×相手の公開鍵)を
    /// 行うため、正規のクライアントであれば必ず同じタグに到達する
    /// (ECDHの対称性)。
    pub fn derive_auth_tag(&self, client_ephemeral_public: &PublicKey) -> [u8; AUTH_TAG_LEN] {
        let shared_secret = self.secret.diffie_hellman(client_ephemeral_public);
        derive_tag_from_shared_secret(shared_secret.as_bytes())
    }

    /// 認証タグと同じX25519 ECDH共有シークレットから、独自の暗号化通信路
    /// (`secure_channel`)用の鍵を導出する(実装フェーズ10)。認証タグの
    /// 導出とは別の`info`文字列を使うことで、2つの用途の鍵を暗号学的に
    /// 分離する(1つの共有シークレットから複数の独立した鍵を作る際の
    /// 標準的な作法)。
    pub fn derive_channel_keys(&self, client_ephemeral_public: &PublicKey) -> ChannelKeys {
        let shared_secret = self.secret.diffie_hellman(client_ephemeral_public);
        derive_channel_keys_from_shared_secret(shared_secret.as_bytes())
    }

    /// 認証タグ・`ChannelKeys`と同じX25519 ECDH共有シークレットから、
    /// [`crate::cert_clone`](実装フェーズ15)が使う64バイトの`AuthKey`を
    /// 導出する。この鍵はHMAC-SHA512の鍵として使われ、本物のREALITYが
    /// 「証明書の署名フィールドをHMAC値に差し替える」際の鍵と同じ役割を
    /// 果たす(出力を64バイトにしているのは、Ed25519署名の長さ〈64バイト〉
    /// に合わせ、TLS 1.3のCertificateVerifyメッセージのワイヤーフォーマット
    /// にそのまま収まるようにするため)。
    pub fn derive_cert_clone_auth_key(&self, client_ephemeral_public: &PublicKey) -> [u8; 64] {
        let shared_secret = self.secret.diffie_hellman(client_ephemeral_public);
        derive_cert_clone_auth_key_from_shared_secret(shared_secret.as_bytes())
    }
}

/// 双方向通信のための2本の鍵(送信方向ごとに別の鍵を使うのは、TLS等でも
/// 一般的な設計。1本の鍵を両方向で使い回すと、ノンス管理を誤った際に
/// 深刻な脆弱性〈鍵ストリームの再利用〉につながりやすいため)。
#[derive(Clone)]
pub struct ChannelKeys {
    pub initiator_to_responder: [u8; 32],
    pub responder_to_initiator: [u8; 32],
}

fn derive_channel_keys_from_shared_secret(shared_secret: &[u8; 32]) -> ChannelKeys {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut initiator_to_responder = [0u8; 32];
    let mut responder_to_initiator = [0u8; 32];
    hk.expand(
        b"aruaru-vpn/reality/channel/initiator-to-responder/v1",
        &mut initiator_to_responder,
    )
    .expect("32 bytes is a valid HKDF output length for SHA-256");
    hk.expand(
        b"aruaru-vpn/reality/channel/responder-to-initiator/v1",
        &mut responder_to_initiator,
    )
    .expect("32 bytes is a valid HKDF output length for SHA-256");
    ChannelKeys {
        initiator_to_responder,
        responder_to_initiator,
    }
}

/// クライアント側のエフェメラル鍵ペア(接続のたびに使い捨てる)。
pub struct ClientEphemeralKeypair {
    secret: StaticSecret,
}

impl ClientEphemeralKeypair {
    pub fn generate(csprng_seed: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(csprng_seed),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// サーバーの公開鍵とX25519 ECDHを行い、サーバー側と同じ手順で
    /// 認証タグを導出する。
    pub fn derive_auth_tag(&self, server_public: &PublicKey) -> [u8; AUTH_TAG_LEN] {
        let shared_secret = self.secret.diffie_hellman(server_public);
        derive_tag_from_shared_secret(shared_secret.as_bytes())
    }

    /// [`ServerIdentity::derive_channel_keys`]のクライアント側版。ECDHの
    /// 対称性により、双方が同じ`ChannelKeys`に到達する。
    pub fn derive_channel_keys(&self, server_public: &PublicKey) -> ChannelKeys {
        let shared_secret = self.secret.diffie_hellman(server_public);
        derive_channel_keys_from_shared_secret(shared_secret.as_bytes())
    }

    /// [`ServerIdentity::derive_cert_clone_auth_key`]のクライアント側版。
    pub fn derive_cert_clone_auth_key(&self, server_public: &PublicKey) -> [u8; 64] {
        let shared_secret = self.secret.diffie_hellman(server_public);
        derive_cert_clone_auth_key_from_shared_secret(shared_secret.as_bytes())
    }
}

const CERT_CLONE_AUTH_KEY_HKDF_INFO: &[u8] = b"aruaru-vpn/reality/cert-clone-auth-key/v1";

fn derive_cert_clone_auth_key_from_shared_secret(shared_secret: &[u8; 32]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut auth_key = [0u8; 64];
    hk.expand(CERT_CLONE_AUTH_KEY_HKDF_INFO, &mut auth_key)
        .expect("64 bytes is a valid HKDF output length for SHA-256");
    auth_key
}

fn derive_tag_from_shared_secret(shared_secret: &[u8; 32]) -> [u8; AUTH_TAG_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut tag = [0u8; AUTH_TAG_LEN];
    hk.expand(HKDF_INFO, &mut tag)
        .expect("AUTH_TAG_LEN is a valid HKDF output length for SHA-256");
    tag
}

/// サーバー側で、クライアントが提示したエフェメラル公開鍵+認証タグの組が
/// 正しいかどうかを検証する(定数時間比較でタイミング攻撃を防ぐ)。
pub fn verify_auth_tag(
    identity: &ServerIdentity,
    client_ephemeral_public: &PublicKey,
    presented_tag: &[u8],
) -> bool {
    // `presented_tag`は本来のTLSの`session_id`フィールド(0〜32バイト)
    // そのものであることがある。標準準拠のTLSクライアント(`rustls`等)が
    // 生成した32バイトのlegacy_session_idの**先頭`AUTH_TAG_LEN`バイトだけ**
    // を認証タグに差し替える設計(`cert_clone`の`SessionIdPatchingStream`
    // 参照、実装フェーズ15)のため、長さが一致しない場合は先頭部分だけを
    // 比較する。TLS 1.3ではlegacy_session_idの中身自体に暗号学的な意味は
    // 無い(middlebox互換のためだけに存在するフィールド)ため、この差し替え
    // はTLSプロトコル自体には一切影響しない。
    if presented_tag.len() < AUTH_TAG_LEN {
        return false;
    }
    let expected = identity.derive_auth_tag(client_ephemeral_public);
    constant_time_eq(&expected, &presented_tag[..AUTH_TAG_LEN])
}

/// [`crate::cert_clone`]用の、事前登録済みクライアント公開鍵の許可リスト
/// (実装フェーズ16)。
///
/// **設計上の経緯**: `session_id`にECDH由来の認証タグを埋め込む方式
/// (`verify_auth_tag`)は、`secure_channel`(独自フレーミング、こちらは
/// 双方とも自前実装なので問題無い)では機能するが、`cert_clone`(標準準拠の
/// `rustls`クライアントと相互運用する必要がある)では**根本的に機能しない**
/// ことが実装フェーズ16で判明した: TLS 1.3のハンドシェイク鍵は
/// ClientHelloの生バイト列全体のトランスクリプトハッシュから導出されるため、
/// `rustls`が内部で構築したClientHelloの`session_id`を送信後に書き換えると、
/// クライアント側の内部状態と実際に送信されたバイト列が食い違い、
/// `Finished`メッセージの検証が失敗する(`PORTING.md`「26.」に詳細記録)。
///
/// そこで`cert_clone`では、`key_share`拡張のX25519公開鍵**そのもの**を
/// クライアントの識別子として使う(この値はClientHello構築時から一貫して
/// 使われる値であり、後から書き換える必要が無い)。`vless::AllowedUuids`
/// と同じ「事前登録済みの識別子の許可リスト」という設計を踏襲する。
///
/// **既知のトレードオフ**: TLS1.3の`key_share`は本来エフェメラル(接続毎に
/// 使い捨て)であるべきだが、この設計ではクライアントが**固定の**識別鍵を
/// 繰り返し使うため、観測者がクライアントを複数接続にわたって追跡できて
/// しまう(プライバシー上の弱化)。`wireguard_handshake.rs`の`Peer`が既に
/// 同種の固定長期鍵を使っているのと同じ設計判断であり、TLS1.3セッション
/// 自体の前方秘匿性(サーバー側エフェメラル鍵は毎回新規)は失われない。
#[derive(Debug, Clone, Default)]
pub struct AllowedClientKeys {
    keys: HashSet<[u8; 32]>,
}

impl AllowedClientKeys {
    pub fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    pub fn is_allowed(&self, key: &PublicKey) -> bool {
        self.keys.contains(key.as_bytes())
    }
}

/// タイミング攻撃を避けるための定数時間バイト列比較。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn client_and_server_derive_the_same_tag() {
        let server = ServerIdentity::generate(seed(1));
        let client = ClientEphemeralKeypair::generate(seed(2));

        let server_tag = server.derive_auth_tag(&client.public_key());
        let client_tag = client.derive_auth_tag(&server.public_key());

        assert_eq!(server_tag, client_tag);
    }

    #[test]
    fn client_and_server_derive_the_same_cert_clone_auth_key() {
        let server = ServerIdentity::generate(seed(11));
        let client = ClientEphemeralKeypair::generate(seed(12));

        let server_key = server.derive_cert_clone_auth_key(&client.public_key());
        let client_key = client.derive_cert_clone_auth_key(&server.public_key());

        assert_eq!(server_key, client_key);
        assert_ne!(
            server_key.to_vec(),
            server.derive_auth_tag(&client.public_key()).to_vec()
        );
    }

    #[test]
    fn client_and_server_derive_the_same_channel_keys() {
        let server = ServerIdentity::generate(seed(3));
        let client = ClientEphemeralKeypair::generate(seed(4));

        let server_keys = server.derive_channel_keys(&client.public_key());
        let client_keys = client.derive_channel_keys(&server.public_key());

        assert_eq!(
            server_keys.initiator_to_responder,
            client_keys.initiator_to_responder
        );
        assert_eq!(
            server_keys.responder_to_initiator,
            client_keys.responder_to_initiator
        );
    }

    #[test]
    fn channel_keys_are_domain_separated_from_the_auth_tag_and_from_each_other() {
        let server = ServerIdentity::generate(seed(5));
        let client_public = ClientEphemeralKeypair::generate(seed(6)).public_key();

        let tag = server.derive_auth_tag(&client_public);
        let keys = server.derive_channel_keys(&client_public);

        assert_ne!(&tag[..], &keys.initiator_to_responder[..tag.len()]);
        assert_ne!(keys.initiator_to_responder, keys.responder_to_initiator);
    }

    #[test]
    fn verify_auth_tag_accepts_genuine_client() {
        let server = ServerIdentity::generate(seed(10));
        let client = ClientEphemeralKeypair::generate(seed(20));

        let tag = client.derive_auth_tag(&server.public_key());
        assert!(verify_auth_tag(&server, &client.public_key(), &tag));
    }

    #[test]
    fn verify_auth_tag_rejects_wrong_tag() {
        let server = ServerIdentity::generate(seed(10));
        let client = ClientEphemeralKeypair::generate(seed(20));

        let mut wrong_tag = client.derive_auth_tag(&server.public_key());
        wrong_tag[0] ^= 0xFF;
        assert!(!verify_auth_tag(&server, &client.public_key(), &wrong_tag));
    }

    #[test]
    fn verify_auth_tag_rejects_impersonator_without_real_client_key() {
        let server = ServerIdentity::generate(seed(10));
        let real_client = ClientEphemeralKeypair::generate(seed(20));
        let impersonator = ClientEphemeralKeypair::generate(seed(99));

        // 攻撃者は正規クライアントの公開鍵を「見る」ことはできるが、
        // 対応する秘密鍵を持たないため、正しいタグを計算できない。
        let forged_tag = impersonator.derive_auth_tag(&server.public_key());
        assert!(!verify_auth_tag(
            &server,
            &real_client.public_key(),
            &forged_tag
        ));
    }

    #[test]
    fn verify_auth_tag_rejects_wrong_length() {
        let server = ServerIdentity::generate(seed(10));
        let client = ClientEphemeralKeypair::generate(seed(20));
        assert!(!verify_auth_tag(&server, &client.public_key(), &[0u8; 4]));
    }
}
