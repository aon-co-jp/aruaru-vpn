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
    if presented_tag.len() != AUTH_TAG_LEN {
        return false;
    }
    let expected = identity.derive_auth_tag(client_ephemeral_public);
    constant_time_eq(&expected, presented_tag)
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
