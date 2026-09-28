//! REALITY本来の証明書クローン(実装フェーズ15)。
//!
//! 実装フェーズ12では「現在のアーキテクチャ(`secure_channel`という
//! TLSではない独自フレーミング)では証明書クローンは不要」と結論づけたが、
//! それは誤りだった(`PORTING.md`「25.」に訂正を記録)。本物のREALITY
//! ([XTLS/REALITY](https://github.com/XTLS/REALITY)、
//! [Xray-core](https://github.com/XTLS/Xray-core))が証明書クローンをする
//! 本当の理由は「クライアント自身がTLS証明書検証をするかどうか」ではなく、
//! **「第三者の検閲装置(DPI)がワイヤー上のバイト列を観測したときに、
//! 本物のサイトへの普通のTLS接続と区別がつくかどうか」**である。
//! `secure_channel`の独自フレーミングは、ClientHelloの直後から明らかに
//! 非TLS構造のバイト列に切り替わるため、この脅威モデルに対して脆弱だった。
//!
//! **設計方針**: 本物のXray-core REALITYはGoの`crypto/tls`標準ライブラリ
//! 自体をフォークする、非常に大規模な実装になっている(Go標準ライブラリは
//! 十分な拡張ポイントを公開していないため)。しかし[rustls](https://crates.io/crates/rustls)
//! は、この目的に必要な拡張ポイントを**標準APIとして公開している**ため、
//! rustls自体をフォークせずに実装できる:
//!
//! - サーバー側: [`rustls::sign::SigningKey`]/[`rustls::sign::Signer`]を
//!   自前実装し、CertificateVerifyメッセージの「署名」として、本物の
//!   秘密鍵による署名の代わりに**HMAC-SHA512値**を返す
//!   ([`reality_auth::derive_cert_clone_auth_key`]で導出した64バイトの鍵、
//!   Ed25519署名と同じ64バイト長になるようスキームをED25519と偽って宣言)。
//!   証明書チェーン自体は、偽装先サイトへ実際にTLS接続して取得した
//!   **本物の公開証明書バイト列**(`fetch_real_certificate_chain`)を
//!   そのまま使う(秘密鍵は不要、証明書は公開情報)。
//! - クライアント側: [`rustls::client::danger::ServerCertVerifier`]を
//!   自前実装し、通常の証明書チェーン検証(CA・ドメイン名照合)を行わず、
//!   代わりに同じHMAC-SHA512値を自分で計算して照合する(一致すれば
//!   `Ok`、これが「認証」そのものになる)。
//!
//! 鍵交換(X25519)・レコード層の暗号化(AEAD)・ハンドシェイクの全体構造は
//! **一切変更せず、標準のTLS 1.3のまま**にする。変更点はCertificateの中身
//! (本物の証明書バイト列を借用)とCertificateVerifyの署名バイト列
//! (HMACに差し替え)だけであり、これが「ワイヤー上のバイト列が本物のTLS
//! 1.3と区別できない」という本来のREALITYの特性を実現する。
//!
//! **クライアント認証の判定方法(実装フェーズ16で訂正)**: 当初は
//! `accept_and_route`(`secure_channel`版)と同じ「ClientHelloの
//! `session_id`にECDH認証タグを埋め込む」方式を流用しようとしたが、
//! 標準準拠の`rustls`クライアントと組み合わせると**根本的に破綻する**
//! ことが判明した。TLS 1.3のハンドシェイク鍵はClientHelloの生バイト列
//! 全体のトランスクリプトハッシュから導出されるため、`rustls`が内部で
//! 構築したClientHelloの`session_id`を送信後に書き換えると、クライアント
//! 側の内部状態(未パッチのバイト列で計算済み)と実際に送信されたバイト列
//! (パッチ済み)が食い違い、`Finished`メッセージの検証が`DecryptError`で
//! 失敗する。本物のREALITY(Xray-core)がGoの`crypto/tls`を丸ごとフォーク
//! している理由はまさにこれで、uTLSは「トランスクリプトハッシュが計算
//! される**前**に」ClientHelloへ認証情報を埋め込める。`rustls`の公開APIに
//! 同等のフックは無い。
//!
//! そこで、`session_id`への埋め込みではなく、[`rustls::crypto::SupportedKxGroup`]
//! を自前実装して**`key_share`拡張のX25519公開鍵そのものをクライアントの
//! 固定識別子として使う**方式に変更した([`FixedX25519ActiveKeyExchange`]、
//! `reality_auth::AllowedClientKeys`)。`key_share`はClientHello構築時から
//! 一貫して使われる値であり、後から書き換える必要が無いため、トランス
//! クリプトハッシュの問題を回避できる。トレードオフは
//! `reality_auth::AllowedClientKeys`のドキュメント参照。

use std::io;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

type HmacSha512 = Hmac<sha2::Sha512>;

/// 署名として使う`SignatureScheme`。Ed25519署名は64バイト固定長であり、
/// HMAC-SHA512の出力(64バイト)とちょうど一致するため、ワイヤー
/// フォーマット上の追加の細工なしに「Ed25519の署名です」と偽装できる。
const CERT_CLONE_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;

fn compute_hmac(auth_key: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(auth_key).expect("HMAC-SHA512 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// 偽装先サイト(`dest`)へ実際にTLS接続し、**本物の公開証明書チェーン**を
/// 取得する(「証明書クローン」の"クローン元"を手に入れる部分)。
///
/// 証明書は公開情報(秘密鍵は一切やり取りしない)なので、チェーン検証を
/// 行わない緩い`ServerCertVerifier`で構わない(この接続自体の安全性は
/// 問題にならない、欲しいのはバイト列だけ)。
pub async fn fetch_real_certificate_chain(
    dest_host: &str,
    dest_port: u16,
) -> io::Result<Vec<CertificateDer<'static>>> {
    #[derive(Debug)]
    struct AcceptAnyServerCert;

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // 偽装先サイトは普通のTLSサーバーなので、標準的なスキームを
            // 幅広く受け入れる。
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(dest_host.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect((dest_host, dest_port)).await?;
    let tls_stream = connector.connect(server_name, tcp).await?;

    let (_io, connection) = tls_stream.get_ref();
    let chain = connection
        .peer_certificates()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dest presented no certificate"))?
        .to_vec();
    Ok(chain)
}

/// サーバー側の署名鍵(実装フェーズ15)。本物の秘密鍵は持たず、
/// `auth_key`によるHMAC-SHA512を「署名」として返す。
#[derive(Debug)]
struct AuthKeySigner {
    auth_key: [u8; 64],
}

impl Signer for AuthKeySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(compute_hmac(&self.auth_key, message))
    }

    fn scheme(&self) -> SignatureScheme {
        CERT_CLONE_SIGNATURE_SCHEME
    }
}

#[derive(Debug)]
struct AuthKeySigningKey {
    auth_key: [u8; 64],
}

impl SigningKey for AuthKeySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&CERT_CLONE_SIGNATURE_SCHEME) {
            Some(Box::new(AuthKeySigner {
                auth_key: self.auth_key,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// [`rustls::server::ResolvesServerCert`]の自前実装(実装フェーズ15)。
/// 常に同じ「本物の証明書チェーン(借用)+HMAC署名鍵」を返す。
#[derive(Debug)]
struct ClonedCertResolver {
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for ClonedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified_key))
    }
}

/// サーバー側: `real_cert_chain`(偽装先から借用した本物の証明書)と
/// `auth_key`(REALITY認証のECDHから導出済み)を使い、TLS 1.3限定の
/// `TlsAcceptor`を組み立てる。
pub fn build_cloned_server_acceptor(
    real_cert_chain: Vec<CertificateDer<'static>>,
    auth_key: [u8; 64],
) -> Result<TlsAcceptor, rustls::Error> {
    let certified_key = Arc::new(CertifiedKey {
        cert: real_cert_chain,
        key: Arc::new(AuthKeySigningKey { auth_key }),
        ocsp: None,
    });
    let resolver = Arc::new(ClonedCertResolver { certified_key });

    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// クライアント側: 通常の証明書チェーン検証を行わず、`auth_key`による
/// HMAC-SHA512の再計算・照合だけで認証する`ServerCertVerifier`
/// (実装フェーズ15)。
#[derive(Debug)]
struct AuthKeyVerifier {
    auth_key: [u8; 64],
}

impl ServerCertVerifier for AuthKeyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 本来のREALITYと同じく、CA/ドメイン名によるチェーン検証は行わない
        // (信頼はX25519 ECDHの共有シークレット、つまりCertificateVerifyの
        // HMAC照合〈`verify_tls13_signature`〉の側で確立する)。
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "aruaru-vpn cert_clone requires TLS 1.3".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let expected = compute_hmac(&self.auth_key, message);
        if constant_time_eq(&expected, dss.signature()) {
            Ok(HandshakeSignatureValid::assertion())
        } else {
            Err(rustls::Error::General(
                "aruaru-vpn cert_clone: AuthKey signature mismatch".to_owned(),
            ))
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![CERT_CLONE_SIGNATURE_SCHEME]
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        None
    }
}

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

/// クライアント側: `auth_key`を使う`TlsConnector`を組み立てる。
///
/// **注意**: この関数はTLS鍵交換にrustls標準のX25519実装(ランダムな
/// エフェメラル鍵)を使う。REALITY認証(`accept_and_route_cert_cloned`の
/// ClientHello覗き見判定)と組み合わせて実際に使う場合は、代わりに
/// [`build_cloned_client_connector_with_reality_ephemeral`]を使い、
/// TLSの鍵交換自体にREALITY認証のエフェメラル鍵を使わせる必要がある
/// (下記のドキュメント参照)。この関数は`cert_clone`単体のTLS
/// ハンドシェイク自体の正しさを確認するテスト用。
pub fn build_cloned_client_connector(auth_key: [u8; 64]) -> TlsConnector {
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AuthKeyVerifier { auth_key }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// [`rustls::crypto::ActiveKeyExchange`]の自前実装(実装フェーズ16):
/// rustlsが生成するランダムなエフェメラル鍵の代わりに、
/// **REALITY認証のエフェメラル鍵(`reality_auth::ClientEphemeralKeypair`)を
/// そのままTLSの鍵交換にも使う**。
///
/// **これが必要な理由**: `accept_and_route_cert_cloned`は、ClientHelloの
/// `key_share`拡張からクライアントのX25519公開鍵を読み取り、それに対して
/// `ServerIdentity::derive_auth_tag`/`derive_cert_clone_auth_key`を計算して
/// REALITY認証を判定する。rustls標準のTLSクライアントは`key_share`に
/// **ランダムに生成した使い捨てのエフェメラル鍵**を使うため、そのままでは
/// サーバー側が「どの秘密鍵とペアなのか」を知りようがなく、REALITY認証の
/// 計算(ECDH)ができない。そこで、TLSの鍵交換自体に**呼び出し側が指定した
/// 特定のX25519秘密鍵**を使わせることで、`key_share`に載る公開鍵が
/// `ClientEphemeralKeypair::public_key()`と一致するようにする。
///
/// TLS 1.3セッション自体の前方秘匿性は損なわれない(サーバー側のTLS
/// エフェメラル鍵は`rustls`が生成する通常のランダム値のまま、ECDHE鍵交換
/// 自体は毎回異なる組み合わせになる)。REALITY認証はこの鍵交換とは別に、
/// 同じクライアント公開鍵を使って「サーバーの**長期**識別鍵」との間で
/// 独立にECDHを行う側面計算に過ぎない(本物のREALITYと同じ設計、
/// `PORTING.md`「25.」参照)。
struct FixedX25519ActiveKeyExchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl std::fmt::Debug for FixedX25519ActiveKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedX25519ActiveKeyExchange")
            .finish_non_exhaustive()
    }
}

impl rustls::crypto::ActiveKeyExchange for FixedX25519ActiveKeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        let peer_bytes: [u8; 32] = peer_pub_key.try_into().map_err(|_| {
            rustls::Error::General(
                "aruaru-vpn cert_clone: malformed X25519 peer public key".to_owned(),
            )
        })?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer_bytes));
        Ok(rustls::crypto::SharedSecret::from(
            shared.as_bytes().as_slice(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
struct FixedX25519KxGroup {
    seed: [u8; 32],
}

impl rustls::crypto::SupportedKxGroup for FixedX25519KxGroup {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        let secret = x25519_dalek::StaticSecret::from(self.seed);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(FixedX25519ActiveKeyExchange { secret, public }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// [`build_cloned_client_connector`]の、実運用向けの版(実装フェーズ16):
/// `ephemeral_seed`(REALITY認証の`ClientEphemeralKeypair::generate`に渡した
/// のと同じシード)をTLSの鍵交換自体にも使わせることで、サーバー側の
/// `accept_and_route_cert_cloned`が`key_share`から読み取る公開鍵と、
/// REALITY認証で使うエフェメラル公開鍵が一致するようにする
/// (`FixedX25519ActiveKeyExchange`のドキュメント参照)。
///
/// 呼び出す側は、`ephemeral_seed`から作った公開鍵を事前に
/// `reality_auth::AllowedClientKeys`へ登録しておく必要がある(サーバー側が
/// `key_share`から読み取った公開鍵をそこで照合する、実装フェーズ16の設計、
/// このモジュールの先頭ドキュメント参照)。
pub fn build_cloned_client_connector_with_reality_ephemeral(
    auth_key: [u8; 64],
    ephemeral_seed: [u8; 32],
) -> TlsConnector {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let kx_group: &'static FixedX25519KxGroup = Box::leak(Box::new(FixedX25519KxGroup {
        seed: ephemeral_seed,
    }));
    provider.kx_groups = vec![kx_group];

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the aws_lc_rs provider with an X25519 kx group")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AuthKeyVerifier { auth_key }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// `www.microsoft.com`は外部ネットワークへの実接続が必要でテストには
    /// 不向きなため、テストでは`rcgen`で自己署名証明書を立てたローカルの
    /// モックTLSサーバーを「偽装先サイト」役として使い、そこから本物の
    /// (このテストにおいては自己署名だが、秘密鍵を持たない状態で借用する
    /// という構造は同じ)証明書チェーンを取得できることを確認する。
    #[tokio::test]
    async fn fetches_real_certificate_chain_from_a_live_tls_server() {
        let (cert, key) =
            crate::tls_terminate::generate_self_signed_cert("mock-camouflage-target.test").unwrap();
        let acceptor = crate::tls_terminate::build_server_acceptor(cert.clone(), key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 16];
            let _ = tls.read(&mut buf).await;
            let _ = tls.shutdown().await;
        });

        let chain = fetch_real_certificate_chain("127.0.0.1", addr.port())
            .await
            .expect("must fetch the mock camouflage target's real certificate chain");

        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].as_ref(), cert.as_ref());
    }

    /// フルパイプライン(実装フェーズ15): 本物の証明書チェーン(自己署名の
    /// モックサイトから借用)+`AuthKey`によるHMAC署名差し替えで、実際に
    /// TLS 1.3ハンドシェイクが成立し、以降アプリケーションデータの
    /// 暗号化された往復ができることを確認する。
    #[tokio::test]
    async fn cloned_tls_handshake_completes_and_carries_encrypted_application_data() {
        use crate::reality_auth::{ClientEphemeralKeypair, ServerIdentity};

        // 偽装先サイト役(自己署名証明書のモックTLSサーバー)。
        let (camouflage_cert, camouflage_key) =
            crate::tls_terminate::generate_self_signed_cert("mock-camouflage-target.test").unwrap();
        let camouflage_acceptor =
            crate::tls_terminate::build_server_acceptor(camouflage_cert, camouflage_key).unwrap();
        let camouflage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camouflage_addr = camouflage_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = camouflage_listener.accept().await {
                if let Ok(mut tls) = camouflage_acceptor.accept(tcp).await {
                    let mut buf = [0u8; 16];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.shutdown().await;
                }
            }
        });

        // REALITY認証(X25519 ECDH)から、両者が同じAuthKeyへ到達する。
        let identity = ServerIdentity::generate([70u8; 32]);
        let client_ephemeral = ClientEphemeralKeypair::generate([71u8; 32]);
        let server_auth_key = identity.derive_cert_clone_auth_key(&client_ephemeral.public_key());
        let client_auth_key = client_ephemeral.derive_cert_clone_auth_key(&identity.public_key());
        assert_eq!(server_auth_key, client_auth_key);

        // 本物の証明書チェーンを、偽装先(モックサイト)から実際に取得する。
        let real_cert_chain = fetch_real_certificate_chain("127.0.0.1", camouflage_addr.port())
            .await
            .unwrap();

        let server_acceptor =
            build_cloned_server_acceptor(real_cert_chain, server_auth_key).unwrap();
        let client_connector = build_cloned_client_connector(client_auth_key);

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = relay_listener.accept().await.unwrap();
            let mut tls = server_acceptor.accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            let _ = tls.shutdown().await;
        });

        let tcp = TcpStream::connect(relay_addr).await.unwrap();
        let server_name = ServerName::try_from("mock-camouflage-target.test").unwrap();
        let mut client_tls = client_connector.connect(server_name, tcp).await.unwrap();

        client_tls
            .write_all(b"cloned-tls-application-data")
            .await
            .unwrap();
        let mut echoed = vec![0u8; b"cloned-tls-application-data".len()];
        client_tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"cloned-tls-application-data");

        client_tls.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    /// 誤った(別のECDHから導出された)AuthKeyを持つクライアントは、
    /// CertificateVerifyのHMAC照合に失敗し、ハンドシェイクが失敗すること
    /// を確認する(認証として機能していることの確認)。
    #[tokio::test]
    async fn wrong_auth_key_fails_the_handshake() {
        use crate::reality_auth::{ClientEphemeralKeypair, ServerIdentity};

        let (camouflage_cert, camouflage_key) =
            crate::tls_terminate::generate_self_signed_cert("mock-camouflage-target.test").unwrap();
        let camouflage_acceptor =
            crate::tls_terminate::build_server_acceptor(camouflage_cert, camouflage_key).unwrap();
        let camouflage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camouflage_addr = camouflage_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = camouflage_listener.accept().await {
                if let Ok(mut tls) = camouflage_acceptor.accept(tcp).await {
                    let mut buf = [0u8; 16];
                    let _ = tls.read(&mut buf).await;
                }
            }
        });

        let identity = ServerIdentity::generate([80u8; 32]);
        let client_ephemeral = ClientEphemeralKeypair::generate([81u8; 32]);
        let server_auth_key = identity.derive_cert_clone_auth_key(&client_ephemeral.public_key());
        // クライアント側は無関係な別のエフェメラル鍵からAuthKeyを導出する
        // (=同じ共有シークレットに到達できない、なりすましのシミュレーション)。
        let impersonator_ephemeral = ClientEphemeralKeypair::generate([99u8; 32]);
        let wrong_auth_key =
            impersonator_ephemeral.derive_cert_clone_auth_key(&identity.public_key());
        assert_ne!(server_auth_key, wrong_auth_key);

        let real_cert_chain = fetch_real_certificate_chain("127.0.0.1", camouflage_addr.port())
            .await
            .unwrap();

        let server_acceptor =
            build_cloned_server_acceptor(real_cert_chain, server_auth_key).unwrap();
        let client_connector = build_cloned_client_connector(wrong_auth_key);

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = relay_listener.accept().await.unwrap();
            let _ = server_acceptor.accept(tcp).await; // クライアント側の失敗で切断される想定
        });

        let tcp = TcpStream::connect(relay_addr).await.unwrap();
        let server_name = ServerName::try_from("mock-camouflage-target.test").unwrap();
        let result = client_connector.connect(server_name, tcp).await;

        assert!(result.is_err(), "wrong AuthKey must fail the handshake");
    }
}
