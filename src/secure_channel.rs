//! REALITY認証(X25519 ECDH)で確立済みの共有鍵から、独自のAEAD暗号化
//! レコード層を実装する(実装フェーズ10)。
//!
//! **背景・設計判断**: `rustls`(標準TLS実装)は、私たちの`ClientHello`
//! `session_id`欄への認証タグ埋め込みという非標準な構造を受け付けない
//! (`tls_terminate.rs`のドキュメント参照)。本来のREALITY(Xray-core)は
//! TLSクライアント/サーバー実装自体を改造(uTLS等)することでこれを解決
//! しているが、それは非常に大規模な作業になる。
//!
//! そこでここでは、**TLS標準への準拠(既存のTLSライブラリとの相互接続性)
//! は目指さず**、`reality_auth`で既に確立した共有鍵をそのまま使って、
//! 独自のフレーミング(`[4バイト長][暗号文+認証タグ]`)によるAEAD暗号化
//! 通信路を実装する。これは「TLS 1.3のレコード層」そのものではないが、
//! 同種の目的(ECDHで確立した鍵による認証付き暗号化通信)を、
//! 監査済みの暗号プリミティブ([chacha20poly1305](https://crates.io/crates/chacha20poly1305))
//! の上に実装するという点で、TLS 1.3のレコード層と設計思想は同じである。
//!
//! **暗号プリミティブ(ChaCha20-Poly1305)は自作しない**(`reality_auth.rs`と
//! 同じ理由)。自作するのはレコードの組み立て・ノンス管理・鍵の方向分離のみ。

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::reality_auth::ChannelKeys;

/// 1メッセージあたりの最大平文長(暴走したlengthフィールドによる過大な
/// メモリ確保を防ぐための上限)。
const MAX_MESSAGE_LEN: usize = 1 << 20; // 1 MiB

/// 送信専用の暗号化ライター。ノンスはメッセージごとに単調増加させる
/// (同じ鍵で同じノンスを2回使うと、ChaCha20-Poly1305の安全性が完全に
/// 崩れるため、カウンタ管理は特に注意深く実装している)。
pub struct SecureWriter<W> {
    inner: W,
    cipher: ChaCha20Poly1305,
    next_nonce: u64,
}

/// 受信専用の復号リーダー。送信側と同じ規則(0から単調増加)で相手の
/// ノンスを再構築する。
pub struct SecureReader<R> {
    inner: R,
    cipher: ChaCha20Poly1305,
    next_nonce: u64,
}

/// ノンスを「96ビットのうち先頭8バイトは0埋め、末尾8バイトにカウンタを
/// ビッグエンディアンで格納」という単純な規則で組み立てる。
fn nonce_from_counter(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(bytes)
}

impl<W: tokio::io::AsyncWrite + Unpin> SecureWriter<W> {
    pub fn new(inner: W, key: [u8; 32]) -> Self {
        Self {
            inner,
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            next_nonce: 0,
        }
    }

    /// `plaintext`を暗号化し、`[4バイト長(暗号文+タグの長さ)][暗号文+タグ]`
    /// の形でそのまま書き込む。
    pub async fn send(&mut self, plaintext: &[u8]) -> std::io::Result<()> {
        if plaintext.len() > MAX_MESSAGE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "message exceeds MAX_MESSAGE_LEN",
            ));
        }
        let nonce = nonce_from_counter(self.next_nonce);
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .expect("nonce counter must not wrap around within a single connection's lifetime");

        let ciphertext = self.cipher.encrypt(&nonce, plaintext).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "AEAD encryption failed")
        })?;

        self.inner
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await?;
        self.inner.write_all(&ciphertext).await?;
        Ok(())
    }

    /// 書き込み方向を明示的に終了する(TCPの片方向クローズ相当)。
    ///
    /// **重要**: `tokio::io::split`で分割した`ReadHalf`/`WriteHalf`は、
    /// 基盤となるストリームをArcで共有しているだけなので、`WriteHalf`を
    /// ただ`drop`しても、まだ`ReadHalf`が生きていれば実際のソケットは
    /// クローズされず、相手側はEOFを検知できない(このバグは実際に
    /// end-to-endテストで再現し、通信が永久にハングする原因になった)。
    /// 相手に「もう送るものが無い」と伝えるには、この`shutdown`を明示的に
    /// 呼ぶ必要がある。
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.inner.shutdown().await
    }
}

impl<R: tokio::io::AsyncRead + Unpin> SecureReader<R> {
    pub fn new(inner: R, key: [u8; 32]) -> Self {
        Self {
            inner,
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            next_nonce: 0,
        }
    }

    /// 次の1メッセージを読み取り、復号した平文を返す。認証タグの検証に
    /// 失敗した場合(改竄・鍵の不一致・ノンスのずれ等)はエラーを返す。
    pub async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_LEN + 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "declared message length exceeds MAX_MESSAGE_LEN",
            ));
        }

        let mut ciphertext = vec![0u8; len];
        self.inner.read_exact(&mut ciphertext).await?;

        let nonce = nonce_from_counter(self.next_nonce);
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .expect("nonce counter must not wrap around within a single connection's lifetime");

        self.cipher
            .decrypt(&nonce, ciphertext.as_slice())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "AEAD authentication failed (tampered data, wrong key, or nonce desync)",
                )
            })
    }
}

/// `ChannelKeys`(方向ごとの2本の鍵)から、イニシエーター(クライアント)
/// 側の送受信ペアを組み立てるヘルパー。
pub fn initiator_channel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    keys: &ChannelKeys,
) -> (
    SecureWriter<tokio::io::WriteHalf<S>>,
    SecureReader<tokio::io::ReadHalf<S>>,
)
where
    S: Send,
{
    let (read_half, write_half) = tokio::io::split(stream);
    (
        SecureWriter::new(write_half, keys.initiator_to_responder),
        SecureReader::new(read_half, keys.responder_to_initiator),
    )
}

/// レスポンダー(サーバー)側の送受信ペアを組み立てるヘルパー(鍵の
/// 割り当てが`initiator_channel`と逆になる)。
pub fn responder_channel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    keys: &ChannelKeys,
) -> (
    SecureWriter<tokio::io::WriteHalf<S>>,
    SecureReader<tokio::io::ReadHalf<S>>,
)
where
    S: Send,
{
    let (read_half, write_half) = tokio::io::split(stream);
    (
        SecureWriter::new(write_half, keys.responder_to_initiator),
        SecureReader::new(read_half, keys.initiator_to_responder),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_auth::{ClientEphemeralKeypair, ServerIdentity};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn client_and_server_exchange_encrypted_messages_over_a_real_tcp_socket() {
        let server_identity = ServerIdentity::generate([11u8; 32]);
        let client_keys_pair = ClientEphemeralKeypair::generate([22u8; 32]);

        let server_channel_keys =
            server_identity.derive_channel_keys(&client_keys_pair.public_key());
        let client_channel_keys =
            client_keys_pair.derive_channel_keys(&server_identity.public_key());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut writer, mut reader) = responder_channel(stream, &server_channel_keys);

            let received = reader
                .recv()
                .await
                .expect("server must decrypt client's message");
            assert_eq!(received, b"hello from client");

            writer
                .send(b"hello from server")
                .await
                .expect("server must send an encrypted reply");
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (mut writer, mut reader) = initiator_channel(client_stream, &client_channel_keys);

        writer.send(b"hello from client").await.unwrap();
        let received = reader
            .recv()
            .await
            .expect("client must decrypt server's reply");
        assert_eq!(received, b"hello from server");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn mismatched_keys_cause_decryption_to_fail_rather_than_silently_succeed() {
        let server_identity = ServerIdentity::generate([1u8; 32]);
        let real_client = ClientEphemeralKeypair::generate([2u8; 32]);
        let impersonator = ClientEphemeralKeypair::generate([3u8; 32]);

        // サーバーは本物のクライアント公開鍵で鍵を導出するが、
        // 攻撃者は自分の鍵ペア(=別のECDH結果)を使って暗号化してしまう
        // 状況を模擬する。
        let server_channel_keys = server_identity.derive_channel_keys(&real_client.public_key());
        let impersonator_channel_keys =
            impersonator.derive_channel_keys(&server_identity.public_key());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_writer, mut reader) = responder_channel(stream, &server_channel_keys);
            reader.recv().await
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (mut writer, _reader) = initiator_channel(client_stream, &impersonator_channel_keys);
        writer.send(b"forged message").await.unwrap();

        let result = server_task.await.unwrap();
        assert!(
            result.is_err(),
            "decryption must fail when the sender used the wrong (impersonator's) keys"
        );
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected_without_allocating_it() {
        use tokio::io::AsyncWriteExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let keys = ChannelKeys {
            initiator_to_responder: [9u8; 32],
            responder_to_initiator: [9u8; 32],
        };
        let keys_for_server = keys.clone();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_writer, mut reader) = responder_channel(stream, &keys_for_server);
            reader.recv().await
        });

        let mut client_stream = TcpStream::connect(addr).await.unwrap();
        // MAX_MESSAGE_LENを大幅に超える、明らかに不正な長さを直接書き込む。
        client_stream
            .write_all(&(u32::MAX).to_be_bytes())
            .await
            .unwrap();

        let result = server_task.await.unwrap();
        assert!(
            result.is_err(),
            "an absurd declared length must be rejected"
        );
    }
}
