//! 実TLS終端(実装フェーズ9・試作品): 自己署名証明書によるTLSハンドシェイク
//! の実際の完了。
//!
//! これまで(`reality`/`tls_clienthello`)は、TLS `ClientHello`のバイト列を
//! 覗き見て認証判定するだけで、実際の暗号化/復号(TLSハンドシェイクの完了)
//! はしていなかった。ここでは監査済みのRust TLS実装
//! ([rustls](https://crates.io/crates/rustls)、
//! [tokio-rustls](https://crates.io/crates/tokio-rustls))を使い、
//! **実際にTLSハンドシェイクを完了させ、暗号化された通信路を確立する**
//! 試作品を実装する。
//!
//! **重要な簡略化(ユーザーとの合意通り)**: 本来のREALITYは偽装先サイトの
//! 証明書をそのまま流用する(証明書のクローン)が、その完全な模倣は非常に
//! 高度な技術であるため、この試作品では**自己署名証明書**でTLSを終端する。
//! 暗号化通信路としては機能するが、証明書の偽装(検閲側から見て「本物の
//! 偽装先サイト」に見えること)はまだ実現していない。
//!
//! **暗号プリミティブ・TLSプロトコル自体は自作せず、`rustls`に委ねる**
//! (`reality_auth.rs`/`wireguard_handshake.rs`と同じ理由)。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// テスト・開発用に、その場で自己署名証明書(+対応する秘密鍵)を生成する。
/// 実運用では固定の証明書ファイルを読み込む形に置き換える(次フェーズ)。
pub fn generate_self_signed_cert(
    subject_alt_name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), rcgen::Error> {
    let cert_key = rcgen::generate_simple_self_signed([subject_alt_name.to_owned()])?;
    let cert_der = cert_key.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert_key.signing_key.serialize_der().into());
    Ok((cert_der, key_der))
}

/// サーバー側のTLS設定(証明書+秘密鍵)から`TlsAcceptor`を作る。
pub fn build_server_acceptor(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, rustls::Error> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// クライアント側のTLS設定を、「この特定の自己署名証明書だけを信頼する」
/// 形で作る(テスト用。実運用のクライアントはOS/ブラウザ標準のルート証明書
/// ストアを使うのが普通だが、ここでは自己署名証明書を検証するための
/// 最小構成)。
pub fn build_client_connector(
    trusted_cert: CertificateDer<'static>,
) -> Result<TlsConnector, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted_cert).map_err(|e| {
        rustls::Error::General(format!("failed to add self-signed cert as trusted root: {e}"))
    })?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// `accept_and_route`が最初の読み取りで既に消費してしまったバイト列
/// (TLS `ClientHello`の先頭部分)を、TLSハンドシェイクへ「巻き戻す」ための
/// ラッパー。読み取り時にまず`prefix`の残りを返し、それを使い切ったら
/// 実ソケット(`inner`)からの読み取りに切り替える。書き込みは常に`inner`へ
/// そのまま委譲する。
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 既に読み取り済みのバイト列(`prefix`)を先頭に「巻き戻し」つつ、
/// `socket`に対して実際にTLSサーバーとしてのハンドシェイクを完了させる。
pub async fn terminate_tls_with_prefix(
    acceptor: &TlsAcceptor,
    prefix: Vec<u8>,
    socket: TcpStream,
) -> io::Result<tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>> {
    let prefixed = PrefixedStream::new(prefix, socket);
    acceptor.accept(prefixed).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// サーバー側が最初の読み取りで一部のバイト(ClientHelloの先頭)を
    /// 別の用途(REALITY判定)のために消費済みであっても、その分を
    /// `PrefixedStream`で巻き戻せば、TLSハンドシェイクが実際に最後まで
    /// 完了し、暗号化されたアプリケーションデータを送受信できることを
    /// 確認する。
    #[tokio::test]
    async fn tls_handshake_completes_after_replaying_a_consumed_prefix() {
        let (cert, key) = generate_self_signed_cert("aruaru-vpn-test.internal")
            .expect("self-signed cert generation must succeed");
        let acceptor =
            build_server_acceptor(cert.clone(), key).expect("server acceptor must build");
        let connector =
            build_client_connector(cert).expect("client connector must trust our test cert");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();

            // `accept_and_route`と同じように、最初の数バイトだけを先に
            // 読み取ってしまう状況を模擬する(REALITY判定のための覗き見)。
            let mut peeked = [0u8; 5];
            let mut socket = socket;
            let peeked_n = socket.peek(&mut peeked).await.unwrap();
            let mut consumed = vec![0u8; peeked_n];
            socket.read_exact(&mut consumed).await.unwrap();

            let mut tls_stream = terminate_tls_with_prefix(&acceptor, consumed, socket)
                .await
                .expect("TLS handshake must complete even after a consumed prefix");

            let mut buf = [0u8; 64];
            let n = tls_stream.read(&mut buf).await.unwrap();
            tls_stream.write_all(&buf[..n]).await.unwrap();
        });

        let server_name = rustls::pki_types::ServerName::try_from("aruaru-vpn-test.internal")
            .unwrap()
            .to_owned();
        let client_socket = TcpStream::connect(addr).await.unwrap();
        let mut client_tls = connector
            .connect(server_name, client_socket)
            .await
            .expect("client-side TLS handshake must complete");

        client_tls.write_all(b"hello over real tls").await.unwrap();
        let mut echoed = vec![0u8; b"hello over real tls".len()];
        client_tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello over real tls");

        server_task.await.unwrap();
    }
}
