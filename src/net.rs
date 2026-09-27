//! 実ネットワークI/O(TCP/UDPソケット)への統合(実装フェーズ5)。
//!
//! これまでのモジュール(`reality`/`reality_auth`/`tls_clienthello`/
//! `wireguard_handshake`/`amnezia`)はいずれもメモリ上のバイト列だけで
//! テストしていた。ここでは実際のTCP/UDPソケットを使い、
//! - REALITYの「認証成功→中継/認証失敗→偽装先サイトへフォールバック転送」
//!   を実際のTCP接続で動かす
//! - WireGuard相当のNoiseハンドシェイクを実際のUDPソケット越しに行う
//! ことを確認する。

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::reality::{decide_from_client_hello_record_x25519, ConnectionAction};
use crate::reality_auth::ServerIdentity;

/// TCP接続を1本受け付け、その最初のTLS ClientHelloレコードを読み取って
/// REALITY判定を行い、
/// - 認証成功(`Relay`) → 呼び出し側にそのまま`TcpStream`を返す(以降の
///   VLESSセッション処理は次フェーズ)
/// - 認証失敗(`Fallback`) → `dial_camouflage`で偽装先へ実際に接続し、
///   クライアント⇔偽装先サイト間のバイトをそのまま双方向で中継する
///   (関数はこの場合`None`を返す。中継が終わるまでこの関数はブロックする)
///
/// `dial_camouflage`は「偽装先ホスト名を受け取り、そこへのTCP接続を返す」
/// 関数。実運用では実際のインターネット上のサイトへ接続するが、テストでは
/// ローカルのモックサーバーを使えるよう抽象化してある。
pub async fn accept_and_route<F, Fut>(
    listener: &TcpListener,
    identity: Arc<ServerIdentity>,
    dial_camouflage: F,
) -> std::io::Result<Option<TcpStream>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    let (mut client_stream, _peer_addr) = listener.accept().await?;

    // TLSレコードは可変長。ここでは「最初の読み取りで1つの完全な
    // ClientHelloレコードが届く」という簡略化した前提を置く(TCPの
    // 断片化・複数レコードへの分割は次フェーズで扱う)。
    let mut buf = vec![0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    let record = &buf[..n];

    let action = decide_from_client_hello_record_x25519(&identity, record, "www.microsoft.com")
        .unwrap_or(ConnectionAction::Fallback {
            camouflage_target: "www.microsoft.com".to_owned(),
        });

    match action {
        ConnectionAction::Relay => Ok(Some(client_stream)),
        ConnectionAction::Fallback { camouflage_target } => {
            let mut camouflage_stream = dial_camouflage(camouflage_target).await?;

            // クライアントが最初に送ってきたバイト(ClientHello自体)を
            // まず偽装先へそのまま転送してから、以降は双方向に中継する
            // (偽装先から見て「普通のTLSクライアントが接続してきた」という
            // 状態を再現するため)。
            camouflage_stream.write_all(record).await?;
            tokio::io::copy_bidirectional(&mut client_stream, &mut camouflage_stream).await?;
            Ok(None)
        }
    }
}

/// 実際のUDPソケット越しにWireGuard相当のNoiseハンドシェイクを行う。
/// [`crate::wireguard_handshake::perform_handshake`]のメモリ上バージョンを
/// 実ソケット越しに置き換えたもの。
pub async fn perform_handshake_over_udp(
    mut initiator: snow::HandshakeState,
    initiator_socket: &UdpSocket,
    mut responder: snow::HandshakeState,
    responder_socket: &UdpSocket,
    responder_addr: std::net::SocketAddr,
) -> Result<(snow::TransportState, snow::TransportState), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 1024];

    // メッセージ1: initiator → (UDP) → responder
    let len = initiator.write_message(&[], &mut buf)?;
    initiator_socket.send_to(&buf[..len], responder_addr).await?;

    let mut recv_buf = [0u8; 1024];
    let (n, from) = responder_socket.recv_from(&mut recv_buf).await?;
    responder.read_message(&recv_buf[..n], &mut [0u8; 1024])?;

    // メッセージ2: responder → (UDP) → initiator
    let len = responder.write_message(&[], &mut buf)?;
    responder_socket.send_to(&buf[..len], from).await?;

    let (n, _from) = initiator_socket.recv_from(&mut recv_buf).await?;
    initiator.read_message(&recv_buf[..n], &mut [0u8; 1024])?;

    let initiator_transport = initiator.into_transport_mode()?;
    let responder_transport = responder.into_transport_mode()?;
    Ok((initiator_transport, responder_transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_auth::ClientEphemeralKeypair;
    use crate::tls_clienthello::tests_support::build_client_hello_with_key_share_for_tests;
    use crate::wireguard_handshake::{build_initiator, build_responder, Peer};
    use tokio::net::TcpListener;

    /// 認証失敗(未登録のREALITYクライアント)の接続が、実際のTCP接続として
    /// 偽装先サイト(モックのechoサーバー)へ転送され、応答がクライアントに
    /// 戻ってくることを確認する。
    #[tokio::test]
    async fn unauthenticated_connection_is_relayed_to_camouflage_target_over_real_tcp() {
        // 偽装先サイト役: 受け取ったバイトをそのまま返すechoサーバー。
        let camouflage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camouflage_addr = camouflage_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = camouflage_listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
                // クライアント側が明示的に接続をクローズする(EOFを送る)まで
                // 待ってから自分の側を閉じる。ここで即座にドロップすると、
                // OSによってはRST(強制切断)を送ってしまい、まだ中継中の
                // `copy_bidirectional`側にエラーを起こすことがあるため。
                let mut discard = [0u8; 1];
                let _ = stream.read(&mut discard).await;
                let _ = stream.shutdown().await;
            }
        });

        // REALITYリスナー役。
        let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reality_addr = reality_listener.local_addr().unwrap();
        let identity = Arc::new(ServerIdentity::generate([9u8; 32]));

        let server_task = tokio::spawn(async move {
            accept_and_route(&reality_listener, identity, move |_camouflage_target| async move {
                TcpStream::connect(camouflage_addr).await
            })
            .await
        });

        // クライアント役: 認証タグなし(session_idが空)の、未認証な
        // ClientHelloを送る。
        let mut client = TcpStream::connect(reality_addr).await.unwrap();
        let record =
            build_client_hello_with_key_share_for_tests(b"", "www.microsoft.com", &[0u8; 32]);
        client.write_all(&record).await.unwrap();

        let mut echoed = vec![0u8; record.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, record, "fallback path must echo back via the camouflage target");

        // クライアント側から明示的に接続を終える(EOFを送る)。これが
        // 中継先(モックの偽装サイト)まで伝わり、双方が正常にクローズできる。
        client.shutdown().await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(result.is_none(), "fallback path must not return a Relay stream");
    }

    /// 認証成功(登録済みREALITYクライアント)の接続は、偽装先へは転送されず
    /// `accept_and_route`が`Some(stream)`を返すことを確認する。
    #[tokio::test]
    async fn authenticated_connection_is_returned_for_relay_handling() {
        let identity = Arc::new(ServerIdentity::generate([9u8; 32]));
        let client_keys = ClientEphemeralKeypair::generate([5u8; 32]);
        let tag = client_keys.derive_auth_tag(&identity.public_key());

        let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reality_addr = reality_listener.local_addr().unwrap();
        let identity_for_server = Arc::clone(&identity);

        let server_task = tokio::spawn(async move {
            accept_and_route(&reality_listener, identity_for_server, |_| async {
                panic!("camouflage dialer must not be called for an authenticated client")
            })
            .await
        });

        let mut client = TcpStream::connect(reality_addr).await.unwrap();
        let record = build_client_hello_with_key_share_for_tests(
            &tag,
            "www.microsoft.com",
            &client_keys.public_key().to_bytes(),
        );
        client.write_all(&record).await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(result.is_some(), "authenticated client must be handed back for Relay handling");
    }

    /// WireGuard相当のNoiseハンドシェイクを、実際のUDPソケット越しに行い、
    /// 完了後に暗号化データを送受信できることを確認する。
    #[tokio::test]
    async fn wireguard_style_handshake_completes_over_real_udp_sockets() {
        let initiator_peer = Peer::generate().unwrap();
        let responder_peer = Peer::generate().unwrap();

        let initiator_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder_addr = responder_socket.local_addr().unwrap();

        let initiator = build_initiator(&initiator_peer, &responder_peer.public_key).unwrap();
        let responder = build_responder(&responder_peer).unwrap();

        let (mut initiator_transport, mut responder_transport) = perform_handshake_over_udp(
            initiator,
            &initiator_socket,
            responder,
            &responder_socket,
            responder_addr,
        )
        .await
        .expect("UDP-based handshake must complete");

        let plaintext = b"real udp socket transport check";
        let mut ciphertext = [0u8; 1024];
        let ct_len = initiator_transport
            .write_message(plaintext, &mut ciphertext)
            .unwrap();
        let mut decrypted = [0u8; 1024];
        let pt_len = responder_transport
            .read_message(&ciphertext[..ct_len], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..pt_len], plaintext);
    }
}
