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
use crate::vless::{self, Address, AllowedUuids, Command, VlessRequest};

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

/// `accept_and_route`が`Relay`と判定して返した`TcpStream`から、実際に
/// VLESSリクエストヘッダを読み取り、指定された宛先へ実際に接続して
/// 中継する(実装フェーズ7: VLESSプロトコル本体の統合)。
///
/// **重要な簡略化**: 本来のREALITYは、この時点でTLSハンドシェイクが完了し
/// 暗号化された通信路の中をVLESSリクエストが流れる。この最小プロトタイプは
/// TLS終端(実際の暗号化/復号)をまだ実装していないため、`client_stream`に
/// 平文で届くバイト列をそのままVLESSリクエストとして解釈する
/// (`open-LiveKit`の実装と同様、「核心のロジックが動く」ことを先に確認し、
/// 実TLS終端は次フェーズで統合する)。
///
/// `dial_destination`は「宛先(IP/ドメイン+ポート)を受け取り、そこへの
/// TCP接続を返す」関数(`Command::Tcp`の場合のみ使う)。実運用では実際の
/// インターネット上の宛先へ接続するが、テストではローカルのモック
/// サーバーを使えるよう抽象化してある。
///
/// `allowed_uuids`は、VLESSリクエストが持つUUID(利用者ごとの識別子)の
/// 許可リスト。REALITY/TLSの認証(輸送路レベル)とは別に、VLESS自身が
/// 「どの利用者か」を検証する二段構えの認証(実際のXray-coreと同じ設計)。
/// 許可されていないUUIDのリクエストは、宛先への接続を試みることなく
/// エラーとして拒否する。
pub async fn handle_relay_session<F, Fut>(
    mut client_stream: TcpStream,
    allowed_uuids: &AllowedUuids,
    dial_destination: F,
) -> std::io::Result<()>
where
    F: FnOnce(Address, u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    let mut buf = vec![0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    let data = &buf[..n];

    let request = vless::parse_request(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))?;

    if !vless::validate_uuid(&request, allowed_uuids) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VLESS request presented an unregistered UUID",
        ));
    }

    let VlessRequest {
        version,
        command,
        address,
        port,
        header_len,
        ..
    } = request;

    let leftover_payload = if header_len < data.len() {
        data[header_len..].to_vec()
    } else {
        Vec::new()
    };

    client_stream
        .write_all(&vless::build_response_header(version))
        .await?;

    match command {
        Command::Tcp => {
            let mut destination_stream = dial_destination(address, port).await?;
            if !leftover_payload.is_empty() {
                destination_stream.write_all(&leftover_payload).await?;
            }
            tokio::io::copy_bidirectional(&mut client_stream, &mut destination_stream).await?;
            Ok(())
        }
        Command::Udp => relay_udp(client_stream, address, port, leftover_payload).await,
        Command::Mux => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "MUX command is not implemented yet",
        )),
    }
}

/// VLESS `Command::Udp`の最小実装: 実際のUDPソケットで宛先とやり取りする。
///
/// **簡略化**: 本来のVLESS UDPは各データグラムに2バイトの長さプレフィックス
/// を付けてTCP上で運ぶ(1本のTCP接続の中に複数のUDPパケットを表現する)
/// フレーミング方式を使うが、ここでは「クライアントからの最初のペイロードを
/// 1個のUDPデータグラムとして送り、宛先からの応答をクライアントへそのまま
/// 返す」という往復1回分の最小疎通確認に留める(複数データグラムの
/// フレーミングは次フェーズ)。
async fn relay_udp(
    mut client_stream: TcpStream,
    address: Address,
    port: u16,
    initial_payload: Vec<u8>,
) -> std::io::Result<()> {
    let destination = match address {
        Address::Ipv4(ip) => (std::net::IpAddr::V4(ip), port).into(),
        Address::Ipv6(ip) => (std::net::IpAddr::V6(ip), port).into(),
        Address::Domain(domain) => {
            let mut addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            addrs.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "domain resolved to no address")
            })?
        }
    };

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    udp_socket.connect(destination).await?;

    if !initial_payload.is_empty() {
        udp_socket.send(&initial_payload).await?;
    }

    let mut response_buf = [0u8; 65536];
    let n = udp_socket.recv(&mut response_buf).await?;
    client_stream.write_all(&response_buf[..n]).await?;
    Ok(())
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

    /// REALITY認証を通過した接続が、実際にVLESSリクエストヘッダで指定した
    /// 宛先(モックのTCPサーバー)へ中継され、往復でデータが届くことを
    /// end-to-endで確認する。
    #[tokio::test]
    async fn relay_session_forwards_to_the_requested_vless_destination() {
        // VLESSリクエストが指す「宛先」役のモックサーバー(echo)。
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_addr = destination_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = destination_listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
                let mut discard = [0u8; 1];
                let _ = stream.read(&mut discard).await;
                let _ = stream.shutdown().await;
            }
        });

        // REALITY認証を通過した後の「クライアント⇔サーバー」区間を模擬する
        // 2つのTCP接続(client_side/server_sideは同じソケットペアの両端)。
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        let destination_port = destination_addr.port();
        let allowed_uuid = [7u8; 16];
        let server_task = tokio::spawn(async move {
            let (server_side_stream, _) = relay_listener.accept().await.unwrap();
            let allowed = AllowedUuids::new([allowed_uuid]);
            handle_relay_session(server_side_stream, &allowed, |address, port| async move {
                assert_eq!(port, destination_port);
                match address {
                    Address::Domain(d) if d == "127.0.0.1" => {
                        TcpStream::connect(("127.0.0.1", port)).await
                    }
                    other => panic!("unexpected destination address in test: {other:?}"),
                }
            })
            .await
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();

        let mut vless_request = Vec::new();
        vless_request.push(0u8); // version
        vless_request.extend_from_slice(&allowed_uuid); // 許可リストに登録済みのUUID
        vless_request.push(0u8); // addons_len = 0
        vless_request.push(1u8); // command = TCP
        vless_request.extend_from_slice(&destination_port.to_be_bytes());
        let domain = b"127.0.0.1";
        vless_request.push(2u8); // address_type = domain
        vless_request.push(domain.len() as u8);
        vless_request.extend_from_slice(domain);
        vless_request.extend_from_slice(b"payload-through-vless");

        client.write_all(&vless_request).await.unwrap();

        // サーバー応答ヘッダ([version][addons_len=0])を確認。
        let mut response_header = [0u8; 2];
        client.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0u8, 0u8]);

        // ペイロードが宛先(モックecho)まで届いて折り返されてくることを確認。
        let mut echoed = vec![0u8; b"payload-through-vless".len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"payload-through-vless");

        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// 許可リストに無いUUIDを提示したVLESSリクエストは、宛先への接続を
    /// 試みることなく拒否されることを確認する。
    #[tokio::test]
    async fn relay_session_rejects_unregistered_uuid_without_dialing_destination() {
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (server_side_stream, _) = relay_listener.accept().await.unwrap();
            let allowed = AllowedUuids::new([[1u8; 16]]); // クライアントは[2u8;16]を使う
            handle_relay_session(server_side_stream, &allowed, |_address, _port| async {
                panic!("destination dialer must not be called for an unregistered UUID")
            })
            .await
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let mut vless_request = Vec::new();
        vless_request.push(0u8);
        vless_request.extend_from_slice(&[2u8; 16]); // 許可リストに無いUUID
        vless_request.push(0u8);
        vless_request.push(1u8); // command = TCP
        vless_request.extend_from_slice(&443u16.to_be_bytes());
        vless_request.push(1u8); // address_type = IPv4
        vless_request.extend_from_slice(&[1, 1, 1, 1]);
        client.write_all(&vless_request).await.unwrap();

        let result = server_task.await.unwrap();
        assert!(result.is_err(), "unregistered UUID must be rejected");
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    /// VLESS `Command::Udp`が、実際のUDPソケットで宛先(モックのUDP echo
    /// サーバー)まで往復できることを確認する。
    #[tokio::test]
    async fn relay_session_forwards_udp_command_to_real_destination() {
        // 宛先役: 受け取ったUDPデータグラムをそのまま送り返すechoサーバー。
        let udp_destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination_addr = udp_destination.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((n, from)) = udp_destination.recv_from(&mut buf).await {
                let _ = udp_destination.send_to(&buf[..n], from).await;
            }
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let allowed_uuid = [3u8; 16];
        let destination_port = udp_destination_addr.port();

        let server_task = tokio::spawn(async move {
            let (server_side_stream, _) = relay_listener.accept().await.unwrap();
            let allowed = AllowedUuids::new([allowed_uuid]);
            handle_relay_session(server_side_stream, &allowed, |_address, _port| async {
                panic!("TCP dialer must not be called for a UDP command")
            })
            .await
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let mut vless_request = Vec::new();
        vless_request.push(0u8);
        vless_request.extend_from_slice(&allowed_uuid);
        vless_request.push(0u8);
        vless_request.push(2u8); // command = UDP
        vless_request.extend_from_slice(&destination_port.to_be_bytes());
        vless_request.push(1u8); // address_type = IPv4
        vless_request.extend_from_slice(&[127, 0, 0, 1]);
        vless_request.extend_from_slice(b"udp-payload");
        client.write_all(&vless_request).await.unwrap();

        let mut response_header = [0u8; 2];
        client.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0u8, 0u8]);

        let mut echoed = vec![0u8; b"udp-payload".len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"udp-payload");

        server_task.await.unwrap().unwrap();
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
