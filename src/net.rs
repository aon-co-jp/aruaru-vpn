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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::cert_clone;
use crate::reality_auth::{ChannelKeys, ServerIdentity};
use crate::secure_channel;
use crate::tls_terminate::PrefixedStream;
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
/// TCPストリームからTLSレコードを**ちょうど1つ分だけ**読み取る。
///
/// レコードヘッダ(5バイト: `content_type`+`legacy_version`+`length`)を
/// まず読み、そこに書かれた長さぶんだけ本体を読む。「まとめて4096バイト
/// 読む」実装だと、クライアントがこのレコードの直後に別プロトコル層の
/// データを続けて送ってきた場合、その分まで読み込んで捨ててしまう
/// (実際にこのバグを踏んで`secure_channel`側がデッドロックした、
/// `accept_and_route`のコメント参照)。
async fn read_exactly_one_tls_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    let mut record = Vec::with_capacity(5 + body_len);
    record.extend_from_slice(&header);
    record.resize(5 + body_len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// [`accept_and_route`]が`Relay`と判定した場合に返す、以降のVLESS
/// セッション処理に必要な材料一式。
pub struct AuthenticatedConnection {
    pub stream: TcpStream,
    /// このクライアントとのX25519 ECDHから導出した`ChannelKeys`
    /// ([`crate::secure_channel`]で暗号化通信路を組み立てるのに使う)。
    pub channel_keys: ChannelKeys,
}

pub async fn accept_and_route<F, Fut>(
    listener: &TcpListener,
    identity: Arc<ServerIdentity>,
    dial_camouflage: F,
) -> std::io::Result<Option<AuthenticatedConnection>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    let (mut client_stream, _peer_addr) = listener.accept().await?;

    // **重要なバグ修正(実装フェーズ10で発覚)**: 以前はここで
    // 「最大4096バイトを1回読み取る」実装になっていたが、クライアントが
    // ClientHelloの直後に続けてsecure_channelのフレームを送ってくると、
    // TCPがそれらを1回の読み取りにまとめてしまい、ClientHelloを超えた分
    // (次のプロトコル層のバイト列)を読み捨ててしまう欠陥があった
    // (`secure_channel`側が「新しいバイトが来るのを待ち続ける」デッド
    // ロックとして顕在化した)。TLSレコードヘッダの5バイト
    // (`type`+`version`+`length`)から実際の長さを読み取り、**ちょうど
    // 1レコード分だけ**を読む。
    let record = read_exactly_one_tls_record(&mut client_stream).await?;

    // `decide_from_client_hello_record_x25519`と同じ判定を行うが、
    // Relay確定時に`ChannelKeys`も導出できるよう、ここではClientHelloを
    // 自前でパースしてクライアントのX25519公開鍵を保持しておく。
    let parsed = crate::tls_clienthello::parse_client_hello(&record).ok();
    let client_public_key = parsed
        .as_ref()
        .and_then(|p| p.x25519_key_share)
        .map(x25519_dalek::PublicKey::from);
    let session_id = parsed
        .as_ref()
        .map(|p| p.session_id.clone())
        .unwrap_or_default();
    let sni = parsed.as_ref().and_then(|p| p.server_name.clone());

    let authenticated = client_public_key
        .as_ref()
        .map(|pk| crate::reality_auth::verify_auth_tag(&identity, pk, &session_id))
        .unwrap_or(false);

    if authenticated {
        // unwrapは安全: `authenticated`がtrueになるのは`client_public_key`が
        // `Some`のときだけ(上の`map`参照)。
        let channel_keys = identity.derive_channel_keys(client_public_key.as_ref().unwrap());
        Ok(Some(AuthenticatedConnection {
            stream: client_stream,
            channel_keys,
        }))
    } else {
        let camouflage_target = sni.unwrap_or_else(|| "www.microsoft.com".to_owned());
        let mut camouflage_stream = dial_camouflage(camouflage_target).await?;

        // クライアントが最初に送ってきたバイト(ClientHello自体)を
        // まず偽装先へそのまま転送してから、以降は双方向に中継する
        // (偽装先から見て「普通のTLSクライアントが接続してきた」という
        // 状態を再現するため)。
        camouflage_stream.write_all(&record).await?;
        tokio::io::copy_bidirectional(&mut client_stream, &mut camouflage_stream).await?;
        Ok(None)
    }
}

/// [`accept_and_route`]の証明書クローン版(実装フェーズ15・16):
/// `secure_channel`の独自フレーミングの代わりに、`cert_clone`で組み立てた
/// 「本物の証明書チェーンを借用したTLS 1.3」で通信路を確立する。
/// ワイヤー上のバイト列が本物のTLS 1.3と区別できなくなる分、
/// `secure_channel`版より検閲耐性が高い(`PORTING.md`「25.」参照)。
///
/// **認証方式が`accept_and_route`(session_idの認証タグ)と異なる点に注意**:
/// ここでは`key_share`拡張のX25519公開鍵そのものを、事前登録済みリスト
/// (`allowed_client_keys`)と照合する方式を使う。session_idへ認証タグを
/// 埋め込む方式は、標準準拠の`rustls`クライアントとは組み合わせられない
/// ことが判明したため([`crate::reality_auth::AllowedClientKeys`]の
/// ドキュメント参照、`PORTING.md`「26.」)。
///
/// `camouflage_port`は偽装先サイトへ証明書取得のために実際に接続する
/// ポート(実運用では443、テストではモックTLSサーバーの任意ポート)。
pub async fn accept_and_route_cert_cloned(
    listener: &TcpListener,
    identity: Arc<ServerIdentity>,
    allowed_client_keys: &crate::reality_auth::AllowedClientKeys,
    camouflage_port: u16,
) -> std::io::Result<Option<tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>>> {
    let (mut client_stream, _peer_addr) = listener.accept().await?;
    let record = read_exactly_one_tls_record(&mut client_stream).await?;

    let parsed = crate::tls_clienthello::parse_client_hello(&record).ok();
    let client_public_key = parsed
        .as_ref()
        .and_then(|p| p.x25519_key_share)
        .map(x25519_dalek::PublicKey::from);
    let sni = parsed.as_ref().and_then(|p| p.server_name.clone());

    let authenticated = client_public_key
        .as_ref()
        .map(|pk| allowed_client_keys.is_allowed(pk))
        .unwrap_or(false);

    if !authenticated {
        let camouflage_target = sni.unwrap_or_else(|| "www.microsoft.com".to_owned());
        let mut camouflage_stream =
            TcpStream::connect((camouflage_target.as_str(), camouflage_port)).await?;
        camouflage_stream.write_all(&record).await?;
        tokio::io::copy_bidirectional(&mut client_stream, &mut camouflage_stream).await?;
        return Ok(None);
    }

    // unwrapは安全: `authenticated`がtrueになるのは`client_public_key`が
    // `Some`のときだけ(上の`map`参照)。
    let client_pub = client_public_key.as_ref().unwrap();
    let auth_key = identity.derive_cert_clone_auth_key(client_pub);
    let camouflage_target = sni.unwrap_or_else(|| "www.microsoft.com".to_owned());

    let real_cert_chain =
        cert_clone::fetch_real_certificate_chain(&camouflage_target, camouflage_port).await?;
    let acceptor = cert_clone::build_cloned_server_acceptor(real_cert_chain, auth_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // クライアントが最初に送ってきたClientHelloは、REALITY判定のために
    // 既に読み取り済み(=消費済み)。rustlsが標準のTLS 1.3ハンドシェイクを
    // 自分で処理できるよう、`PrefixedStream`でそのバイト列を「巻き戻す」
    // (`tls_terminate.rs`のドキュメント参照、実装フェーズ9と同じ手法)。
    let prefixed = PrefixedStream::new(record, client_stream);
    let tls_stream = acceptor.accept(prefixed).await?;
    Ok(Some(tls_stream))
}

/// [`accept_and_route_cert_cloned`]が返すTLS 1.3ストリームから、実際に
/// VLESSリクエストを読み取り、指定された宛先へ中継する(`handle_relay_session`
/// の薄いラッパー、実装フェーズ16)。
pub async fn handle_relay_session_cert_cloned<F, Fut>(
    tls_stream: tokio_rustls::server::TlsStream<PrefixedStream<TcpStream>>,
    allowed_uuids: &AllowedUuids,
    dial_destination: F,
) -> std::io::Result<()>
where
    F: FnOnce(Address, u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    handle_relay_session(tls_stream, allowed_uuids, dial_destination).await
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
///
/// `client_stream`は`AsyncRead`/`AsyncWrite`を実装する任意のストリーム型
/// (実TCP接続そのものだけでなく、実装フェーズ15の`cert_clone`が返す
/// TLS 1.3ストリームもここへそのまま渡せる、`handle_relay_session_cert_cloned`
/// 参照)。
pub async fn handle_relay_session<S, F, Fut>(
    mut client_stream: S,
    allowed_uuids: &AllowedUuids,
    dial_destination: F,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
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

/// [`handle_relay_session`]の暗号化版(実装フェーズ10・11): REALITY認証で
/// 確立済みの`ChannelKeys`を使い、[`secure_channel`]で実際に暗号化された
/// 通信路の中でVLESSセッションを処理する。
///
/// `client_stream`は生のTCP接続そのもの(TLSではなく、`secure_channel`の
/// 独自AEADフレーミングで暗号化する、`tls_terminate.rs`のドキュメント
/// 参照)。クライアントは最初の1メッセージとして「VLESSリクエストヘッダ+
/// (あれば)先頭ペイロード」をまとめて送ってくる前提。
///
/// **現時点のスコープ**: `Command::Tcp`/`Command::Udp`に対応
/// (`Mux`は引き続き未対応、`PORTING.md`「20.」参照)。
pub async fn handle_relay_session_secure<F, Fut>(
    client_stream: TcpStream,
    channel_keys: &ChannelKeys,
    allowed_uuids: &AllowedUuids,
    dial_destination: F,
) -> std::io::Result<()>
where
    F: FnOnce(Address, u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    let (mut writer, mut reader) = secure_channel::responder_channel(client_stream, channel_keys);

    let first_message = reader.recv().await?;
    let request = vless::parse_request(&first_message)
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

    let leftover_payload = first_message[header_len..].to_vec();

    match command {
        Command::Tcp => {
            let mut destination_stream = dial_destination(address, port).await?;
            if !leftover_payload.is_empty() {
                destination_stream.write_all(&leftover_payload).await?;
            }
            writer.send(&vless::build_response_header(version)).await?;

            // secure_channelは「暗号化フレーム単位」、destination_streamは
            // 「生のバイトストリーム」なので、`copy_bidirectional`は使えない。
            // 双方向を手動でポンピングする最小限のループ。
            let mut dest_buf = vec![0u8; 8192];
            loop {
                tokio::select! {
                    from_client = reader.recv() => {
                        match from_client {
                            Ok(plaintext) => destination_stream.write_all(&plaintext).await?,
                            Err(_) => break, // クライアント側の終了(EOF/エラー)とみなす
                        }
                    }
                    from_dest = destination_stream.read(&mut dest_buf) => {
                        let n = from_dest?;
                        if n == 0 {
                            break; // 宛先側がクローズ
                        }
                        writer.send(&dest_buf[..n]).await?;
                    }
                }
            }
            Ok(())
        }
        Command::Udp => {
            relay_udp_secure(
                &mut writer,
                &mut reader,
                address,
                port,
                leftover_payload,
                version,
            )
            .await
        }
        Command::Mux => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "MUX command is not implemented yet",
        )),
    }
}

/// [`relay_udp`]の暗号化版(実装フェーズ11): クライアント⇔サーバー間は
/// [`secure_channel`]の暗号化フレーム単位でやり取りしつつ、サーバー⇔
/// 実際の宛先の間は生のUDPデータグラムで中継する。
///
/// **フレーミング**: 平文版(`relay_udp`)と同じく、クライアントからの
/// 最初のペイロードを1個のUDPデータグラムとして送り、宛先からの応答を
/// 折り返すという往復1回分の最小疎通確認に留める(複数データグラムの
/// 継続的なやり取りは次フェーズ)。`secure_channel`のメッセージ境界が
/// そのままUDPデータグラム境界に対応するため、追加の長さプレフィックスは
/// 不要(TCP版のVLESS UDPが必要とする2バイト長プレフィックスは、暗号化
/// フレーム自体が既にメッセージ境界を保持しているため省略している)。
async fn relay_udp_secure<W, R>(
    writer: &mut secure_channel::SecureWriter<W>,
    reader: &mut secure_channel::SecureReader<R>,
    address: Address,
    port: u16,
    initial_payload: Vec<u8>,
    response_version: u8,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    let destination = match address {
        Address::Ipv4(ip) => (std::net::IpAddr::V4(ip), port).into(),
        Address::Ipv6(ip) => (std::net::IpAddr::V6(ip), port).into(),
        Address::Domain(domain) => {
            let mut addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            addrs.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "domain resolved to no address",
                )
            })?
        }
    };

    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    udp_socket.connect(destination).await?;

    writer
        .send(&vless::build_response_header(response_version))
        .await?;

    if !initial_payload.is_empty() {
        udp_socket.send(&initial_payload).await?;
    }

    // クライアント→宛先、宛先→クライアントの両方向を、それぞれが
    // クローズ/エラーになるまでポンピングし続ける(平文版は往復1回で
    // 打ち切っていたが、`secure_channel`のメッセージ単位フレーミングは
    // 継続的なデータグラムのやり取りにそのまま拡張できるため、ここでは
    // 複数データグラムに対応する)。
    let mut dest_buf = [0u8; 65536];
    loop {
        tokio::select! {
            from_client = reader.recv() => {
                match from_client {
                    Ok(datagram) => { udp_socket.send(&datagram).await?; }
                    Err(_) => break,
                }
            }
            from_dest = udp_socket.recv(&mut dest_buf) => {
                let n = from_dest?;
                if writer.send(&dest_buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// VLESS `Command::Udp`の最小実装: 実際のUDPソケットで宛先とやり取りする。
///
/// **簡略化**: 本来のVLESS UDPは各データグラムに2バイトの長さプレフィックス
/// を付けてTCP上で運ぶ(1本のTCP接続の中に複数のUDPパケットを表現する)
/// フレーミング方式を使うが、ここでは「クライアントからの最初のペイロードを
/// 1個のUDPデータグラムとして送り、宛先からの応答をクライアントへそのまま
/// 返す」という往復1回分の最小疎通確認に留める(複数データグラムの
/// フレーミングは次フェーズ)。
async fn relay_udp<S: AsyncWrite + Unpin>(
    mut client_stream: S,
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
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "domain resolved to no address",
                )
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
    initiator_socket
        .send_to(&buf[..len], responder_addr)
        .await?;

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
    use crate::wireguard_handshake::{Peer, build_initiator, build_responder};
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

        let server_task =
            tokio::spawn(async move {
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
        assert_eq!(
            echoed, record,
            "fallback path must echo back via the camouflage target"
        );

        // クライアント側から明示的に接続を終える(EOFを送る)。これが
        // 中継先(モックの偽装サイト)まで伝わり、双方が正常にクローズできる。
        client.shutdown().await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(
            result.is_none(),
            "fallback path must not return a Relay stream"
        );
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
        assert!(
            result.is_some(),
            "authenticated client must be handed back for Relay handling"
        );
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

    /// VLESS `Command::Udp`が、`secure_channel`で暗号化された通信路越しでも
    /// 実際のUDPソケットで宛先(モックのUDP echoサーバー)まで複数回往復
    /// できることを確認する(実装フェーズ11)。
    #[tokio::test]
    async fn relay_session_secure_forwards_udp_command_to_real_destination() {
        use crate::reality_auth::ClientEphemeralKeypair;

        // 宛先役: 受け取ったUDPデータグラムをそのまま送り返すechoサーバー
        // (複数回の往復に対応)。
        let udp_destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_destination_addr = udp_destination.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match udp_destination.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let _ = udp_destination.send_to(&buf[..n], from).await;
                    }
                    Err(_) => break,
                }
            }
        });

        let identity = Arc::new(ServerIdentity::generate([60u8; 32]));
        let client_ephemeral = ClientEphemeralKeypair::generate([61u8; 32]);
        let auth_tag = client_ephemeral.derive_auth_tag(&identity.public_key());
        let allowed_uuid = [9u8; 16];

        let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reality_addr = reality_listener.local_addr().unwrap();
        let identity_for_server = Arc::clone(&identity);
        let destination_port = udp_destination_addr.port();

        let server_task = tokio::spawn(async move {
            let authenticated =
                accept_and_route(&reality_listener, identity_for_server, |_| async {
                    panic!("this test's client must always authenticate; camouflage path unused")
                })
                .await
                .unwrap()
                .expect("client must authenticate via REALITY");

            let allowed = AllowedUuids::new([allowed_uuid]);
            handle_relay_session_secure(
                authenticated.stream,
                &authenticated.channel_keys,
                &allowed,
                |_address, _port| async {
                    panic!("TCP dialer must not be called for a UDP command")
                },
            )
            .await
        });

        let mut client_tcp = TcpStream::connect(reality_addr).await.unwrap();
        let client_hello = build_client_hello_with_key_share_for_tests(
            &auth_tag,
            "www.microsoft.com",
            &client_ephemeral.public_key().to_bytes(),
        );
        client_tcp.write_all(&client_hello).await.unwrap();

        let client_channel_keys = client_ephemeral.derive_channel_keys(&identity.public_key());
        let (mut writer, mut reader) =
            secure_channel::initiator_channel(client_tcp, &client_channel_keys);

        let mut vless_request = Vec::new();
        vless_request.push(0u8);
        vless_request.extend_from_slice(&allowed_uuid);
        vless_request.push(0u8); // addons_len = 0
        vless_request.push(2u8); // command = UDP
        vless_request.extend_from_slice(&destination_port.to_be_bytes());
        vless_request.push(1u8); // address_type = IPv4
        vless_request.extend_from_slice(&[127, 0, 0, 1]);
        vless_request.extend_from_slice(b"udp-datagram-one");

        writer.send(&vless_request).await.unwrap();

        let response_header = reader.recv().await.unwrap();
        assert_eq!(response_header, vec![0u8, 0u8]);

        let echoed_one = reader.recv().await.unwrap();
        assert_eq!(echoed_one, b"udp-datagram-one");

        // 2個目のデータグラムも、同じ暗号化フレームのやり取りで往復できる
        // (複数データグラム対応、平文版〈TCP埋め込みの1往復限定〉との差分)。
        writer.send(b"udp-datagram-two").await.unwrap();
        let echoed_two = reader.recv().await.unwrap();
        assert_eq!(echoed_two, b"udp-datagram-two");

        writer.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// フルパイプラインのend-to-endテスト(実装フェーズ10): 実際のTCP接続で
    /// REALITY認証(X25519) → `secure_channel`による暗号化通信路の確立 →
    /// VLESSリクエストの解析 → 実際の宛先への中継、までを一気通貫で確認する。
    #[tokio::test]
    async fn full_pipeline_reality_auth_to_encrypted_vless_relay() {
        use crate::reality_auth::ClientEphemeralKeypair;

        // VLESSリクエストが指す宛先役のモックサーバー(echo)。
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

        let identity = Arc::new(ServerIdentity::generate([50u8; 32]));
        let client_ephemeral = ClientEphemeralKeypair::generate([51u8; 32]);
        let auth_tag = client_ephemeral.derive_auth_tag(&identity.public_key());
        let allowed_uuid = [8u8; 16];

        let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reality_addr = reality_listener.local_addr().unwrap();
        let identity_for_server = Arc::clone(&identity);
        let destination_port = destination_addr.port();

        let server_task = tokio::spawn(async move {
            let authenticated =
                accept_and_route(&reality_listener, identity_for_server, |_| async {
                    panic!("this test's client must always authenticate; camouflage path unused")
                })
                .await
                .unwrap()
                .expect("client must authenticate via REALITY");

            let allowed = AllowedUuids::new([allowed_uuid]);
            handle_relay_session_secure(
                authenticated.stream,
                &authenticated.channel_keys,
                &allowed,
                move |_address, port| async move {
                    assert_eq!(port, destination_port);
                    TcpStream::connect(("127.0.0.1", port)).await
                },
            )
            .await
        });

        // クライアント側: 実際のREALITY ClientHello(X25519 key_share +
        // 認証タグ)を送り、その後は同じX25519共有シークレットから導出した
        // ChannelKeysでsecure_channelを組み立てて、VLESSリクエストを送る。
        let mut client_tcp = TcpStream::connect(reality_addr).await.unwrap();
        let client_hello = build_client_hello_with_key_share_for_tests(
            &auth_tag,
            "www.microsoft.com",
            &client_ephemeral.public_key().to_bytes(),
        );
        client_tcp.write_all(&client_hello).await.unwrap();

        let client_channel_keys = client_ephemeral.derive_channel_keys(&identity.public_key());
        let (mut writer, mut reader) =
            secure_channel::initiator_channel(client_tcp, &client_channel_keys);

        let mut vless_request = Vec::new();
        vless_request.push(0u8);
        vless_request.extend_from_slice(&allowed_uuid);
        vless_request.push(0u8); // addons_len = 0
        vless_request.push(1u8); // command = TCP
        vless_request.extend_from_slice(&destination_port.to_be_bytes());
        vless_request.push(1u8); // address_type = IPv4
        vless_request.extend_from_slice(&[127, 0, 0, 1]);
        vless_request.extend_from_slice(b"full-pipeline-payload");

        writer.send(&vless_request).await.unwrap();

        let response_header = reader.recv().await.unwrap();
        assert_eq!(response_header, vec![0u8, 0u8]);

        let echoed = reader.recv().await.unwrap();
        assert_eq!(echoed, b"full-pipeline-payload");

        // `drop(writer)`だけでは、`reader`がまだ生きているため
        // `tokio::io::split`で共有された下層ソケットはクローズされず、
        // サーバー側がEOFを検知できずハングする(実際に踏んだバグ)。
        // 明示的に書き込み方向をシャットダウンする。
        writer.shutdown().await.unwrap();
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

    /// 証明書クローン(実装フェーズ15・16)の`accept_and_route_cert_cloned`
    /// のうち、**未認証接続が偽装先へ透過転送されるフォールバック側**の
    /// 経路が実際のTCP接続で動くことを確認する。
    ///
    /// **設計変更の経緯(`PORTING.md`「26.」に詳細記録)**: 当初は
    /// `accept_and_route`(`secure_channel`版)と同じ「ClientHelloの
    /// `session_id`にECDH認証タグを埋め込む」方式を試したが、標準準拠の
    /// `rustls`クライアントと組み合わせると、TLS1.3のトランスクリプト
    /// ハッシュ(ClientHelloの生バイト列全体から計算される)が送信後の
    /// 書き換えで壊れ、`Finished`検証が`DecryptError`で失敗することが
    /// 判明した(本物のREALITYがGoの`crypto/tls`を丸ごとフォークしている
    /// のはこれが理由)。そこで`key_share`拡張のX25519公開鍵そのものを
    /// 事前登録リストと照合する方式(`AllowedClientKeys`)へ変更した。
    #[tokio::test]
    async fn accept_and_route_cert_cloned_relays_unauthenticated_connection_to_camouflage_target() {
        let camouflage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camouflage_port = camouflage_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = camouflage_listener.accept().await {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
                let mut discard = [0u8; 1];
                let _ = stream.read(&mut discard).await;
                let _ = stream.shutdown().await;
            }
        });

        let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reality_addr = reality_listener.local_addr().unwrap();
        let identity = Arc::new(ServerIdentity::generate([95u8; 32]));
        let allowed_keys = crate::reality_auth::AllowedClientKeys::default();

        let server_task = tokio::spawn(async move {
            accept_and_route_cert_cloned(
                &reality_listener,
                identity,
                &allowed_keys,
                camouflage_port,
            )
            .await
        });

        // クライアント役: 未登録の(=許可リストに無い)エフェメラル鍵で
        // 接続する未認証なClientHelloを送る(127.0.0.1宛の偽装先へ実際に
        // TCP接続できるよう、SNIには"127.0.0.1"を使う)。
        let mut client = TcpStream::connect(reality_addr).await.unwrap();
        let record = build_client_hello_with_key_share_for_tests(b"", "127.0.0.1", &[0u8; 32]);
        client.write_all(&record).await.unwrap();

        let mut echoed = vec![0u8; record.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            echoed, record,
            "fallback path must echo back via the camouflage target"
        );

        client.shutdown().await.unwrap();

        let result = server_task.await.unwrap().unwrap();
        assert!(
            result.is_none(),
            "fallback path must not return a cloned TLS stream"
        );
    }

    /// 証明書クローン(実装フェーズ15・16)のフルパイプラインend-to-end
    /// テスト: 実際のTCP接続で、REALITY認証(`key_share`の公開鍵を事前
    /// 登録リストと照合)→本物の証明書チェーンを偽装先から借用したTLS 1.3
    /// ハンドシェイクの完了(`cert_clone`)→VLESSリクエストの解析→実際の
    /// 宛先への中継、までを一気通貫で確認する。クライアントは
    /// `tokio_rustls`が生成する**本物のTLS 1.3 ClientHello**を使う
    /// (独自フレーミングではない、`key_share`の鍵だけを
    /// `FixedX25519ActiveKeyExchange`経由で固定する)。
    #[tokio::test]
    async fn full_pipeline_cert_cloned_reality_auth_to_real_tls13_vless_relay() {
        use rustls::pki_types::ServerName;

        // 偽装先サイト役(自己署名証明書のモックTLSサーバー、"localhost"
        // 向け)。REALITY認証が成功すると、サーバーはこのサイトへ実際に
        // 接続して本物の証明書チェーンを借用する。
        let (camouflage_cert, camouflage_key) =
            crate::tls_terminate::generate_self_signed_cert("localhost").unwrap();
        let camouflage_acceptor =
            crate::tls_terminate::build_server_acceptor(camouflage_cert, camouflage_key).unwrap();
        let camouflage_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camouflage_port = camouflage_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = camouflage_listener.accept().await else {
                    break;
                };
                if let Ok(mut tls) = camouflage_acceptor.accept(tcp).await {
                    let mut buf = [0u8; 16];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.shutdown().await;
                }
            }
        });

        // VLESSリクエストが指す「宛先」役のモックサーバー(echo、証明書
        // クローンのTLSとは無関係な、REALITY中継後のVLESS宛先)。
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

        let identity = Arc::new(ServerIdentity::generate([90u8; 32]));
        let ephemeral_seed = [91u8; 32];
        let client_ephemeral_public = {
            let secret = x25519_dalek::StaticSecret::from(ephemeral_seed);
            x25519_dalek::PublicKey::from(&secret)
        };
        let client_auth_key = identity.derive_cert_clone_auth_key(&client_ephemeral_public);
        let allowed_keys =
            crate::reality_auth::AllowedClientKeys::new([*client_ephemeral_public.as_bytes()]);
        let allowed_uuid = [15u8; 16];

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let destination_port = destination_addr.port();

        let server_task = tokio::spawn(async move {
            let tls_stream = accept_and_route_cert_cloned(
                &relay_listener,
                identity,
                &allowed_keys,
                camouflage_port,
            )
            .await
            .unwrap()
            .expect("registered client must authenticate and complete the cloned TLS handshake");

            let allowed = AllowedUuids::new([allowed_uuid]);
            handle_relay_session_cert_cloned(
                tls_stream,
                &allowed,
                move |_address, port| async move {
                    assert_eq!(port, destination_port);
                    TcpStream::connect(("127.0.0.1", port)).await
                },
            )
            .await
        });

        // クライアント側: 本物のrustls TLSクライアントを、事前登録した
        // エフェメラル鍵をTLS鍵交換自体にも使う形で組み立てる。
        let client_connector = cert_clone::build_cloned_client_connector_with_reality_ephemeral(
            client_auth_key,
            ephemeral_seed,
        );
        let tcp = TcpStream::connect(relay_addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client_tls = client_connector.connect(server_name, tcp).await.unwrap();

        let mut vless_request = Vec::new();
        vless_request.push(0u8);
        vless_request.extend_from_slice(&allowed_uuid);
        vless_request.push(0u8); // addons_len = 0
        vless_request.push(1u8); // command = TCP
        vless_request.extend_from_slice(&destination_port.to_be_bytes());
        vless_request.push(1u8); // address_type = IPv4
        vless_request.extend_from_slice(&[127, 0, 0, 1]);
        vless_request.extend_from_slice(b"cert-cloned-pipeline-payload");

        client_tls.write_all(&vless_request).await.unwrap();

        let mut response_header = [0u8; 2];
        client_tls.read_exact(&mut response_header).await.unwrap();
        assert_eq!(response_header, [0u8, 0u8]);

        let mut echoed = vec![0u8; b"cert-cloned-pipeline-payload".len()];
        client_tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"cert-cloned-pipeline-payload");

        client_tls.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }
}
