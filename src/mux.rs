//! VLESS `Command::Mux`の実装(実装フェーズ17)。
//!
//! 本来のVLESS/V2Rayの`Mux.Cool`プロトコルは、1本のセッションの中に複数の
//! 独立したサブストリーム(それぞれ別の宛先への接続に対応)を、ID+ステータス
//! (New/Keep/End/KeepAlive)付きフレームで多重化する仕組みである。
//! `Mux.Cool`公開仕様のみを参考に、コードは流用せず一から設計する
//! (このリポジトリ全体の方針どおり)。
//!
//! **このリポジトリでの位置づけ**: `aruaru-vpn`は利用者が自分専用の中継を
//! 構築するテンプレートであり、実際に相互接続する相手は基本的に自分自身が
//! 動かすクライアント/サーバーの組(`aruaru-vpn`同士)になる想定のため、
//! 本物のXray-core/V2Rayとのワイヤーフォーマット互換は目標にしない
//! (`secure_channel`が本物のTLSと互換を目指さないのと同じ設計判断)。
//! フレームフォーマットは`Mux.Cool`の考え方(ステータス+サブストリームID)を
//! 参考にしつつ、独自に単純化して定義する。
//!
//! **フレームフォーマット(独自定義)**:
//! ```text
//! [1B status][2B sub_id(big-endian)]
//! status=New(1)の場合のみ: [2B port][1B address_type][address][payload...]
//! status=Keep(2)の場合: [payload...]
//! status=End(3)の場合: (payload無し)
//! ```
//! バイトストリーム上(`Command::Tcp`と同じ生TCP/TLSストリーム)では、この
//! フレーム本体の前に`[2Bフレーム長]`を付ける。`secure_channel`上では
//! メッセージ境界が既にフレーム境界を兼ねるため、長さプレフィックスは
//! 不要(`handle_mux_over_secure_channel`参照)。

use std::collections::HashMap;
use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::vless::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxStatus {
    New,
    Keep,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub sub_id: u16,
    pub status: MuxStatus,
    /// `status == New`のときだけ`Some`(サブストリームが接続すべき宛先)。
    pub new_target: Option<(Address, u16)>,
    pub payload: Vec<u8>,
}

impl MuxFrame {
    pub fn new_stream(sub_id: u16, address: Address, port: u16, payload: Vec<u8>) -> Self {
        Self {
            sub_id,
            status: MuxStatus::New,
            new_target: Some((address, port)),
            payload,
        }
    }

    pub fn keep(sub_id: u16, payload: Vec<u8>) -> Self {
        Self {
            sub_id,
            status: MuxStatus::Keep,
            new_target: None,
            payload,
        }
    }

    pub fn end(sub_id: u16) -> Self {
        Self {
            sub_id,
            status: MuxStatus::End,
            new_target: None,
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxParseError {
    TooShort,
    UnknownStatus(u8),
    UnknownAddressType(u8),
    InvalidDomain,
}

fn encode_address(out: &mut Vec<u8>, address: &Address) {
    match address {
        Address::Ipv4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            out.push(2);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(ip) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_address(data: &[u8]) -> Result<(Address, usize), MuxParseError> {
    let address_type = *data.first().ok_or(MuxParseError::TooShort)?;
    let rest = &data[1..];
    match address_type {
        1 => {
            if rest.len() < 4 {
                return Err(MuxParseError::TooShort);
            }
            let octets = [rest[0], rest[1], rest[2], rest[3]];
            Ok((Address::Ipv4(std::net::Ipv4Addr::from(octets)), 1 + 4))
        }
        2 => {
            let domain_len = *rest.first().ok_or(MuxParseError::TooShort)? as usize;
            if rest.len() < 1 + domain_len {
                return Err(MuxParseError::TooShort);
            }
            let domain = std::str::from_utf8(&rest[1..1 + domain_len])
                .map_err(|_| MuxParseError::InvalidDomain)?
                .to_owned();
            Ok((Address::Domain(domain), 1 + 1 + domain_len))
        }
        3 => {
            if rest.len() < 16 {
                return Err(MuxParseError::TooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            Ok((Address::Ipv6(std::net::Ipv6Addr::from(octets)), 1 + 16))
        }
        other => Err(MuxParseError::UnknownAddressType(other)),
    }
}

/// フレーム本体([1B status][2B sub_id]...)をエンコードする(長さ
/// プレフィックスは含まない、呼び出し側の伝送路に応じて付与/不要かが
/// 変わるため)。
pub fn encode_frame_body(frame: &MuxFrame) -> Vec<u8> {
    let mut out = Vec::new();
    let status_byte = match frame.status {
        MuxStatus::New => 1u8,
        MuxStatus::Keep => 2u8,
        MuxStatus::End => 3u8,
    };
    out.push(status_byte);
    out.extend_from_slice(&frame.sub_id.to_be_bytes());
    if let MuxStatus::New = frame.status {
        let (address, port) = frame
            .new_target
            .as_ref()
            .expect("New frame must carry a target");
        out.extend_from_slice(&port.to_be_bytes());
        encode_address(&mut out, address);
    }
    out.extend_from_slice(&frame.payload);
    out
}

/// [`encode_frame_body`]の逆。
pub fn decode_frame_body(data: &[u8]) -> Result<MuxFrame, MuxParseError> {
    if data.len() < 3 {
        return Err(MuxParseError::TooShort);
    }
    let status = match data[0] {
        1 => MuxStatus::New,
        2 => MuxStatus::Keep,
        3 => MuxStatus::End,
        other => return Err(MuxParseError::UnknownStatus(other)),
    };
    let sub_id = u16::from_be_bytes([data[1], data[2]]);
    let mut cursor = 3usize;

    let new_target = if status == MuxStatus::New {
        if data.len() < cursor + 2 {
            return Err(MuxParseError::TooShort);
        }
        let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;
        let (address, consumed) = decode_address(&data[cursor..])?;
        cursor += consumed;
        Some((address, port))
    } else {
        None
    };

    let payload = data[cursor..].to_vec();
    Ok(MuxFrame {
        sub_id,
        status,
        new_target,
        payload,
    })
}

/// バイトストリーム上のフレーミング: `[2Bフレーム長][フレーム本体]`。
pub(crate) fn encode_mux_frame(frame: &MuxFrame) -> Vec<u8> {
    let body = encode_frame_body(frame);
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub(crate) async fn read_one_mux_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<MuxFrame>> {
    let mut len_buf = [0u8; 2];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let body_len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    decode_frame_body(&body)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
}

/// `Command::Mux`の本体(実装フェーズ17): 1本のバイトストリーム
/// (生TCP、または`cert_clone`のTLS 1.3ストリーム)上で、複数のサブ
/// ストリームを多重化する。サブストリームごとに`dial_destination`で
/// 実際の宛先へ接続し、双方向にデータを中継する。
///
/// クライアントの最初のフレームは、この関数が呼ばれる前に既に読み取り
/// 済みの前提(`net.rs`の`handle_relay_session`と同じ「1バイト目から
/// フレーミングが始まる」設計)。
///
/// **設計上の注意(実装フェーズ17でのバグ修正、2段階)**:
/// (1) 当初`tokio::io::split`でクライアントストリームを読み取り専用/
/// 書き込み専用の2半分に分け、**書き込み専用の別タスク**を立てる設計を
/// 試みたが、実際にテストすると宛先からの応答フレームが送信されないまま
/// ハングすることが判明した。
/// (2) 次に、分割せず単一タスクの`select!`で読み書き両方を行う設計に
/// 変えたところハングは解消したが、`read_one_mux_frame`が内部で2回
/// `read_exact`を呼ぶため、`select!`の他の分岐(`agg_rx.recv()`)が
/// 途中(2回目の`read_exact`待ち)で先に完了すると、`read_one_mux_frame`の
/// Futureごとキャンセルされ、既に読み取り済みの長さプレフィックスが
/// 失われてフレーム境界がずれる(キャンセル安全性の問題)。
///
/// 最終的に、**読み取り専用の別タスク**(完全なフレームを1個ずつ
/// デコードしてから`mpsc`チャネルで渡す、部分読み取り状態を`select!`の
/// 外に閉じ込める)+**書き込みはメインループが排他的に行う**という構成に
/// 落ち着いた。`mpsc::Receiver::recv()`はキャンセル安全なため、
/// `select!`で複数のチャネルを待ち受けても問題ない。
pub async fn handle_mux_session<S, F, Fut>(stream: S, dial_destination: F) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Address, u16) -> Fut,
    Fut: Future<Output = std::io::Result<TcpStream>>,
{
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // 読み取り専用タスク: クライアントからのフレームを1個ずつデコードし、
    // 完全な`MuxFrame`単位でメインループへ渡す(部分読み取りの状態を
    // `select!`の外に閉じ込め、キャンセル安全性の問題を避ける)。
    let (client_frame_tx, mut client_frame_rx) = mpsc::channel::<MuxFrame>(64);
    let reader_task = tokio::spawn(async move {
        loop {
            match read_one_mux_frame(&mut read_half).await {
                Ok(Some(frame)) => {
                    if client_frame_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    });

    let (agg_tx, mut agg_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut destinations: HashMap<u16, mpsc::Sender<Vec<u8>>> = HashMap::new();

    loop {
        let frame = tokio::select! {
            maybe_frame = client_frame_rx.recv() => {
                match maybe_frame {
                    Some(f) => f,
                    None => break,
                }
            }
            Some(body) = agg_rx.recv() => {
                if write_half.write_all(&body).await.is_err() {
                    break;
                }
                continue;
            }
        };

        match frame.status {
            MuxStatus::New => {
                let Some((address, port)) = frame.new_target else {
                    continue;
                };
                let sub_id = frame.sub_id;
                let dest_stream = match dial_destination(address, port).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = write_half
                            .write_all(&encode_mux_frame(&MuxFrame::end(sub_id)))
                            .await;
                        continue;
                    }
                };
                let (mut dest_read, mut dest_write) = dest_stream.into_split();
                if !frame.payload.is_empty() && dest_write.write_all(&frame.payload).await.is_err()
                {
                    continue;
                }

                let (to_dest_tx, mut to_dest_rx) = mpsc::channel::<Vec<u8>>(64);
                destinations.insert(sub_id, to_dest_tx);

                // 宛先→クライアント方向: 読み取ったバイト列を集約チャネル
                // (`agg_tx`)経由でメインループへ渡す。実際にクライアントへ
                // 書き込むのは、常にこのメインループ(`stream`の唯一の
                // 所有者)だけ。
                let agg_tx_for_dest = agg_tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match dest_read.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let frame = MuxFrame::keep(sub_id, buf[..n].to_vec());
                                if agg_tx_for_dest
                                    .send(encode_mux_frame(&frame))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = agg_tx_for_dest
                        .send(encode_mux_frame(&MuxFrame::end(sub_id)))
                        .await;
                });

                // クライアント→宛先方向。
                tokio::spawn(async move {
                    while let Some(payload) = to_dest_rx.recv().await {
                        if dest_write.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                });
            }
            MuxStatus::Keep => {
                if let Some(tx) = destinations.get(&frame.sub_id) {
                    let _ = tx.send(frame.payload).await;
                }
            }
            MuxStatus::End => {
                destinations.remove(&frame.sub_id);
            }
        }
    }

    reader_task.abort();
    Ok(())
}

/// [`handle_mux_session`]の`secure_channel`版(実装フェーズ17):
/// メッセージ単位のフレーミングが既に`secure_channel`側にあるため、
/// 長さプレフィックスは不要で、1メッセージ=1フレーム本体として扱う。
///
/// `writer`/`reader`を排他的に借用するため(`SecureWriter`/`SecureReader`
/// は`&mut self`でのみ送受信できる)、複数サブストリームの並行処理は
/// この関数自身のイベントループ(`tokio::select!`)の中で行い、送信側は
/// 常にこの1タスクだけが`writer`を使う(複数タスクが直接書き込むと
/// フレームが混ざるため)。宛先ごとの読み取りタスクは、集約用の
/// `mpsc`チャネル経由でこのループへフレームを渡す。
///
/// `initial_frame_body`は、VLESSリクエストヘッダの直後に既に届いていた
/// バイト列(`net.rs`の`handle_relay_session_secure`が`first_message`から
/// 切り出した`leftover_payload`)。`secure_channel`は「1メッセージ=1フレーム
/// 本体」という前提のため、これは最初のMuxフレームそのものとして扱う
/// (空なら何もしない)。
pub async fn handle_mux_over_secure_channel<W, R, F, Fut>(
    writer: &mut crate::secure_channel::SecureWriter<W>,
    reader: &mut crate::secure_channel::SecureReader<R>,
    initial_frame_body: Vec<u8>,
    dial_destination: F,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: Fn(Address, u16) -> Fut,
    Fut: Future<Output = std::io::Result<TcpStream>>,
{
    let (agg_tx, mut agg_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut destinations: HashMap<u16, mpsc::Sender<Vec<u8>>> = HashMap::new();

    let mut pending: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    if !initial_frame_body.is_empty() {
        pending.push_back(initial_frame_body);
    }

    loop {
        let body = if let Some(b) = pending.pop_front() {
            Some(b)
        } else {
            tokio::select! {
                from_client = reader.recv() => from_client.ok(),
                Some(agg_body) = agg_rx.recv() => {
                    if writer.send(&agg_body).await.is_err() {
                        break;
                    }
                    continue;
                }
            }
        };

        {
            let Some(body) = body else { break };
            let frame = match decode_frame_body(&body) {
                Ok(f) => f,
                Err(_) => continue,
            };
            match frame.status {
                MuxStatus::New => {
                    let Some((address, port)) = frame.new_target else {
                        continue;
                    };
                    let sub_id = frame.sub_id;
                    let dest_stream = match dial_destination(address, port).await {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = agg_tx.send(encode_frame_body(&MuxFrame::end(sub_id))).await;
                            continue;
                        }
                    };
                    let (mut dest_read, mut dest_write) = dest_stream.into_split();
                    if !frame.payload.is_empty()
                        && dest_write.write_all(&frame.payload).await.is_err()
                    {
                        continue;
                    }

                    let (to_dest_tx, mut to_dest_rx) = mpsc::channel::<Vec<u8>>(64);
                    destinations.insert(sub_id, to_dest_tx);

                    let agg_tx_for_dest = agg_tx.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match dest_read.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let frame = MuxFrame::keep(sub_id, buf[..n].to_vec());
                                    if agg_tx_for_dest
                                        .send(encode_frame_body(&frame))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = agg_tx_for_dest
                            .send(encode_frame_body(&MuxFrame::end(sub_id)))
                            .await;
                    });

                    tokio::spawn(async move {
                        while let Some(payload) = to_dest_rx.recv().await {
                            if dest_write.write_all(&payload).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                MuxStatus::Keep => {
                    if let Some(tx) = destinations.get(&frame.sub_id) {
                        let _ = tx.send(frame.payload).await;
                    }
                }
                MuxStatus::End => {
                    destinations.remove(&frame.sub_id);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_new_frame_with_domain_address() {
        let frame = MuxFrame::new_stream(
            7,
            Address::Domain("example.test".to_owned()),
            443,
            b"hello".to_vec(),
        );
        let encoded = encode_frame_body(&frame);
        let decoded = decode_frame_body(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn round_trips_a_keep_frame() {
        let frame = MuxFrame::keep(3, b"payload-bytes".to_vec());
        let encoded = encode_frame_body(&frame);
        let decoded = decode_frame_body(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn round_trips_an_end_frame() {
        let frame = MuxFrame::end(99);
        let encoded = encode_frame_body(&frame);
        let decoded = decode_frame_body(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn round_trips_ipv4_and_ipv6_new_frames() {
        let v4 = MuxFrame::new_stream(
            1,
            Address::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            80,
            vec![],
        );
        assert_eq!(decode_frame_body(&encode_frame_body(&v4)).unwrap(), v4);

        let v6 = MuxFrame::new_stream(2, Address::Ipv6(std::net::Ipv6Addr::LOCALHOST), 80, vec![]);
        assert_eq!(decode_frame_body(&encode_frame_body(&v6)).unwrap(), v6);
    }

    #[test]
    fn rejects_unknown_status() {
        let data = vec![9u8, 0, 1];
        assert_eq!(
            decode_frame_body(&data),
            Err(MuxParseError::UnknownStatus(9))
        );
    }

    #[test]
    fn rejects_too_short_input() {
        assert_eq!(decode_frame_body(&[1u8, 0]), Err(MuxParseError::TooShort));
    }

    /// `handle_mux_session`が、1本のバイトストリームの中で**2本の独立した
    /// サブストリーム**を同時に多重化し、それぞれ別のモック宛先へ正しく
    /// 中継できることを確認する(実装フェーズ17のフルend-to-endテスト)。
    #[tokio::test]
    async fn relays_two_concurrent_substreams_to_different_destinations() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relays_two_concurrent_substreams_to_different_destinations_inner(),
        )
        .await
        .expect("test must not hang");
    }

    async fn relays_two_concurrent_substreams_to_different_destinations_inner() {
        use tokio::net::TcpListener;

        // 宛先A・宛先B: 受け取ったバイト列の先頭に印を付けて返すecho。
        async fn spawn_tagging_echo(tag: u8) -> std::net::SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let mut reply = vec![tag];
                                reply.extend_from_slice(&buf[..n]);
                                if stream.write_all(&reply).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            addr
        }

        let dest_a_addr = spawn_tagging_echo(0xAA).await;
        let dest_b_addr = spawn_tagging_echo(0xBB).await;

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = relay_listener.accept().await.unwrap();
            handle_mux_session(stream, |_address, port| async move {
                TcpStream::connect(("127.0.0.1", port)).await
            })
            .await
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();

        // サブストリーム1をAへ、サブストリーム2をBへ、それぞれNewで開く。
        let new_a = MuxFrame::new_stream(
            1,
            Address::Domain("127.0.0.1".to_owned()),
            dest_a_addr.port(),
            b"from-a".to_vec(),
        );
        let new_b = MuxFrame::new_stream(
            2,
            Address::Domain("127.0.0.1".to_owned()),
            dest_b_addr.port(),
            b"from-b".to_vec(),
        );
        client.write_all(&encode_mux_frame(&new_a)).await.unwrap();
        client.write_all(&encode_mux_frame(&new_b)).await.unwrap();

        // 両方からの応答(タグ付き)をフレームとして受信し、正しいサブ
        // ストリームIDに紐づいていることを確認する。
        let mut seen = std::collections::HashMap::new();
        for _ in 0..2 {
            let frame = read_one_mux_frame(&mut client).await.unwrap().unwrap();
            assert_eq!(frame.status, MuxStatus::Keep);
            seen.insert(frame.sub_id, frame.payload);
        }
        assert_eq!(seen.get(&1).unwrap(), &{
            let mut v = vec![0xAA];
            v.extend_from_slice(b"from-a");
            v
        });
        assert_eq!(seen.get(&2).unwrap(), &{
            let mut v = vec![0xBB];
            v.extend_from_slice(b"from-b");
            v
        });

        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }
}
