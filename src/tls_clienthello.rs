//! TLS ClientHelloの最小限のパーサー(REALITY判定への統合、実装フェーズ2)。
//!
//! 実際のREALITYは、クライアントがTLSハンドシェイクの`ClientHello`メッセージ
//! に認証情報を埋め込み(session_idフィールドやX25519鍵共有等)、サーバー側は
//! **完全なTLSハンドシェイクを完了する前に**そのバイト列を覗き見て、
//! 「これは正規のREALITYクライアントか、それとも無関係な接続か」を判定する。
//! ここでは`rustls`等の完全なTLS実装には頼らず(そもそも認証前は通常の
//! TLSサーバーとして応答してはならないため)、ワイヤーフォーマットを直接
//! 手作業でパースする最小限の実装を行う(`xray-lite`等のアーキテクチャを
//! 参考にしつつ、コードは流用せず一から設計)。
//!
//! パースする範囲は「SNI(Server Name Indication)拡張」と
//! 「session_idフィールド(32バイト、REALITYが認証情報を埋め込む場所)」に
//! 限定し、TLS ClientHello全体の厳密なパース(全拡張の解釈等)は行わない
//! (`open-runo-federation`のSDLパーサーと同じ「必要な範囲だけを厳密に
//! 実装する」方針)。

/// `ClientHello`から抽出した、REALITY判定に必要な最小限の情報。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// SNI拡張で示されたホスト名(例: "www.microsoft.com")。無ければ`None`。
    pub server_name: Option<String>,
    /// session_idフィールド(0〜32バイト)。REALITYの認証情報(short_id)は
    /// この末尾数バイトに埋め込まれる想定(実際のREALITY仕様に準拠する
    /// 詳細な埋め込み方式は次フェーズで確定する)。
    pub session_id: Vec<u8>,
}

/// パース失敗時のエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotAClientHello,
    Malformed(&'static str),
}

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_TYPE_SERVER_NAME: u16 = 0x0000;

/// TLSレコード層(5バイトヘッダ)+ハンドシェイク層(4バイトヘッダ)を剥がし、
/// `ClientHello`本体から`server_name`と`session_id`を抽出する。
///
/// 入力は「1つの完全なTLSレコードに収まったClientHello」を前提とする
/// (フラグメント化されたClientHelloへの対応は次フェーズ)。
pub fn parse_client_hello(record: &[u8]) -> Result<ParsedClientHello, ParseError> {
    // TLSレコードヘッダ: type(1) + version(2) + length(2)
    if record.len() < 5 {
        return Err(ParseError::TooShort);
    }
    if record[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Err(ParseError::NotAClientHello);
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let body = &record[5..];
    if body.len() < record_len {
        return Err(ParseError::TooShort);
    }
    let body = &body[..record_len];

    // ハンドシェイクヘッダ: msg_type(1) + length(3)
    if body.len() < 4 {
        return Err(ParseError::TooShort);
    }
    if body[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParseError::NotAClientHello);
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let hs_body = &body[4..];
    if hs_body.len() < hs_len {
        return Err(ParseError::TooShort);
    }
    let hs_body = &hs_body[..hs_len];

    // client_version(2) + random(32) = 34バイト
    if hs_body.len() < 34 {
        return Err(ParseError::TooShort);
    }
    let mut cursor = 34usize;

    // session_id: 1バイト長 + 可変長本体
    let session_id_len = *hs_body
        .get(cursor)
        .ok_or(ParseError::Malformed("missing session_id length"))? as usize;
    cursor += 1;
    if hs_body.len() < cursor + session_id_len {
        return Err(ParseError::Malformed("session_id truncated"));
    }
    let session_id = hs_body[cursor..cursor + session_id_len].to_vec();
    cursor += session_id_len;

    // cipher_suites: 2バイト長 + 可変長本体
    let cipher_suites_len = u16::from_be_bytes(
        hs_body
            .get(cursor..cursor + 2)
            .ok_or(ParseError::Malformed("missing cipher_suites length"))?
            .try_into()
            .unwrap(),
    ) as usize;
    cursor += 2 + cipher_suites_len;

    // compression_methods: 1バイト長 + 可変長本体
    let compression_len = *hs_body
        .get(cursor)
        .ok_or(ParseError::Malformed("missing compression_methods length"))?
        as usize;
    cursor += 1 + compression_len;

    // extensions: 2バイト長 + 可変長本体(無ければserver_nameはNone)
    let server_name = if cursor + 2 <= hs_body.len() {
        let extensions_len = u16::from_be_bytes([hs_body[cursor], hs_body[cursor + 1]]) as usize;
        cursor += 2;
        let extensions_end = (cursor + extensions_len).min(hs_body.len());
        parse_server_name_extension(&hs_body[cursor..extensions_end])
    } else {
        None
    };

    Ok(ParsedClientHello {
        server_name,
        session_id,
    })
}

/// 拡張リストの中からSNI拡張(type=0)を探し、ホスト名を取り出す。
fn parse_server_name_extension(extensions: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    while cursor + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let ext_len = u16::from_be_bytes([extensions[cursor + 2], extensions[cursor + 3]]) as usize;
        let ext_start = cursor + 4;
        let ext_end = (ext_start + ext_len).min(extensions.len());
        if ext_type == EXTENSION_TYPE_SERVER_NAME {
            return parse_server_name_list(&extensions[ext_start..ext_end]);
        }
        cursor = ext_end;
    }
    None
}

/// SNI拡張本体(server_name_list)から、最初のホスト名(name_type=0)を返す。
fn parse_server_name_list(body: &[u8]) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    // server_name_list length(2) はここでは使わず末尾まで走査する。
    let mut cursor = 2usize;
    while cursor + 3 <= body.len() {
        let name_type = body[cursor];
        let name_len = u16::from_be_bytes([body[cursor + 1], body[cursor + 2]]) as usize;
        let name_start = cursor + 3;
        let name_end = (name_start + name_len).min(body.len());
        if name_type == 0 {
            return std::str::from_utf8(&body[name_start..name_end])
                .ok()
                .map(|s| s.to_owned());
        }
        cursor = name_end;
    }
    None
}

/// 他モジュールのテストからも使える、ClientHelloバイト列組み立てヘルパー。
#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) fn build_client_hello_for_tests(session_id: &[u8], sni: &str) -> Vec<u8> {
        super::tests::build_client_hello(session_id, sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用に、SNI("example.test")とsession_idを含む最小限の
    /// ClientHelloバイト列を組み立てる。
    pub(super) fn build_client_hello(session_id: &[u8], sni: &str) -> Vec<u8> {
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version (TLS 1.2 legacy)
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(session_id.len() as u8);
        hs_body.extend_from_slice(session_id);
        hs_body.extend_from_slice(&[0x00, 0x00]); // cipher_suites (empty)
        hs_body.push(0x00); // compression_methods (empty)

        let sni_bytes = sni.as_bytes();
        let mut server_name_entry = Vec::new();
        server_name_entry.push(0x00); // name_type = host_name
        server_name_entry.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        server_name_entry.extend_from_slice(sni_bytes);

        let mut server_name_list = Vec::new();
        server_name_list.extend_from_slice(&(server_name_entry.len() as u16).to_be_bytes());
        server_name_list.extend_from_slice(&server_name_entry);

        let mut sni_extension = Vec::new();
        sni_extension.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type = server_name
        sni_extension.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
        sni_extension.extend_from_slice(&server_name_list);

        hs_body.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&sni_extension);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        let hs_len = hs_body.len() as u32;
        handshake.extend_from_slice(&hs_len.to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&hs_body);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE_CONTENT_TYPE);
        record.extend_from_slice(&[0x03, 0x03]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_and_session_id() {
        let record = build_client_hello(b"example-short-id", "www.microsoft.com");
        let parsed = parse_client_hello(&record).expect("valid ClientHello must parse");
        assert_eq!(parsed.server_name.as_deref(), Some("www.microsoft.com"));
        assert_eq!(parsed.session_id, b"example-short-id".to_vec());
    }

    #[test]
    fn rejects_too_short_input() {
        assert_eq!(parse_client_hello(&[0x16, 0x03]), Err(ParseError::TooShort));
    }

    #[test]
    fn rejects_non_handshake_content_type() {
        let mut record = build_client_hello(b"x", "example.test");
        record[0] = 0x17; // application_data, not handshake
        assert_eq!(
            parse_client_hello(&record),
            Err(ParseError::NotAClientHello)
        );
    }

    #[test]
    fn empty_session_id_parses_as_empty_vec() {
        let record = build_client_hello(b"", "example.test");
        let parsed = parse_client_hello(&record).expect("valid ClientHello must parse");
        assert!(parsed.session_id.is_empty());
    }
}
