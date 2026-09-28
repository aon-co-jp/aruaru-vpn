//! VLESSプロトコル本体: リクエストヘッダの解析(実装フェーズ7)。
//!
//! REALITY認証(`reality`/`reality_auth`)を通過した接続が、実際に
//! どの宛先(IP/ドメイン+ポート)への転送を要求しているかを読み取る。
//! VLESSはXray-coreが定義する公開プロトコルであり、ワイヤーフォーマットは
//! 以下の通り(公開仕様のみ参考、コードは流用せず一から実装):
//!
//! ```text
//! [1B version][16B UUID][1B addons_len][addons_len B addons]
//! [1B command][2B port (big-endian)][1B address_type][address][payload...]
//! ```
//!
//! - `command`: 1=TCP, 2=UDP, 3=MUX
//! - `address_type`: 1=IPv4(4B), 2=ドメイン名(1B長+可変長), 3=IPv6(16B)
//!
//! サーバー応答ヘッダは`[1B version][1B addons_len][addons_len B addons]`
//! で、以降は転送データそのもの。

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// VLESSリクエストヘッダから読み取った、転送先の指定方法。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

/// パース済みのVLESSリクエストヘッダ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub version: u8,
    pub uuid: [u8; 16],
    pub command: Command,
    pub port: u16,
    pub address: Address,
    /// リクエストヘッダの直後に続くペイロードの開始位置(呼び出し側が
    /// `record[header_len..]`で実データを取り出せるようにするための
    /// バイトオフセット)。
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessParseError {
    TooShort,
    UnknownCommand(u8),
    UnknownAddressType(u8),
    InvalidDomain,
}

/// 生のバイト列からVLESSリクエストヘッダを解析する。
pub fn parse_request(data: &[u8]) -> Result<VlessRequest, VlessParseError> {
    let mut cursor = 0usize;

    let version = *data.get(cursor).ok_or(VlessParseError::TooShort)?;
    cursor += 1;

    if data.len() < cursor + 16 {
        return Err(VlessParseError::TooShort);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[cursor..cursor + 16]);
    cursor += 16;

    let addons_len = *data.get(cursor).ok_or(VlessParseError::TooShort)? as usize;
    cursor += 1;
    if data.len() < cursor + addons_len {
        return Err(VlessParseError::TooShort);
    }
    cursor += addons_len; // addons本体の中身は現時点では解釈しない(空の想定)

    let command_byte = *data.get(cursor).ok_or(VlessParseError::TooShort)?;
    let command = match command_byte {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Mux,
        other => return Err(VlessParseError::UnknownCommand(other)),
    };
    cursor += 1;

    if data.len() < cursor + 2 {
        return Err(VlessParseError::TooShort);
    }
    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    cursor += 2;

    let address_type = *data.get(cursor).ok_or(VlessParseError::TooShort)?;
    cursor += 1;

    let address = match address_type {
        1 => {
            if data.len() < cursor + 4 {
                return Err(VlessParseError::TooShort);
            }
            let octets = [
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ];
            cursor += 4;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        2 => {
            let domain_len = *data.get(cursor).ok_or(VlessParseError::TooShort)? as usize;
            cursor += 1;
            if data.len() < cursor + domain_len {
                return Err(VlessParseError::TooShort);
            }
            let domain = std::str::from_utf8(&data[cursor..cursor + domain_len])
                .map_err(|_| VlessParseError::InvalidDomain)?
                .to_owned();
            cursor += domain_len;
            Address::Domain(domain)
        }
        3 => {
            if data.len() < cursor + 16 {
                return Err(VlessParseError::TooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[cursor..cursor + 16]);
            cursor += 16;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        other => return Err(VlessParseError::UnknownAddressType(other)),
    };

    Ok(VlessRequest {
        version,
        uuid,
        command,
        port,
        address,
        header_len: cursor,
    })
}

/// サーバー応答ヘッダ(`[version][addons_len=0]`、addonsは付けない最小版)
/// を組み立てる。
pub fn build_response_header(version: u8) -> Vec<u8> {
    vec![version, 0x00]
}

/// 許可されたクライアントUUID(利用者ごとの識別子)の集合。VLESSは
/// REALITY/TLSの認証とは別に、リクエストヘッダ自身が持つUUIDで
/// 「どの利用者か」を識別・検証する(実際のXray-coreと同じ二段構えの
/// 認証: 外側の輸送路〈REALITY〉と、内側のプロトコル〈VLESSのUUID〉)。
#[derive(Debug, Clone, Default)]
pub struct AllowedUuids {
    uuids: HashSet<[u8; 16]>,
}

impl AllowedUuids {
    pub fn new(uuids: impl IntoIterator<Item = [u8; 16]>) -> Self {
        Self {
            uuids: uuids.into_iter().collect(),
        }
    }

    pub fn is_allowed(&self, uuid: &[u8; 16]) -> bool {
        self.uuids.contains(uuid)
    }
}

/// リクエストが許可済みUUIDを提示しているかを検証する。
pub fn validate_uuid(request: &VlessRequest, allowed: &AllowedUuids) -> bool {
    allowed.is_allowed(&request.uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_request(
        version: u8,
        uuid: [u8; 16],
        command: u8,
        port: u16,
        address_type_and_bytes: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(version);
        data.extend_from_slice(&uuid);
        data.push(0x00); // addons_len = 0
        data.push(command);
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(address_type_and_bytes);
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn parses_ipv4_tcp_request() {
        let uuid = [7u8; 16];
        let data = build_request(0, uuid, 1, 443, &[1, 93, 184, 216, 34], b"payload-bytes");
        let parsed = parse_request(&data).expect("valid request must parse");

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.uuid, uuid);
        assert_eq!(parsed.command, Command::Tcp);
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.address, Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(&data[parsed.header_len..], b"payload-bytes");
    }

    #[test]
    fn parses_domain_udp_request() {
        let uuid = [1u8; 16];
        let domain = b"example.test";
        let mut addr_bytes = vec![2u8, domain.len() as u8];
        addr_bytes.extend_from_slice(domain);
        let data = build_request(0, uuid, 2, 53, &addr_bytes, b"");
        let parsed = parse_request(&data).expect("valid request must parse");

        assert_eq!(parsed.command, Command::Udp);
        assert_eq!(parsed.address, Address::Domain("example.test".to_owned()));
        assert_eq!(parsed.header_len, data.len());
    }

    #[test]
    fn parses_ipv6_request() {
        let uuid = [2u8; 16];
        let mut addr_bytes = vec![3u8];
        addr_bytes.extend_from_slice(&[0u8; 15]);
        addr_bytes.push(1); // ::1
        let data = build_request(0, uuid, 1, 80, &addr_bytes, b"x");
        let parsed = parse_request(&data).expect("valid request must parse");
        assert_eq!(parsed.address, Address::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rejects_unknown_command() {
        let uuid = [0u8; 16];
        let data = build_request(0, uuid, 99, 1, &[1, 0, 0, 0, 0], b"");
        assert_eq!(parse_request(&data), Err(VlessParseError::UnknownCommand(99)));
    }

    #[test]
    fn rejects_unknown_address_type() {
        let uuid = [0u8; 16];
        let data = build_request(0, uuid, 1, 1, &[9], b"");
        assert_eq!(
            parse_request(&data),
            Err(VlessParseError::UnknownAddressType(9))
        );
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(parse_request(&[0u8; 5]), Err(VlessParseError::TooShort));
    }

    #[test]
    fn response_header_has_version_and_zero_addons() {
        let header = build_response_header(0);
        assert_eq!(header, vec![0x00, 0x00]);
    }

    #[test]
    fn validate_uuid_accepts_registered_client() {
        let uuid = [42u8; 16];
        let data = build_request(0, uuid, 1, 443, &[1, 1, 1, 1, 1], b"");
        let request = parse_request(&data).unwrap();

        let allowed = AllowedUuids::new([uuid]);
        assert!(validate_uuid(&request, &allowed));
    }

    #[test]
    fn validate_uuid_rejects_unregistered_client() {
        let uuid = [42u8; 16];
        let data = build_request(0, uuid, 1, 443, &[1, 1, 1, 1, 1], b"");
        let request = parse_request(&data).unwrap();

        let allowed = AllowedUuids::new([[99u8; 16]]);
        assert!(!validate_uuid(&request, &allowed));
    }

    #[test]
    fn validate_uuid_rejects_when_allow_list_is_empty() {
        let uuid = [1u8; 16];
        let data = build_request(0, uuid, 1, 443, &[1, 1, 1, 1, 1], b"");
        let request = parse_request(&data).unwrap();

        let allowed = AllowedUuids::default();
        assert!(!validate_uuid(&request, &allowed));
    }
}
