//! VLESS+REALITY本体の核となる「認証判定→フォールバック転送」の仕組み。
//!
//! REALITYの本質(`README.md`「技術選定」参照、[XTLS/REALITY](https://github.com/xtls/reality)
//! の公開仕様のみを参考に、コードは流用せず一から設計):
//! - サーバーは正規サイト(例: microsoft.com)への接続を装う。
//! - クライアントが正しい認証情報(事前共有した公開鍵に対応する秘密鍵で
//!   導出した値)を提示した場合のみ、プロキシとして振る舞う。
//! - 認証情報が無い/不正な接続は、本物のターゲットサイトへそのまま転送し、
//!   応答もそのまま返す。これにより外部の観測者(検閲側)には「本物の
//!   ターゲットサイトへの普通のTLS接続」にしか見えない。
//!
//! ここでは実際のTLSライブラリ改造(uTLSのClientHello偽装等)には踏み込まず、
//! 「認証チェック→分岐」という核心のロジックだけを、テスト可能な形で
//! 最小実装する(小規模な基本部分から段階的に進める方針)。

use std::collections::HashSet;

/// クライアントが提示した認証キーの検証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// 認証成功。プロキシとして振る舞ってよい。
    Authenticated,
    /// 認証情報が無い、または不正。本物のターゲットサイトへそのまま
    /// 転送する(フォールバック)必要がある。
    Fallback,
}

/// REALITYの認証チェッカー。
///
/// 実際のREALITYはTLSのClientHello内の特定フィールド(X25519鍵共有等)に
/// 認証情報を埋め込むが、ここではその詳細に踏み込まず、「事前共有した
/// 短いID(short_id)の集合に対する所属チェック」という核心の判定ロジックを
/// 抽象化して実装する(実際のTLS層への統合は次フェーズ)。
#[derive(Debug, Clone, Default)]
pub struct RealityAuthChecker {
    /// 有効なshort_id(利用者ごとに配布する短い識別子)の集合。
    valid_short_ids: HashSet<Vec<u8>>,
}

impl RealityAuthChecker {
    pub fn new(valid_short_ids: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            valid_short_ids: valid_short_ids.into_iter().collect(),
        }
    }

    /// 提示されたshort_idを検証する。空のshort_id・未登録のshort_idは
    /// いずれも`Fallback`(=偽装先サイトへの転送)とする。
    pub fn check(&self, presented_short_id: &[u8]) -> AuthDecision {
        if presented_short_id.is_empty() {
            return AuthDecision::Fallback;
        }
        if self.valid_short_ids.contains(presented_short_id) {
            AuthDecision::Authenticated
        } else {
            AuthDecision::Fallback
        }
    }
}

/// 認証判定の結果に応じて、実際に何をすべきかを表す。
///
/// `Relay`はプロキシとしての本処理(VLESSセッションの開始)、
/// `Fallback`は偽装先サイトのアドレスへ生バイトをそのまま転送すべき
/// ことを示す(検閲側からは正規サイトへの接続にしか見えない)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionAction {
    Relay,
    Fallback { camouflage_target: String },
}

/// 認証チェッカーと偽装先サイトの設定から、接続ごとの振る舞いを決定する。
pub fn decide_connection_action(
    checker: &RealityAuthChecker,
    presented_short_id: &[u8],
    camouflage_target: &str,
) -> ConnectionAction {
    match checker.check(presented_short_id) {
        AuthDecision::Authenticated => ConnectionAction::Relay,
        AuthDecision::Fallback => ConnectionAction::Fallback {
            camouflage_target: camouflage_target.to_owned(),
        },
    }
}

/// 生のTLS ClientHelloレコードを受け取り、[`crate::tls_clienthello`]で
/// パースした`session_id`を認証情報として使って接続の振る舞いを決定する。
///
/// 偽装先(`camouflage_target`)は、ClientHelloのSNIが指定されていれば
/// それを優先し(利用者が実際にアクセスしようとしたサイトへそのまま
/// 転送する方が、検閲側から見て一貫性がある)、無ければ設定値
/// `default_camouflage_target`を使う。
pub fn decide_from_client_hello_record(
    checker: &RealityAuthChecker,
    record: &[u8],
    default_camouflage_target: &str,
) -> Result<ConnectionAction, crate::tls_clienthello::ParseError> {
    let parsed = crate::tls_clienthello::parse_client_hello(record)?;
    let camouflage_target = parsed.server_name.as_deref().unwrap_or(default_camouflage_target);
    Ok(decide_connection_action(
        checker,
        &parsed.session_id,
        camouflage_target,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_short_id_always_falls_back() {
        let checker = RealityAuthChecker::new([vec![1, 2, 3]]);
        assert_eq!(checker.check(&[]), AuthDecision::Fallback);
    }

    #[test]
    fn unknown_short_id_falls_back() {
        let checker = RealityAuthChecker::new([vec![1, 2, 3]]);
        assert_eq!(checker.check(&[9, 9, 9]), AuthDecision::Fallback);
    }

    #[test]
    fn registered_short_id_authenticates() {
        let checker = RealityAuthChecker::new([vec![1, 2, 3], vec![4, 5, 6]]);
        assert_eq!(checker.check(&[4, 5, 6]), AuthDecision::Authenticated);
    }

    #[test]
    fn decide_connection_action_relays_when_authenticated() {
        let checker = RealityAuthChecker::new([vec![7, 7, 7]]);
        let action = decide_connection_action(&checker, &[7, 7, 7], "www.microsoft.com");
        assert_eq!(action, ConnectionAction::Relay);
    }

    #[test]
    fn decide_connection_action_falls_back_with_camouflage_target_when_unauthenticated() {
        let checker = RealityAuthChecker::new([vec![7, 7, 7]]);
        let action = decide_connection_action(&checker, &[0, 0, 0], "www.microsoft.com");
        assert_eq!(
            action,
            ConnectionAction::Fallback {
                camouflage_target: "www.microsoft.com".to_owned()
            }
        );
    }

    #[test]
    fn decide_from_client_hello_record_authenticates_when_session_id_matches() {
        use crate::tls_clienthello::tests_support::build_client_hello_for_tests;

        let checker = RealityAuthChecker::new([b"good-short-id".to_vec()]);
        let record = build_client_hello_for_tests(b"good-short-id", "www.microsoft.com");
        let action =
            decide_from_client_hello_record(&checker, &record, "fallback.example").unwrap();
        assert_eq!(action, ConnectionAction::Relay);
    }

    #[test]
    fn decide_from_client_hello_record_falls_back_to_sni_when_unauthenticated() {
        use crate::tls_clienthello::tests_support::build_client_hello_for_tests;

        let checker = RealityAuthChecker::new([b"good-short-id".to_vec()]);
        let record = build_client_hello_for_tests(b"wrong-id", "www.microsoft.com");
        let action =
            decide_from_client_hello_record(&checker, &record, "fallback.example").unwrap();
        assert_eq!(
            action,
            ConnectionAction::Fallback {
                camouflage_target: "www.microsoft.com".to_owned()
            }
        );
    }
}
