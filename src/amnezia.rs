//! AmneziaWG型難読化の核心機構: ハンドシェイク前後への「ジャンクパケット」
//! 挿入(実装フェーズ2)。
//!
//! AmneziaWGは、WireGuardの実際のハンドシェイクパケットの前後にランダムな
//! 内容・個数のダミーパケット(ジャンクパケット)を挟むことで、WireGuard
//! 特有の「ハンドシェイクパケットが規則的な間隔・サイズで現れる」という
//! 検出可能な通信パターンを崩す(公開されている設定パラメータ`Jc`
//! 〈ジャンクパケット数〉・`Jmin`/`Jmax`〈各ジャンクパケットのサイズ範囲〉
//! の仕組みのみを参考にし、コードは流用せず一から設計する)。
//!
//! ここではWireGuard本体の暗号処理(Noiseプロトコルハンドシェイク)には
//! 踏み込まず、「送信すべきパケット列(ジャンク+実データ)の計画を立てる」
//! というAmneziaWGの核心部分だけを、乱数源を外部から注入する形で
//! テスト可能に実装する。

/// ジャンクパケット挿入の設定(AmneziaWGの`Jc`/`Jmin`/`Jmax`相当)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObfuscationConfig {
    /// 実際のハンドシェイクパケットの前に挿入するジャンクパケットの個数。
    pub junk_packet_count: u8,
    /// 各ジャンクパケットの最小サイズ(バイト)。
    pub junk_min_size: u16,
    /// 各ジャンクパケットの最大サイズ(バイト、`junk_min_size`以上)。
    pub junk_max_size: u16,
}

impl ObfuscationConfig {
    /// 設定値が矛盾していないかを検証する(`junk_min_size <= junk_max_size`)。
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.junk_min_size > self.junk_max_size {
            return Err("junk_min_size must be <= junk_max_size");
        }
        Ok(())
    }
}

/// 送信計画の1ステップ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendStep {
    /// ダミーデータ(指定バイト数)を送信する。
    Junk { size: usize },
    /// 実際のハンドシェイクパケットを送信する。
    RealHandshakePacket,
}

/// `config`と、呼び出し側が与える乱数列(`[0.0, 1.0)`の値、ジャンクサイズの
/// 決定に使う)を使って、「ジャンクパケットN個→実ハンドシェイクパケット1個」
/// という送信計画を作る。
///
/// 乱数生成そのものはこの関数のスコープ外とし(実装着手時に暗号論的に
/// 安全な乱数源を選定する、`open-LiveKit`の`NodePool::pick`と同じ設計)、
/// 呼び出し側から`junk_packet_count`個ぶんの乱数を渡してもらう形で
/// 決定的にテストできるようにしている。
pub fn plan_handshake_send_sequence(
    config: &ObfuscationConfig,
    junk_size_randoms: &[f64],
) -> Vec<SendStep> {
    let mut steps = Vec::with_capacity(config.junk_packet_count as usize + 1);
    let size_range = (config.junk_max_size - config.junk_min_size) as f64;

    for i in 0..config.junk_packet_count as usize {
        let r = junk_size_randoms.get(i).copied().unwrap_or(0.0).clamp(0.0, 0.999_999_999);
        let size = config.junk_min_size as usize + (r * size_range) as usize;
        steps.push(SendStep::Junk { size });
    }
    steps.push(SendStep::RealHandshakePacket);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_inverted_size_range() {
        let config = ObfuscationConfig {
            junk_packet_count: 3,
            junk_min_size: 100,
            junk_max_size: 50,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_normal_range() {
        let config = ObfuscationConfig {
            junk_packet_count: 3,
            junk_min_size: 40,
            junk_max_size: 200,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn plan_ends_with_real_handshake_packet() {
        let config = ObfuscationConfig {
            junk_packet_count: 4,
            junk_min_size: 40,
            junk_max_size: 100,
        };
        let plan = plan_handshake_send_sequence(&config, &[0.0, 0.25, 0.5, 0.75]);
        assert_eq!(plan.len(), 5);
        assert_eq!(plan.last(), Some(&SendStep::RealHandshakePacket));
    }

    #[test]
    fn plan_junk_sizes_stay_within_configured_range() {
        let config = ObfuscationConfig {
            junk_packet_count: 10,
            junk_min_size: 40,
            junk_max_size: 100,
        };
        let randoms: Vec<f64> = (0..10).map(|i| i as f64 / 10.0).collect();
        let plan = plan_handshake_send_sequence(&config, &randoms);

        for step in &plan[..plan.len() - 1] {
            match step {
                SendStep::Junk { size } => {
                    assert!(*size >= config.junk_min_size as usize);
                    assert!(*size <= config.junk_max_size as usize);
                }
                SendStep::RealHandshakePacket => panic!("unexpected real packet before the end"),
            }
        }
    }

    #[test]
    fn zero_junk_packets_produces_only_real_packet() {
        let config = ObfuscationConfig {
            junk_packet_count: 0,
            junk_min_size: 40,
            junk_max_size: 100,
        };
        let plan = plan_handshake_send_sequence(&config, &[]);
        assert_eq!(plan, vec![SendStep::RealHandshakePacket]);
    }
}
