//! `aruaru-llm`(AIによる通信パターン擬態)・`open-cuda`(暗号処理/AI推論の
//! GPU高速化)との連携インターフェース。
//!
//! `open-cuda`/`open-directx`は現時点で実体が乏しく(`README.md`「関連
//! リポジトリとの連携」参照)、今すぐ実際の連携実装はできない。そこで、
//! ここでは**契約(トレイト)だけを先に定義**し、既定実装(何もしない
//! フォールバック)を用意する。これにより:
//! - `aruaru-vpn`本体の開発は、`aruaru-llm`/`open-cuda`の成熟を待たずに
//!   進められる(既定実装を使えば動く)。
//! - `aruaru-llm`/`open-cuda`側の実装が育った段階で、このトレイトを実装する
//!   だけで実際の連携に差し替えられる。

use std::time::Duration;

/// 送信するパケットに対して、`aruaru-llm`が提案する「より自然に見える」
/// タイミング・サイズの調整を表す。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrafficShapingHint {
    /// このパケットを送信する前に追加で待つべき時間(検閲側のAIトラフィック
    /// 分類器に対し、機械的に規則正しいパターンに見えないようにする)。
    pub extra_delay: Duration,
    /// パディングとして追加すべきバイト数(パケットサイズの分布を、実際の
    /// 一般的な通信のサイズ分布に近づける)。
    pub padding_bytes: usize,
}

impl TrafficShapingHint {
    pub const NONE: Self = Self {
        extra_delay: Duration::ZERO,
        padding_bytes: 0,
    };
}

/// `aruaru-llm`が提供する予定の「通信パターン擬態」機能の契約。
///
/// 既定実装(`NoOpTrafficShaper`)は何も調整しない。`aruaru-llm`側の実装が
/// 育ったら、このトレイトを実装する新しい型に差し替える。
pub trait TrafficShaper: Send + Sync {
    /// 次に送信するパケット(のサイズ)に対する調整ヒントを返す。
    fn shape(&self, upcoming_packet_len: usize) -> TrafficShapingHint;
}

/// 何も調整しない既定実装(`aruaru-llm`未接続時のフォールバック)。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpTrafficShaper;

impl TrafficShaper for NoOpTrafficShaper {
    fn shape(&self, _upcoming_packet_len: usize) -> TrafficShapingHint {
        TrafficShapingHint::NONE
    }
}

/// `open-cuda`が提供する予定の「暗号処理/AI推論のGPU高速化」機能の契約。
///
/// 既定実装(`CpuOnlyCryptoAccelerator`)はGPUを使わずCPUでそのまま処理する
/// ことを示すだけで、実際の暗号演算はこのトレイトの外(実際のTLS/暗号
/// ライブラリ)で行う想定。ここでは「GPUが使えるかどうか」の問い合わせ
/// 契約のみを定義する。
pub trait CryptoAccelerator: Send + Sync {
    /// GPUによる高速化が利用可能かどうか。
    fn gpu_available(&self) -> bool;
}

/// GPUを使わない既定実装(`open-cuda`未接続時のフォールバック)。
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuOnlyCryptoAccelerator;

impl CryptoAccelerator for CpuOnlyCryptoAccelerator {
    fn gpu_available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_traffic_shaper_never_adjusts() {
        let shaper = NoOpTrafficShaper;
        let hint = shaper.shape(1200);
        assert_eq!(hint, TrafficShapingHint::NONE);
    }

    #[test]
    fn cpu_only_accelerator_reports_no_gpu() {
        let accel = CpuOnlyCryptoAccelerator;
        assert!(!accel.gpu_available());
    }

    /// 将来`aruaru-llm`が実装するトレイト実装を差し替え可能であることの
    /// 確認(トレイトオブジェクトとして扱えることの単体テスト)。
    #[test]
    fn traffic_shaper_can_be_used_as_trait_object() {
        struct FixedDelayShaper;
        impl TrafficShaper for FixedDelayShaper {
            fn shape(&self, _upcoming_packet_len: usize) -> TrafficShapingHint {
                TrafficShapingHint {
                    extra_delay: Duration::from_millis(5),
                    padding_bytes: 16,
                }
            }
        }

        let shaper: Box<dyn TrafficShaper> = Box::new(FixedDelayShaper);
        let hint = shaper.shape(500);
        assert_eq!(hint.padding_bytes, 16);
    }
}
