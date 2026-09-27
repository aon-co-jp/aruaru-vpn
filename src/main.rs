mod amnezia;
mod integration;
mod reality;
mod tls_clienthello;

use amnezia::{plan_handshake_send_sequence, ObfuscationConfig};
use integration::{CpuOnlyCryptoAccelerator, CryptoAccelerator, NoOpTrafficShaper, TrafficShaper};
use reality::{decide_connection_action, ConnectionAction, RealityAuthChecker};

fn main() {
    let checker = RealityAuthChecker::new([b"example-short-id".to_vec()]);
    let action = decide_connection_action(&checker, b"example-short-id", "www.microsoft.com");
    match action {
        ConnectionAction::Relay => println!("authenticated: proceed as VLESS+REALITY proxy"),
        ConnectionAction::Fallback { camouflage_target } => {
            println!("unauthenticated: fall back to {camouflage_target}")
        }
    }

    let shaper = NoOpTrafficShaper;
    println!("traffic shaping hint: {:?}", shaper.shape(1200));

    let accel = CpuOnlyCryptoAccelerator;
    println!(
        "GPU available (open-cuda not yet connected): {}",
        accel.gpu_available()
    );

    let obfuscation = ObfuscationConfig {
        junk_packet_count: 4,
        junk_min_size: 40,
        junk_max_size: 150,
    };
    obfuscation.validate().expect("valid obfuscation config");
    let plan = plan_handshake_send_sequence(&obfuscation, &[0.1, 0.4, 0.7, 0.9]);
    println!("AmneziaWG-style send plan: {plan:?}");
}
