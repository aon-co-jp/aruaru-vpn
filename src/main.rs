mod integration;
mod reality;

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
    println!("GPU available (open-cuda not yet connected): {}", accel.gpu_available());
}
