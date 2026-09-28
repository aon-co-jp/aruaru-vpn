//! 実装フェーズ12: `src/bin/keys_gui.rs`(鍵管理GUI)が`key_storage`等の
//! モジュールを再利用できるよう、ライブラリターゲットとして公開する
//! (それまでは`main.rs`のみのバイナリクレートだった)。

pub mod amnezia;
pub mod integration;
pub mod key_storage;
pub mod net;
pub mod reality;
pub mod reality_auth;
pub mod secure_channel;
pub mod tls_clienthello;
pub mod tls_terminate;
pub mod vless;
pub mod wireguard_handshake;
