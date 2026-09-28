//! 鍵管理GUI(実装フェーズ12)。
//!
//! [`aruaru_vpn::key_storage`]を使い、利用者が任意のドライブ/ディレクトリを
//! ファイルピッカーで選び、REALITYサーバーの長期鍵ペアを生成・保存できる
//! ネイティブGUI([egui](https://github.com/emilk/egui)/`eframe`、ファイル
//! ピッカーは[rfd](https://github.com/PolyMeilex/rfd))。
//!
//! **鍵の値そのものはこの画面に一切表示しない**(`CLAUDE.md`「鍵管理方針」
//! `feedback_keys_via_files_never_echo`メモリのとおり)。表示するのは保存先
//! パスと、公開鍵のみ(公開鍵は他者に渡す前提の値であり、秘匿情報ではない)。

use std::path::PathBuf;

use aruaru_vpn::key_storage::{self, KeyStorageConfig, SaveError};
use aruaru_vpn::reality_auth::ServerIdentity;

struct KeysApp {
    directory: Option<PathBuf>,
    peer_name: String,
    overwrite: bool,
    status: String,
    last_public_key_hex: Option<String>,
}

impl Default for KeysApp {
    fn default() -> Self {
        Self {
            directory: None,
            peer_name: "server".to_owned(),
            overwrite: false,
            status: String::new(),
            last_public_key_hex: None,
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl eframe::App for KeysApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("aruaru-vpn 鍵管理");

            ui.separator();
            ui.label("保存先ディレクトリ(任意のドライブ可):");
            ui.horizontal(|ui| {
                let shown = self
                    .directory
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(未選択)".to_owned());
                ui.monospace(shown);
                if ui.button("フォルダを選択…").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        match key_storage::verify_directory_is_usable(&dir) {
                            Ok(()) => {
                                self.status =
                                    format!("保存先を確認しました: {}", dir.display());
                                self.directory = Some(dir);
                            }
                            Err(e) => {
                                self.status =
                                    format!("この保存先には書き込めません: {e}");
                            }
                        }
                    }
                }
            });

            ui.separator();
            ui.label("識別名(peer_name、鍵ファイル名に使われます):");
            ui.text_edit_singleline(&mut self.peer_name);
            ui.checkbox(&mut self.overwrite, "既存の鍵を上書きする");

            ui.separator();
            let can_generate = self.directory.is_some() && !self.peer_name.trim().is_empty();
            if ui
                .add_enabled(can_generate, egui::Button::new("鍵ペアを生成して保存"))
                .clicked()
            {
                let directory = self.directory.clone().expect("checked by can_generate");
                let config = KeyStorageConfig::new(directory);

                let seed: [u8; 32] = rand::random();
                let identity = ServerIdentity::generate(seed);
                let public_key_bytes = identity.public_key().to_bytes();

                // 秘密鍵はseedそのもの(`ServerIdentity::generate`が受け取る
                // 32バイト)。この値はファイルにのみ書き込み、画面には出さない。
                match key_storage::save_keypair(
                    &config,
                    self.peer_name.trim(),
                    &seed,
                    &public_key_bytes,
                    self.overwrite,
                ) {
                    Ok((priv_path, pub_path)) => {
                        self.status = format!(
                            "保存しました:\n秘密鍵: {}\n公開鍵: {}",
                            priv_path.display(),
                            pub_path.display()
                        );
                        self.last_public_key_hex = Some(to_hex(&public_key_bytes));
                    }
                    Err(SaveError::AlreadyExists(path)) => {
                        self.status = format!(
                            "既に鍵ファイルが存在します(上書きするにはチェックを入れてください): {}",
                            path.display()
                        );
                    }
                    Err(SaveError::Io(e)) => {
                        self.status = format!("保存に失敗しました: {e}");
                    }
                }
            }

            if let Some(hex) = &self.last_public_key_hex {
                ui.separator();
                ui.label("公開鍵(他者と共有してよい値):");
                ui.horizontal(|ui| {
                    ui.monospace(hex);
                    if ui.button("コピー").clicked() {
                        ui.ctx().copy_text(hex.clone());
                    }
                });
            }

            ui.separator();
            ui.colored_label(egui::Color32::LIGHT_BLUE, &self.status);
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "aruaru-vpn 鍵管理",
        options,
        Box::new(|_cc| Ok(Box::new(KeysApp::default()))),
    )
}
