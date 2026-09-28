//! 秘密鍵・公開鍵の保存先(ドライブ/ディレクトリ)を利用者が選択できる仕組み
//! (実装フェーズ6)。
//!
//! [`CLAUDE.md`]「鍵管理方針」のとおり、鍵の実際の値はチャットに貼り付けたり
//! 表示したりせず、**ローカルドライブ上のファイル**として管理する。この
//! モジュールはその保存先を固定パスに決め打ちせず、**利用者が指定した
//! 任意のディレクトリ(別ドライブでも可)**を使えるようにする。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// 鍵の保存先ディレクトリの設定。`directory`は利用者が選択した任意の
/// パス(例: `D:\my-keys`、`F:\aruaru-vpn\secrets`等、ドライブも自由)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStorageConfig {
    pub directory: PathBuf,
}

impl KeyStorageConfig {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn private_key_path(&self, peer_name: &str) -> PathBuf {
        self.directory.join(format!("{peer_name}.private.key"))
    }

    fn public_key_path(&self, peer_name: &str) -> PathBuf {
        self.directory.join(format!("{peer_name}.public.key"))
    }
}

/// 保存に失敗した理由。
#[derive(Debug)]
pub enum SaveError {
    Io(io::Error),
    /// 既に鍵ファイルが存在し、`overwrite: false`で呼ばれた場合
    /// (鍵の誤上書きによる消失事故を防ぐための安全策)。
    AlreadyExists(PathBuf),
}

impl From<io::Error> for SaveError {
    fn from(e: io::Error) -> Self {
        SaveError::Io(e)
    }
}

/// 指定した`config.directory`(利用者が選んだドライブ/ディレクトリ)に、
/// `peer_name`に対応する秘密鍵・公開鍵ファイルを保存する。
///
/// ディレクトリが存在しなければ作成する。既に同名の鍵ファイルがある場合、
/// `overwrite = false`ならエラーにする(意図しない上書き・鍵の紛失を防ぐ)。
/// **鍵の値そのものはこの関数の戻り値・ログに一切含めない**(戻すのは
/// 保存先の`PathBuf`のみ)。
pub fn save_keypair(
    config: &KeyStorageConfig,
    peer_name: &str,
    private_key: &[u8],
    public_key: &[u8],
    overwrite: bool,
) -> Result<(PathBuf, PathBuf), SaveError> {
    fs::create_dir_all(&config.directory)?;

    let private_path = config.private_key_path(peer_name);
    let public_path = config.public_key_path(peer_name);

    if !overwrite {
        if private_path.exists() {
            return Err(SaveError::AlreadyExists(private_path));
        }
        if public_path.exists() {
            return Err(SaveError::AlreadyExists(public_path));
        }
    }

    fs::write(&private_path, private_key)?;
    fs::write(&public_path, public_key)?;

    Ok((private_path, public_path))
}

/// 指定した保存先から秘密鍵を読み込む。
pub fn load_private_key(config: &KeyStorageConfig, peer_name: &str) -> io::Result<Vec<u8>> {
    fs::read(config.private_key_path(peer_name))
}

/// 指定した保存先から公開鍵を読み込む。
pub fn load_public_key(config: &KeyStorageConfig, peer_name: &str) -> io::Result<Vec<u8>> {
    fs::read(config.public_key_path(peer_name))
}

/// `peer_name`に対応する鍵ファイルが、指定した保存先に既に存在するかどうか。
pub fn keypair_exists(config: &KeyStorageConfig, peer_name: &str) -> bool {
    config.private_key_path(peer_name).exists() && config.public_key_path(peer_name).exists()
}

/// 保存先が実際に書き込み可能かどうかを、利用者が選択したディレクトリを
/// 確定する前に確認するためのヘルパー(存在しなければ作成を試み、
/// 作成・書き込み権限を検証する)。実際の鍵は書き込まない。
pub fn verify_directory_is_usable(directory: &Path) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    let probe_path = directory.join(".aruaru-vpn-write-check");
    fs::write(&probe_path, b"ok")?;
    fs::remove_file(&probe_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト専用の一時ディレクトリ(OSの一時領域内、実際の利用者データとは
    /// 無関係)を作る。「利用者が選んだ任意のドライブ/ディレクトリ」を
    /// 模擬するためのテストヘルパー。
    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("aruaru-vpn-test-{name}-{}", std::process::id()));
        dir
    }

    #[test]
    fn save_and_load_round_trip_recovers_the_same_keys() {
        let dir = temp_dir("roundtrip");
        let config = KeyStorageConfig::new(&dir);

        let (priv_path, pub_path) =
            save_keypair(&config, "peer-a", b"private-bytes", b"public-bytes", false)
                .expect("save must succeed on a fresh directory");
        assert!(priv_path.starts_with(&dir));
        assert!(pub_path.starts_with(&dir));

        let loaded_private =
            load_private_key(&config, "peer-a").expect("private key must be readable back");
        let loaded_public =
            load_public_key(&config, "peer-a").expect("public key must be readable back");

        assert_eq!(loaded_private, b"private-bytes");
        assert_eq!(loaded_public, b"public-bytes");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn different_configs_select_different_drives_or_directories() {
        let dir_a = temp_dir("dir-a");
        let dir_b = temp_dir("dir-b");
        let config_a = KeyStorageConfig::new(&dir_a);
        let config_b = KeyStorageConfig::new(&dir_b);

        save_keypair(&config_a, "peer", b"priv-a", b"pub-a", false).unwrap();
        save_keypair(&config_b, "peer", b"priv-b", b"pub-b", false).unwrap();

        assert_eq!(load_private_key(&config_a, "peer").unwrap(), b"priv-a");
        assert_eq!(load_private_key(&config_b, "peer").unwrap(), b"priv-b");

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn refuses_to_overwrite_existing_keys_by_default() {
        let dir = temp_dir("no-overwrite");
        let config = KeyStorageConfig::new(&dir);

        save_keypair(&config, "peer", b"first", b"first-pub", false).unwrap();
        let result = save_keypair(&config, "peer", b"second", b"second-pub", false);

        assert!(matches!(result, Err(SaveError::AlreadyExists(_))));
        // 上書きされていないことも確認する。
        assert_eq!(load_private_key(&config, "peer").unwrap(), b"first");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrite_true_replaces_existing_keys() {
        let dir = temp_dir("overwrite-ok");
        let config = KeyStorageConfig::new(&dir);

        save_keypair(&config, "peer", b"first", b"first-pub", false).unwrap();
        save_keypair(&config, "peer", b"second", b"second-pub", true)
            .expect("overwrite=true must succeed even when the key already exists");

        assert_eq!(load_private_key(&config, "peer").unwrap(), b"second");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn keypair_exists_reflects_actual_files() {
        let dir = temp_dir("exists-check");
        let config = KeyStorageConfig::new(&dir);

        assert!(!keypair_exists(&config, "peer"));
        save_keypair(&config, "peer", b"p", b"pub", false).unwrap();
        assert!(keypair_exists(&config, "peer"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_directory_is_usable_creates_missing_directories() {
        let dir = temp_dir("verify-usable");
        assert!(!dir.exists());
        verify_directory_is_usable(&dir).expect("a fresh, writable path must be usable");
        assert!(dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
