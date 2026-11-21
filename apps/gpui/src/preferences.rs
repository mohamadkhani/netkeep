//! GUI preferences that are not daemon policy.
//!
//! The decision dialog runs as a separate process for every pending decision,
//! so a toggle in the settings window only reaches it through a file. Keep
//! this file small: it is read synchronously at dialog startup.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preferences {
    /// Ask RDAP which network owns an IP-only destination.
    ///
    /// Off by default: the lookup tells a third party which address the
    /// machine contacted.
    #[serde(default)]
    pub network_lookup: bool,
    #[serde(default)]
    version: u32,
}

impl Preferences {
    pub fn load() -> Self {
        Self::load_from(&config_path())
    }

    pub fn load_from(path: &Path) -> Self {
        let Ok(bytes) = fs::read(path) else {
            return Self::default();
        };
        let mut prefs: Preferences = serde_json::from_slice(&bytes).unwrap_or_default();
        if prefs.version == 0 {
            prefs.version = FORMAT_VERSION;
        }
        prefs
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create config dir: {e}"))?;
        }
        let mut value = self.clone();
        value.version = FORMAT_VERSION;
        let bytes =
            serde_json::to_vec_pretty(&value).map_err(|e| format!("serialize preferences: {e}"))?;
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&tmp, bytes).map_err(|e| format!("write preferences: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("replace preferences: {e}")
        })
    }
}

/// `$XDG_CONFIG_HOME/netkeep/gui.json`, or `~/.config/netkeep/gui.json`.
/// `NETKEEP_GUI_CONFIG` overrides the exact path.
pub fn config_path() -> PathBuf {
    if let Ok(path) = env::var("NETKEEP_GUI_CONFIG") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(base) = env::var("XDG_CONFIG_HOME") {
        if !base.is_empty() {
            return PathBuf::from(base).join("netkeep").join("gui.json");
        }
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config/netkeep/gui.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_means_network_lookup_is_off() {
        let dir =
            std::env::temp_dir().join(format!("netkeep-prefs-missing-{}", std::process::id()));
        let path = dir.join("missing.json");
        assert!(!Preferences::load_from(&path).network_lookup);
    }

    #[test]
    fn round_trips_the_opt_in() {
        let dir =
            std::env::temp_dir().join(format!("netkeep-prefs-roundtrip-{}", std::process::id()));
        let path = dir.join("gui.json");
        let prefs = Preferences {
            network_lookup: true,
            version: FORMAT_VERSION,
        };
        prefs.save_to(&path).unwrap();
        assert_eq!(Preferences::load_from(&path), prefs);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unknown_or_partial_file_keeps_lookup_off() {
        let dir =
            std::env::temp_dir().join(format!("netkeep-prefs-partial-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gui.json");
        fs::write(&path, br#"{"something_else": true}"#).unwrap();
        assert!(!Preferences::load_from(&path).network_lookup);
        let _ = fs::remove_dir_all(dir);
    }
}
