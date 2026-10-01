use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub gpu: String,
    pub scan_threads: usize,
    pub update_channel: String,
    #[serde(default = "default_hide_controls")]
    pub hide_controls: String,
}

fn default_hide_controls() -> String { "auto".into() }

impl Default for Settings {
    fn default()->Self{Self{gpu:"auto".into(),scan_threads:scan_thread_limit().min(std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1).max(1)),update_channel:"stable".into(),hide_controls:default_hide_controls()}}
}

/// The user-facing maximum is twice the logical CPU count, with an eight-thread
/// floor for low-core systems.  The actual worker count remains bounded by work.
pub fn scan_thread_limit() -> usize {
    std::thread::available_parallelism().map(|n|n.get().saturating_mul(2)).unwrap_or(8).max(8)
}

fn path()->PathBuf{std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("SilverFoxRescue").join("settings.json")}
pub fn load()->Settings{let p=path();let mut value:Settings=fs::read(&p).ok().and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or_default();value.scan_threads=value.scan_threads.clamp(1,scan_thread_limit());if !matches!(value.hide_controls.as_str(),"auto"|"enabled"|"disabled"){value.hide_controls=default_hide_controls();}value}
pub fn selected_update_channel()->&'static str{match load().update_channel.as_str(){"beta"=>"beta",_=>"stable"}}
pub fn save(value:&Settings)->anyhow::Result<()> {let p=path();if let Some(parent)=p.parent(){fs::create_dir_all(parent)?;}let temp=p.with_extension("pending");fs::write(&temp,serde_json::to_vec_pretty(value)?)?;if fs::rename(&temp,&p).is_err(){fs::remove_file(&p).ok();fs::rename(&temp,&p)?;}Ok(())}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_without_control_preference_default_to_automatic_hiding() {
        let value:Settings=serde_json::from_str(r#"{"gpu":"auto","scan_threads":4,"update_channel":"stable"}"#).unwrap();
        assert_eq!(value.hide_controls,"auto");
    }
}
