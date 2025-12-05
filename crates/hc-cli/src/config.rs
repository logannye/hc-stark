use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Preset {
    pub block_size: Option<usize>,
    pub auto_block: Option<bool>,
    pub trace_length: Option<usize>,
    pub target_rss_mb: Option<usize>,
    pub profile: Option<String>,
    pub hardware_detect: Option<bool>,
    pub tuner_cache: Option<String>,
    pub disable_tuner_cache: Option<bool>,
    pub commitment: Option<String>,
    pub metrics_dir: Option<PathBuf>,
    pub metrics_tag: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub presets: HashMap<String, Preset>,
}

pub fn load_file_config(path: Option<&Path>) -> FileConfig {
    if let Some(path) = resolve_config_path(path) {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&contents) {
                return cfg;
            }
        }
    }
    FileConfig::default()
}

fn resolve_config_path(path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = path {
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    let default = Path::new(".hc-cli.toml");
    if default.exists() {
        return Some(default.to_path_buf());
    }
    None
}

pub fn lookup_preset(cfg: &FileConfig, name: &str) -> Option<Preset> {
    if let Some(custom) = cfg.presets.get(name) {
        return Some(custom.clone());
    }
    builtin_preset(name)
}

fn builtin_preset(name: &str) -> Option<Preset> {
    match name {
        "balanced" => Some(Preset::default()),
        "memory" => Some(Preset {
            auto_block: Some(true),
            target_rss_mb: Some(256),
            profile: Some("memory".into()),
            hardware_detect: Some(false),
            ..Preset::default()
        }),
        "latency" => Some(Preset {
            auto_block: Some(true),
            target_rss_mb: Some(768),
            profile: Some("latency".into()),
            hardware_detect: Some(false),
            ..Preset::default()
        }),
        "laptop" => Some(Preset {
            auto_block: Some(true),
            target_rss_mb: Some(256),
            trace_length: Some(1 << 20),
            profile: Some("balanced".into()),
            hardware_detect: Some(true),
            ..Preset::default()
        }),
        "server" => Some(Preset {
            auto_block: Some(true),
            target_rss_mb: Some(2048),
            trace_length: Some(1 << 22),
            profile: Some("latency".into()),
            hardware_detect: Some(true),
            ..Preset::default()
        }),
        _ => None,
    }
}
