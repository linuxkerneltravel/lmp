use anyhow::Result;
use serde::Deserialize;
use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::Path,
    time::Duration,
};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: Global,
    pub matching: Matching,
    pub matched: Matched,
    pub unmatched: Unmatched,
    pub cache: Cache,
}

#[derive(Debug, Deserialize)]
pub struct Global {
    pub interface: Option<String>,
    pub log: String,
    pub worker: usize,
    pub loss: f64,
    pub api_listen_at: String,
    #[serde(with = "humantime_serde")]
    pub report_interval: Duration,
}

#[derive(Debug, Deserialize)]
pub struct Matching {
    pub capacity: u64,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
pub struct Matched {
    pub capacity: u64,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

#[derive(Debug, Deserialize)]
pub struct Unmatched {
    pub capacity: u64,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

#[derive(Debug, Deserialize)]
pub struct Cache {
    pub capacity: u64,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

fn default_config() -> &'static str {
    include_str!("../config.toml")
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Config> {
        let toml_str = match File::open(path) {
            Ok(mut file) => {
                let mut toml_str = String::new();
                file.read_to_string(&mut toml_str)?;
                toml_str
            }
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    default_config().to_string()
                } else {
                    Err(e)?
                }
            }
        };
        let config: Config = toml::from_str(&toml_str)?;
        Ok(config)
    }
}
