use std::net::Ipv4Addr;
use std::path::Path;
use eyre::Context;

pub const CONFIG_FILE_NAME: &str = "game_vpn.json";

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub server_address: Ipv4Addr,
    pub server_port: u16,
    pub debug: DebugConfig,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DebugConfig {
    pub console: bool,
    pub file_log: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            console: false,
            file_log: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_address: Ipv4Addr::LOCALHOST,
            server_port: 5000,
            debug: Default::default(),
        }
    }
}

pub fn create_initial_config(directory: impl AsRef<Path>) -> eyre::Result<()> {
    let default_conf = Config::default();
    let path = directory.as_ref().join(CONFIG_FILE_NAME);

    if !path.exists() {
        let mut file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(&mut file, &default_conf)?;
    }

    Ok(())
}

pub fn overwrite_config(directory: impl AsRef<Path>) -> eyre::Result<Config> {
    let default_conf = Config::default();
    let path = directory.as_ref().join(CONFIG_FILE_NAME);
    let mut file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(&mut file, &default_conf)?;

    Ok(default_conf)
}

pub fn load_config(directory: impl AsRef<Path>) -> eyre::Result<Config> {
    let file = std::fs::read(directory.as_ref().join(CONFIG_FILE_NAME))?;
    let conf = serde_json::from_slice(&file).or_else(|_| overwrite_config(directory)).context("Failed to read/overwrite config file, is it valid?")?;

    Ok(conf)
}