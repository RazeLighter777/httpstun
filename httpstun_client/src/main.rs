use clap::Parser;
use serde::{Serialize, Deserialize};
use std::path::Path;
use log::{info, warn, error};
use futures_util::{StreamExt, SinkExt};
use tappers::{Interface, DeviceState, tokio::AsyncTun};
use reqwest_websocket::{Message, RequestBuilderExt};
use std::time::Duration;

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct Args {
    #[clap(long, default_value = "ws://127.0.0.1:8080/")]
    /// Server base URL (must include scheme and trailing slash)
    server_url: String,
    #[clap(long, default_value = "client1")]
    /// Client name for auth header
    client_name: String,
    #[clap(long, default_value = "changeme123")]
    /// Client password (will be sent to server for Argon2 verification)
    client_password: String,
    #[clap(long, default_value = "tun0")]
    /// Local TUN interface name
    tun_interface_name: String,
    #[clap(long, default_value = "./httpstun_client.toml")]
    /// Path to client config file
    config_file: String,
    #[clap(long, default_value = "info")]
    /// Log level
    log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub client_args: Args,
}

fn parse_config(path: &str) -> Option<Config> {
    if !Path::new(path).exists() { return None; }
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}

fn override_config(mut config: Config, args: &Args) -> Config { config.client_args = args.clone(); config }

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let config = match parse_config(&args.config_file) { Some(c)=> override_config(c,&args), None => Config{ client_args: args.clone() } };
    let mut env_log_builder = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.client_args.log_level));
    env_log_builder.init();
    println!("httpstun_client starting. Will connect to {} as {}", config.client_args.server_url, config.client_args.client_name);
    // Create / open TUN interface
    let tap_name = Interface::new(config.client_args.tun_interface_name.clone())
        .unwrap_or_else(|_| {
            eprintln!("Failed to create interface with name {}, trying default name", config.client_args.tun_interface_name);
            Interface::new("tun0").unwrap()
        });
    let mut tap = match AsyncTun::new_named(tap_name) { Ok(t)=> t, Err(e)=> { error!("Failed to open tap: {e:?}"); return; } };
    if let Err(e) = tap.set_state(DeviceState::Up) { error!("Failed to set device up: {e:?}"); }

    // Reconnect loop
    loop {
        match connect_and_run(&config, &mut tap).await {
            Ok(()) => {
                info!("Connection closed gracefully, retrying in 5s");
            }
            Err(e) => {
                warn!("Connection error: {e:?}, retrying in 5s");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn connect_and_run(config: &Config, tap: &mut AsyncTun) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = config.client_args.server_url.clone();
    info!("Connecting to server {url}");
    let client = reqwest::Client::new();
    let mut ws = client.get(url)
        .header("X-Httpstun-Client-Name", &config.client_args.client_name)
        .header("X-Httpstun-Client-Password", &config.client_args.client_password)
        .upgrade()
        .send()
        .await?
        .into_websocket()
        .await?;
    info!("WebSocket established");
    let mut tap_buf = [0u8; 9000];
    loop {
        tokio::select! {
            ws_msg = ws.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(bin))) => {
                        if let Err(e) = tap.send(&bin).await { warn!("Failed sending to tap: {e:?}"); }
                    }
                    Some(Ok(Message::Ping(p))) => { ws.send(Message::Pong(p)).await?; }
                    Some(Ok(Message::Close { code: _, reason: _ })) => { info!("Server closed connection"); return Ok(()); }
                    Some(Ok(_)) => { /* ignore other frames */ }
                    Some(Err(e)) => { return Err(Box::new(e)); }
                    None => return Ok(()),
                }
            }
            tap_read = tap.recv(&mut tap_buf) => {
                match tap_read {
                    Ok(sz) => {
                        let packet = &tap_buf[..sz];
                        if let Err(e) = ws.send(Message::Binary(packet.to_vec().into())).await { return Err(Box::new(e)); }
                    }
                    Err(e) => { warn!("Tap read error: {e:?}"); return Err(Box::new(e)); }
                }
            }
        }
    }
}
