
use std::{collections::HashMap, net::IpAddr};

use actix_web::{web::Data, App, HttpServer};
use clap::Parser;
use async_channel::{unbounded, Sender, Receiver};
use serde::{Deserialize, Serialize};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
mod tun;
mod ws;
mod fw;
// Map client IP -> per-client outbound channel to WS
pub type ClientRegistry = std::sync::Arc<tokio::sync::RwLock<HashMap<IpAddr, async_channel::Sender<Vec<u8>>>> >;

// Message from a WebSocket client headed to the TUN device
#[derive(Clone, Debug)]
pub struct WsToTunPacket {
    pub client_ip: IpAddr,
    pub data: Vec<u8>,
}
#[derive(Parser, Debug, Serialize, Deserialize, Clone)]
pub struct Args{
    #[clap(short, long, default_value = "8080")]
    port: u16,
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    #[clap(short, long, default_value = "info")]
    log_level: String,
    #[clap(short, long, default_value = "tun0")]
    tun_interface_name: String,
    #[clap(short, long, default_value = "eth0")]
    external_interface_name: String,
    #[clap(short, long, default_value = "./httpstun_server.toml")]
    config_file: String,
    #[clap(short, long, default_value = "true")]
    interactive: bool,
    #[clap(short, long, default_value = "10.10.10.1")]
    server_ip: IpAddr,
    #[clap(short, long, default_value = "255.255.255.0")]
    netmask
    : IpAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Client {
    pub name: String,
    pub token : String,
    pub ip : IpAddr
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    server_args: Args,
    clients: Vec<Client>,
}

pub fn parse_config(file_path: &str) -> Option<Config> {
    let config_content = std::fs::read_to_string(file_path).ok()?;
    let config: Config = toml::from_str(&config_content).unwrap();
    Some(config)
}

pub fn override_config_with_args(mut config: Config, args: &Args) -> Config {
    config.server_args = args.clone();
    config
}

pub fn restart_server(config: &Config) {
    cleanup(config);
    // call exec to restart the server
    nix::unistd::execv(
        &std::ffi::CString::new(std::env::current_exe().unwrap().to_str().unwrap()).unwrap(),
        &[
            std::ffi::CString::new(std::env::current_exe().unwrap().to_str().unwrap()).unwrap(),
        ],
    ).expect("Failed to restart the server");
}

pub fn add_client(name: &str, password: &str, ip: IpAddr, config_file_path: &str) {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
    let new_client = Client {
        name: name.to_string(),
        token: password_hash,
        ip,
    };
    let mut config = parse_config(config_file_path).unwrap_or(Config {
        server_args: Args::parse(),
        clients: vec![],
    });
    config.clients.push(new_client);
    let toml_string = toml::to_string(&config).unwrap();
    std::fs::write(config_file_path, toml_string).expect("Unable to write config file");
    println!("Client {} added successfully.", name);
    restart_server(&config);
}

pub fn remove_client(name: &str, config_file_path: &str) {
    let mut config = parse_config(config_file_path).unwrap_or(Config {
        server_args: Args::parse(),
        clients: vec![],
    });
    if  !config.clients.iter().any(|client| client.name == name) {
        println!("Client {} does not exist.", name);
        return;
    }
    config.clients.retain(|client| client.name != name);

    let toml_string = toml::to_string(&config).unwrap();
    std::fs::write(config_file_path, toml_string).expect("Unable to write config file");
    println!("Client {} removed successfully.", name);
    restart_server(&config);
}

pub fn validate_client(name: &str, password: &str, config: &Config) -> bool {
    if let Some(client) = config.clients.iter().find(|c| c.name == name) {
        let parsed_hash = PasswordHash::new(&client.token).unwrap();
        Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
    } else {
        false
    }
}

pub fn is_valid_ip(ip: &IpAddr, config: &Config) -> bool {
    config.clients.iter().any(|c| &c.ip == ip)
}


pub fn prompt_command(_config: &Config) {
    use std::io::{self, Write};
    print!("Enter command (add_client, remove_client, list_clients, shutdown, restart): ");
    io::stdout().flush().unwrap();
    let mut command = String::new();
    io::stdin().read_line(&mut command).unwrap();
    let command = command.trim();
    match command {
        "add_client" => {
            println!("Adding a new client...");
            let mut name = String::new();
            let mut password;
            print!("Enter client name: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            print!("Enter client password: ");
            loop {
                password = rpassword::read_password().unwrap();
                if password.len() < 8 {
                    println!("Password must be at least 8 characters long. Please try again.");
                    print!("Enter client password: ");
                    io::stdout().flush().unwrap();
                } else {
                    break;
                }
            }
            let mut ip = String::new();
            print!("Enter client IP address (e.g., 10.10.10.2, 2001:db8::2): ");
            loop {
                io::stdout().flush().unwrap();
                ip.clear();
                io::stdin().read_line(&mut ip).unwrap();
                let ip = ip.trim();
                if ip.parse::<IpAddr>().is_ok() {
                    add_client(name.trim(), password.trim(), ip.parse().unwrap(), &_config.server_args.config_file);
                    break;
                } else {
                    println!("Invalid IP address format. Please try again.");
                    print!("Enter client IP address (e.g., 10.10.10.2, 2001:db8::2): ");
                }
            }
            add_client(name.trim(), password.trim(), ip.parse().unwrap(), &_config.server_args.config_file);
        }
        "remove_client" => {
            println!("Removing a client...");
            let mut name = String::new();
            print!("Enter client name: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            remove_client(name.trim(), &_config.server_args.config_file);
        }
        "list_clients" => {
            println!("Listing clients...");
            for client in &_config.clients {
                println!("Client Name: {}, Token: {}", client.name, client.token);
            }
        }
        "shutdown" => {
            println!("Shutting down the server...");
            std::process::exit(0);
        }
        "restart" => {
            println!("Restarting the server...");
            restart_server(&_config);
        }
        _ => {
            println!("Unknown command: {}", command);
            println!("Available commands: add_client, remove_client, list_clients, shutdown, restart");
        }
    }
}

pub fn cleanup(config : &Config) {
    if let Err(e) = fw::remove_masquerade_rule(&config.server_args.tun_interface_name, &config.server_args.external_interface_name) {
        eprintln!("Failed to remove iptables masquerade rule: {}", e);
    } else {
        println!("Removed iptables masquerade rule.");
    }
} 

pub fn setup_signal_handlers(config : &Config) {
    let mut signals = signal_hook::iterator::Signals::new(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]).expect("Failed to set up signal handlers");
    let config = config.clone();
    std::thread::spawn(move || {
        for signal in signals.forever() {
            match signal {
                signal_hook::consts::SIGINT | signal_hook::consts::SIGTERM => {
                    println!("Received termination signal. Shutting down...");
                    cleanup(&config);
                    std::process::exit(0);
                }
                signal_hook::consts::SIGHUP => {
                    println!("Received SIGHUP. Restarting server...");
                    restart_server(&config);
                }
                _ => unreachable!(),
            }
        }
    });
}

use log::info;
#[tokio::main]
async fn main() -> std::io::Result<()> {
    
    let args = Args::parse();
    let config = match parse_config(&args.config_file) {
        Some(cfg) => override_config_with_args(cfg, &args),
        None => {
            info!("Failed to parse config file, using command line arguments only.");
            Config {
                server_args: args.clone(),
                clients: vec![],
            }
        }
    };
    let mut env_log_builder = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.server_args.log_level));
    env_log_builder.init();



    let server_address = format!("{}:{}", config.server_args.host, config.server_args.port);
    println!("Starting server at http://{}", server_address);
    let confclone = config.clone();
    let (wstx, wsrx): (Sender<WsToTunPacket>, Receiver<WsToTunPacket>) = unbounded();
    // Global client registry for routing TUN->WS traffic per client
    let registry: ClientRegistry = std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let registry_for_http = registry.clone();
    tokio::spawn(async move {
        HttpServer::new(move || {
            App::new()
                .app_data(Data::new(confclone.clone()))
                .app_data(Data::new(wstx.clone()))
                .app_data(Data::new(registry_for_http.clone()))
                .service(ws::tun_service)
        })
        .bind(server_address)
        .expect("Can not bind to port")
        .run()
        .await
        .expect("Failed to run server");
    });
    let confclone = config.clone();
    let registry_for_tun = registry.clone();
    tokio::spawn(async move {
        tun::run_tun(wsrx, registry_for_tun, &confclone).await.expect("TUN handler failed");
    });
    // parse client commands, adding and deleting clients, shutdown, restart.
    loop {
        if config.server_args.interactive {
            prompt_command(&config);
        } else {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}