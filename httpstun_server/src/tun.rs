use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use log::{debug, error, warn};
use tappers::{AddAddressV4, AddAddressV6, DeviceState, Interface, tokio::AsyncTun};
use async_channel::Receiver;
use crate::{ClientRegistry, Config, WsToTunPacket};
use etherparse::NetSlice;
use crate::fw;
pub async fn run_tun(wsrx: Receiver<WsToTunPacket>, registry: ClientRegistry, config : &Config) -> io::Result<()> {
    let tap_name = Interface::new(config.server_args.tun_interface_name.clone())?;
    let mut tap = AsyncTun::new_named(tap_name)?;
    // create iptables masquerade rule
    if let Err(e) = fw::create_masquerade_rule(&config.server_args.tun_interface_name, &config.server_args.external_interface_name) {
        error!("Failed to create iptables masquerade rule: {}", e);
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to create iptables rule"));
    }
    // On exit, remove the iptables rule
    //set tun interface IP address
    match config.server_args.server_ip {
        IpAddr::V4(ipv4) => {
            let netmask = match config.server_args.netmask {
                IpAddr::V4(nm) => nm,
                _ => {
                    eprintln!("Server netmask must be an IPv4 address when server IP is IPv4");
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid netmask"));
                }
            };
            let mut add_addr = AddAddressV4::new(ipv4);
            let prefix_len = netmask.octets().iter().map(|&b| b.count_ones()).sum::<u32>();
            add_addr.set_netmask(prefix_len as u8);
            tap.add_addr(add_addr)?;
        }
        IpAddr::V6(ipv6) => {
            let netmask = match config.server_args.netmask {
                IpAddr::V6(nm) => nm,
                _ => {
                    eprintln!("Server netmask must be an IPv6 address when server IP is IPv6");
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid netmask"));
                }
            };
            let mut add_addr = AddAddressV6::new(ipv6);
            let prefix_len = netmask.octets().iter().map(|&b| b.count_ones()).sum::<u32>();
            add_addr.set_netmask(prefix_len as u8);
            tap.add_addr(add_addr)?;
        }
    }
    // Set the interface up
    tap.set_state(DeviceState::Up)?;
    //listen for packets from the tap interface and forward them to the correct websocket client
    let mut tap_packet = [0u8; 9000];
    loop {
        tokio::select! {
            result = tap.recv(&mut tap_packet) => {
                match result {
                    Ok(size) => {
                        debug!("Received packet from TUN: {:?}", &tap_packet[..size]);
                        //parse dst IP to determine which client to send to
                        let pkt = match etherparse::SlicedPacket::from_ip(&tap_packet[..size]) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("Failed to parse packet: {:?}", e);
                                continue;
                            }
                        };
                        let dst = match pkt.net {
                            Some(NetSlice::Ipv4(header)) => IpAddr::V4(Ipv4Addr::from(header.header().destination())),
                            Some(NetSlice::Ipv6(header)) => IpAddr::V6(Ipv6Addr::from(header.header().destination())),
                            _ => {
                                warn!("Unsupported network layer");
                                continue;
                            }
                        };
                        if !crate::is_valid_ip(&dst, config) {
                            warn!("Destination IP {} is not assigned to any client, dropping packet", dst);
                            continue;
                        }
                        // route to the correct client's channel if present
                        let sender_opt = { registry.read().await.get(&dst).cloned() };
                        if let Some(client_tx) = sender_opt {
                            if let Err(e) = client_tx.send(tap_packet[..size].to_vec()).await {
                                warn!("Failed to send packet to client {}: {}", dst, e);
                            }
                        } else {
                            // client not currently connected
                            debug!("No active session for {}, dropping packet", dst);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving from TUN: {:?}", e);
                        break;
                    }
                }
            }
            ws_result = wsrx.recv() => {
                match ws_result {
                    Ok(ws_packet) => {
                        debug!("Received packet from WebSocket for {}: {} bytes", ws_packet.client_ip, ws_packet.data.len());
                        //parse source IP to determine if it's from a valid client
                        let pkt = match etherparse::SlicedPacket::from_ip(&ws_packet.data) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("Failed to parse packet: {:?}", e);
                                continue;
                            }
                        };
                        let src = match pkt.net {
                            Some(NetSlice::Ipv4(header)) => IpAddr::V4(Ipv4Addr::from(header.header().source())),
                            Some(NetSlice::Ipv6(header)) => IpAddr::V6(Ipv6Addr::from(header.header().source())),
                            _ => {
                                warn!("Unsupported network layer");
                                continue;
                            }
                        };
                        // strict check: source must match authenticated client's IP
                        if src != ws_packet.client_ip {
                            warn!("Spoofed packet: src {} != authenticated {}. Dropping.", src, ws_packet.client_ip);
                            continue;
                        }

                        if let Err(e) = tap.send(&ws_packet.data).await {
                            eprintln!("Failed to send packet to TUN: {:?}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("WebSocket channel closed: {:?}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}