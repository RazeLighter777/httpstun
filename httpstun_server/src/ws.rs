use actix_web::{get, rt, web, Error, HttpRequest, HttpResponse};
use actix_ws::AggregatedMessage;
use futures_util::StreamExt as _;
use log::{warn, debug};

use crate::{ClientRegistry, Config, WsToTunPacket};

#[get("/")]
async fn tun_service(req: HttpRequest, stream: web::Payload, web_tx: web::Data<async_channel::Sender<WsToTunPacket>>, registry: web::Data<ClientRegistry>, config : web::Data<Config>) -> Result<HttpResponse, Error> {
    // get client name and password from headers
    let client_name = if let Some(name) = req.headers().get("X-Httpstun-Client-Name") {
        name.to_str().unwrap_or("")
    } else {
        ""
    };
    let client_password = if let Some(password) = req.headers().get("X-Httpstun-Client-Password") {
        password.to_str().unwrap_or("")
    } else {
        ""
    };
    if !crate::validate_client(client_name, client_password, &config) {
        //404 against RFC to avoid leaking info
        warn!("Invalid client name or password from {}", req.peer_addr().map(|a| a.to_string()).unwrap_or("unknown".to_string()));
        return Ok(HttpResponse::NotFound().finish());

    }
    // find client's assigned IP
    let client_ip = match config.clients.iter().find(|c| c.name == client_name) {
        Some(c) => c.ip,
        None => {
            // Should not happen if validate_client passed
            return Ok(HttpResponse::NotFound().finish());
        }
    };
    let (res, session, stream) = actix_ws::handle(&req, stream)?;

    let stream = stream
        .aggregate_continuations()
        // aggregate continuation frames up to 1MiB
        .max_continuation_size(2_usize.pow(20));

    // start task but don't wait for it
    let registry_for_task = registry.clone();
    rt::spawn(async move {
        // Create per-client channel and register
        let (client_tx, client_rx) = async_channel::unbounded::<Vec<u8>>();
        {
            let mut map = registry_for_task.write().await;
            map.insert(client_ip, client_tx.clone());
            debug!("Registered client {}", client_ip);
        }
        // Task 1: receive messages from websocket and forward to TUN handler
        let web_tx_clone = web_tx.clone();
        let mut session_clone = session.clone();
        let mut stream_recv = stream;
        let recv_task = rt::spawn(async move {
            while let Some(msg) = stream_recv.next().await {
                match msg {
                    Ok(AggregatedMessage::Text(text)) => {
                        //shouldn't happen
                        warn!("Received unexpected text message: {}", text);
                        return;
                    }
                    Ok(AggregatedMessage::Binary(bin)) => {
                        // forward binary message to TUN handler with the authenticated client IP
                        let pkt = WsToTunPacket { client_ip, data: bin.to_vec() };
                        if let Err(e) = web_tx_clone.send(pkt).await {
                            warn!("Failed to send message to TUN handler: {}", e);
                            return;
                        }
                    }
                    Ok(AggregatedMessage::Ping(msg)) => {
                        // respond to PING frame with PONG frame
                        session_clone.pong(&msg).await.unwrap();
                    }
                    _ => {}
                }
            }
        });

        // Task 2: receive messages from TUN handler and forward to websocket client
        let mut session_send = session;
        let client_rx = client_rx.clone();
        let send_task = rt::spawn(async move {
            while let Ok(bin) = client_rx.recv().await {
                if let Err(e) = session_send.binary(bin).await {
                    warn!("Failed to send binary message to client: {}", e);
                    return;
                }
            }
        });

        // Wait for either task to finish, then cleanup
        let _ = futures_util::future::select(recv_task, send_task).await;
        {
            let mut map = registry_for_task.write().await;
            map.remove(&client_ip);
            debug!("Unregistered client {}", client_ip);
        }
    });

    // respond immediately with response connected to WS session
    Ok(res)
}
