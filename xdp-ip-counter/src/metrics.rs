use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Receiver;

use crate::structs::LocalMap;

pub async fn generate(
    local_map: Arc<Mutex<LocalMap>>,
    custom_ports: Option<Vec<u16>>,
    mut rx: Receiver<bool>,
) {
    while let Some(message) = rx.recv().await {
        if message {
            println!("GOT = {}", message)
        }
    }
}
