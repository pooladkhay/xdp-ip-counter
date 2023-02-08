use std::sync::{Arc, Mutex};
use warp::{http, Filter};

use crate::map::LocalMaps;
use crate::prometheus;

pub async fn serve_metrics(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
    server_port: u16,
) {
    let metrics_route = warp::get()
        .and(warp::path("metrics"))
        .and(warp::any().map(move || local_maps.clone()))
        .and(warp::any().map(move || custom_ports.clone()))
        .and_then(metrics_handler);

    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], server_port))
        .await;
}

async fn metrics_handler(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let metrics_buffer = match prometheus::generate_mertics(local_maps, custom_ports) {
        Ok(buf) => buf,
        Err(_) => "".to_string(),
    };

    // Ok(warp::reply::with_header(
    //     warp::reply::with_status(metrics_buffer, http::StatusCode::OK),
    //     "Content-Type",
    //     "application/openmetrics-text; version=1.0.0; charset=utf-8",
    // ))

    Ok(warp::reply::with_status(
        metrics_buffer,
        http::StatusCode::OK,
    ))
}
