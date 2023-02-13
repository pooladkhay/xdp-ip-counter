use std::sync::{Arc, Mutex};
use warp::reply::json;
use warp::{http, Filter};

use crate::api::ip_data;
use crate::api::prometheus;
use crate::map::LocalMaps;

pub async fn serve(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
    server_port: u16,
) {
    let lm = local_maps.clone();
    let cp = custom_ports.clone();
    let metrics_route = warp::get()
        .and(warp::path("metrics"))
        .and(warp::any().map(move || lm.clone()))
        .and(warp::any().map(move || cp.clone()))
        .and_then(prometheus_metrics);

    let ips_route = warp::get()
        .and(warp::path("list"))
        .and(warp::any().map(move || local_maps.clone()))
        .and(warp::any().map(move || custom_ports.clone()))
        .and_then(ip_data_list);

    // let not = warp::any()
    //     .map(|| warp::reply::with_status("reply".to_owned(), http::StatusCode::NOT_FOUND));

    let routes = warp::get().and(metrics_route.or(ips_route));

    warp::serve(routes).run(([0, 0, 0, 0], server_port)).await;
}

async fn prometheus_metrics(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match prometheus::generate_mertics(local_maps, custom_ports) {
        Ok(metrics_buffer) => Ok(warp::reply::with_status(
            metrics_buffer,
            http::StatusCode::OK,
        )),
        Err(_) => Ok(warp::reply::with_status(
            "Internal Server Error".to_owned(),
            http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

async fn ip_data_list(
    local_maps: Arc<Mutex<LocalMaps>>,
    custom_ports: Option<Vec<u16>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ip_list = ip_data::generate_list(local_maps, custom_ports);

    Ok(warp::reply::with_status(
        json(&ip_list),
        http::StatusCode::OK,
    ))

    // Ok(warp::reply::with_header(
    //     warp::reply::with_status(metrics_buffer, http::StatusCode::OK),
    //     "Content-Type",
    //     "application/openmetrics-text; version=1.0.0; charset=utf-8",
    // ))
}
