use std::sync::{Arc, Mutex};
use warp::reply::json;
use warp::{http, Filter};

use crate::api::prometheus;
use crate::structs::LocalMap;

pub async fn serve(local_map: Arc<Mutex<LocalMap>>, server_port: u16, serve_ip_list: bool) {
    let lm1 = local_map.clone();
    let lm2 = local_map.clone();

    let metrics_route = warp::get()
        .and(warp::path("metrics"))
        .and(warp::any().map(move || lm1.clone()))
        .and_then(prometheus_metrics);

    if serve_ip_list {
        let ips_route = warp::get()
            .and(warp::path("list"))
            .and(warp::any().map(move || lm2.clone()))
            .and_then(ip_data_list);

        let routes = warp::get().and(metrics_route.or(ips_route));
        warp::serve(routes).run(([0, 0, 0, 0], server_port)).await;
    } else {
        warp::serve(metrics_route)
            .run(([0, 0, 0, 0], server_port))
            .await;
    }
}

async fn prometheus_metrics(
    local_map: Arc<Mutex<LocalMap>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match prometheus::generate_mertics(local_map) {
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
    local_map: Arc<Mutex<LocalMap>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let local_map = local_map
        .lock()
        .expect("unable to accuire lock for local_map");
    let ip_list = local_map.get_ip_list();

    Ok(warp::reply::with_header(
        warp::reply::with_status(json(&ip_list), http::StatusCode::OK),
        "Access-Control-Allow-Origin",
        "http://localhost:3000",
    ))

    // Ok(warp::reply::with_status(
    //     json(&ip_list),
    //     http::StatusCode::OK,
    // ))
}
