use axum::{http::StatusCode, response::Html};
use color_eyre::{Result, eyre::Context};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

#[derive(Deserialize, Debug)]
struct ClientConfig {
    client_secret: String,
    redirect_uris: Vec<String>,
}

struct AppState {
    clients: std::collections::HashMap<String, ClientConfig>,
}

async fn handle_index() -> Result<Html<String>, (StatusCode, String)> {
    Ok(Html("Hello!".to_string()))
}

fn load_config(path: &str) -> Result<std::collections::HashMap<String, ClientConfig>> {
    let file = File::open(path).wrap_err_with(|| format!("Failed to open config {}", path))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).wrap_err_with(|| format!("Failed to parse config {}", path))
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let config = load_config("./config.json")?;
    let app_state = Arc::new(AppState { clients: config });
    let app = axum::Router::new()
        .with_state(app_state)
        .route("/", axum::routing::get(handle_index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7743")
        .await
        .unwrap();
    Ok(axum::serve(listener, app).await?)
}
