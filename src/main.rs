use axum::{http::StatusCode, response::Html};

async fn handle_index() -> Result<Html<String>, (StatusCode, String)> {
    Ok(Html("Hello!".to_string()))
}

#[tokio::main]
async fn main() {
    let app = axum::Router::new().route("/", axum::routing::get(handle_index));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7743")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
