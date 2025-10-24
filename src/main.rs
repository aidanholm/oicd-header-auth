use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use color_eyre::eyre::ContextCompat;
use color_eyre::{Result, eyre::Context};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex};

/// Name of the header set by the reverse proxy containing the ID of the authenticated user, if
/// any, or not set otherwise.
const AUTH_HEADER_NAME: &str = "x-webauth-user";

#[derive(Deserialize, Debug)]
struct ClientConfig {
    redirect_uris: Vec<String>,
}

#[allow(unused, reason = "Used in next commit.")]
struct TokenState {
    user_id: String,
}

struct AppState {
    /// Map from OAuth client IDs to their configuration.
    /// Not mutated after program startup.
    clients: std::collections::HashMap<String, ClientConfig>,
    /// Map from (token, client ID) to the active user.
    tokens: Mutex<std::collections::HashMap<(String, String), TokenState>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthorizeArgs {
    client_id: String,
    redirect_uri: String,
    state: String,
}

fn url_safe_token() -> String {
    let mut buffer = [0u8; 32];
    // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html#Security
    rand::rng().fill(&mut buffer);
    URL_SAFE.encode(buffer)
}

fn user_id_from_header(headers: &axum::http::HeaderMap) -> color_eyre::Result<String> {
    headers
        .get(AUTH_HEADER_NAME)
        .with_context(|| format!("Missing {AUTH_HEADER_NAME} header"))?
        .to_str()
        .with_context(|| format!("Failed to parse {AUTH_HEADER_NAME} header"))
        .map(|v| v.to_string())
}

async fn handle_authorize(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    query: axum::extract::Query<AuthorizeArgs>,
) -> axum::response::Response {
    let user_id = match user_id_from_header(&headers) {
        Ok(user_id) => user_id,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Validate client_id and redirect_uri parameters. state is passed through.
    let client_config = match state.clients.get(&query.client_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response(),
    };
    if !client_config.redirect_uris.contains(&query.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "Invalid redirect_uri").into_response();
    }

    let token = url_safe_token();
    let redirect_url_with_params =
        format!("{}?code={token}&state={}", query.redirect_uri, query.state);
    state
        .tokens
        .lock()
        .unwrap()
        .insert((token, query.client_id.clone()), TokenState { user_id });
    axum::response::Response::builder()
        .status(302)
        .header("Location", redirect_url_with_params)
        .body(axum::body::Body::empty())
        .unwrap()
}

fn load_config(path: &str) -> Result<std::collections::HashMap<String, ClientConfig>> {
    let file = File::open(path).wrap_err_with(|| format!("Failed to open config {}", path))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).wrap_err_with(|| format!("Failed to parse config {}", path))
}

fn app_from_config_path(config_path: &str) -> Result<Router> {
    let config = load_config(config_path)?;
    let app_state = Arc::new(AppState {
        clients: config,
        tokens: Mutex::new(std::collections::HashMap::new()),
    });
    Ok(axum::Router::new()
        .route("/authorize", axum::routing::get(handle_authorize))
        .with_state(app_state))
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let app = app_from_config_path("./config.json")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7743")
        .await
        .unwrap();
    Ok(axum::serve(listener, app).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asserting::{assert_that, prelude::AssertStringPattern};
    use axum::http::StatusCode;
    use axum_test::TestServer;

    /// Applies request/response modifications done by our reverse proxy.
    async fn proxy(request: axum_test::TestRequest) -> axum_test::TestResponse {
        request
            .add_header(AUTH_HEADER_NAME, "alice@example.com")
            .await
    }

    /// Returns /authorize args that match the hardcoded config.
    fn valid_authorize_args() -> AuthorizeArgs {
        AuthorizeArgs {
            client_id: "foo-client".to_string(),
            redirect_uri: "https://example.com/1".to_string(),
            state: "foo-state".to_string(),
        }
    }

    /// Returns (redirect destination, query parameters).
    fn parse_authorize_response(
        response: axum_test::TestResponse,
    ) -> (String, std::collections::HashMap<String, String>) {
        let redirect_dest = response.header("location").to_str().unwrap().to_string();
        let url = url::Url::parse(&redirect_dest).unwrap();
        (
            redirect_dest.to_string(),
            url.query_pairs().into_owned().collect(),
        )
    }

    #[tokio::test]
    async fn test_authorize_returns_redirect_with_code_and_state() {
        let app = app_from_config_path("./config.json").unwrap();
        let server = TestServer::new(app).unwrap();

        let args = valid_authorize_args();
        let response = proxy(server.get("/authorize").add_query_params(args)).await;
        response.assert_status(StatusCode::FOUND);
        let (redirect_dest, redirect_query_params) = parse_authorize_response(response);

        assert_that!(redirect_dest).starts_with("https://example.com/1?");
        assert!(redirect_query_params.contains_key("code"));
        assert_eq!(redirect_query_params.get("state").unwrap(), "foo-state");
    }

    #[tokio::test]
    async fn test_authorize_returns_different_code_each_time() {
        let app = app_from_config_path("./config.json").unwrap();
        let server = TestServer::new(app).unwrap();

        let args = valid_authorize_args();
        let (_, first_response_params) =
            parse_authorize_response(proxy(server.get("/authorize").add_query_params(&args)).await);
        let first_code = first_response_params.get("code").unwrap();
        let (_, second_response_params) =
            parse_authorize_response(proxy(server.get("/authorize").add_query_params(&args)).await);
        let second_code = second_response_params.get("code").unwrap();

        assert_ne!(first_code, second_code);
    }

    #[tokio::test]
    async fn test_authorize_rejects_unknown_client_id() {
        let app = app_from_config_path("./config.json").unwrap();
        let server = TestServer::new(app).unwrap();

        let response = proxy(server.get("/authorize").add_query_params(AuthorizeArgs {
            client_id: "unknown-client".to_string(),
            ..valid_authorize_args()
        }))
        .await;

        response.assert_status_bad_request();
        response.assert_text("Invalid client_id");
    }

    #[tokio::test]
    async fn test_authorize_rejects_unknown_redirect_uri() {
        let app = app_from_config_path("./config.json").unwrap();
        let server = TestServer::new(app).unwrap();

        let response = proxy(server.get("/authorize").add_query_params(AuthorizeArgs {
            redirect_uri: "unknown-redirect-uri".to_string(),
            ..valid_authorize_args()
        }))
        .await;

        response.assert_status_bad_request();
        response.assert_text("Invalid redirect_uri");
    }

    #[tokio::test]
    async fn test_authorize_fails_on_missing_auth_header() {
        let app = app_from_config_path("./config.json").unwrap();
        let server = TestServer::new(app).unwrap();

        let response = server
            .get("/authorize")
            .add_query_params(&AuthorizeArgs {
                client_id: "foo-client".to_string(),
                redirect_uri: "https://example.com/1".to_string(),
                state: "foo-state".to_string(),
            })
            .await;

        response.assert_status_internal_server_error();
        response.assert_text("Missing x-webauth-user header");
    }
}
