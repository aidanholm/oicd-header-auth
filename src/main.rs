use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use color_eyre::eyre::ContextCompat;
use color_eyre::{Result, eyre::Context};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use jwt::VerifyWithKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;

/// Name of the header set by the reverse proxy containing the ID of the authenticated user, if
/// any, or not set otherwise.
const AUTH_HEADER_NAME: &str = "x-webauth-user";
/// The domain (well, really the URL) on which this OICD provider is being served.
const DOMAIN: &str = "https://oauth.example.com";

#[derive(Deserialize, Debug)]
struct ClientConfig {
    redirect_uris: Vec<String>,
    client_secret: String,
}

struct TokenState {
    user_id: String,
}

struct AppState {
    /// Map from OAuth client IDs to their configuration.
    /// Not mutated after program startup.
    clients: std::collections::HashMap<String, ClientConfig>,
    /// Map from (token, client ID) to the active user.
    tokens: Mutex<std::collections::HashMap<(String, String), TokenState>>,
    /// Secret key used to sign JWT tokens.
    jwt_hmac: Hmac<sha2::Sha256>,
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

#[derive(Serialize, Deserialize, Debug)]
struct TokenArgs {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct TokenResponse<'a> {
    access_token: String,
    token_type: &'a str,
    expires_in: u64,
}

async fn handle_token(
    State(state): State<Arc<AppState>>,
    form: axum::extract::Form<TokenArgs>,
) -> axum::response::Response {
    if form.grant_type != "authorization_code" {
        return (StatusCode::BAD_REQUEST, "Invalid grant_type").into_response();
    }

    let client_config = match state.clients.get(&form.client_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response(),
    };
    if client_config
        .client_secret
        .as_bytes()
        .ct_ne(form.client_secret.as_bytes())
        .into()
    {
        return (StatusCode::BAD_REQUEST, "Invalid client_secret").into_response();
    }
    let token_key = (form.code.clone(), form.client_id.clone());
    let token_state = match state.tokens.lock().unwrap().remove(&token_key) {
        Some(state) => state,
        None => return (StatusCode::BAD_REQUEST, "Invalid code").into_response(),
    };

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let expiry = Duration::from_secs(60);
    let claims = JwtClaims {
        sub: token_state.user_id,
        iss: DOMAIN.to_string(),
        aud: form.client_id.clone(),
        iat: now.as_secs(),
        exp: (now + expiry).as_secs(),
    };

    Json(TokenResponse {
        access_token: claims.sign_with_key(&state.jwt_hmac).unwrap(),
        token_type: "Bearer",
        expires_in: expiry.as_secs(),
    })
    .into_response()
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Userinfo {
    sub: String,
    email: String,
}

async fn handle_userinfo(
    State(state): State<Arc<AppState>>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> axum::response::Response {
    let claims: JwtClaims = match authorization.token().verify_with_key(&state.jwt_hmac) {
        Ok(claims) => claims,
        Err(e) => return (StatusCode::UNAUTHORIZED, e.to_string()).into_response(),
    };
    Json(Userinfo {
        sub: claims.sub.clone(),
        email: claims.sub,
    })
    .into_response()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct OpenIdConfig {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

async fn handle_openid_config() -> axum::response::Response {
    Json(OpenIdConfig {
        issuer: DOMAIN.into(),
        authorization_endpoint: format!("{DOMAIN}/authorize"),
        token_endpoint: format!("{DOMAIN}/token"),
        userinfo_endpoint: format!("{DOMAIN}/userinfo"),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into()],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["HS256".into()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
    })
    .into_response()
}

fn load_config() -> std::collections::HashMap<String, ClientConfig> {
    serde_json::from_str(include_str!("./config.json")).unwrap()
}

fn app_from_config() -> (Router, Arc<AppState>) {
    let config = load_config();
    let app_state = Arc::new(AppState {
        clients: config,
        tokens: Mutex::new(std::collections::HashMap::new()),
        // Use a new signing secret every time the server starts. We never expect tokens to be used
        // for any longer than a few seconds at most.
        jwt_hmac: Hmac::new_from_slice(url_safe_token().as_bytes()).unwrap(),
    });
    (
        axum::Router::new()
            .route("/authorize", axum::routing::get(handle_authorize))
            .route("/token", axum::routing::post(handle_token))
            .route("/userinfo", axum::routing::get(handle_userinfo))
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(handle_openid_config),
            )
            .with_state(app_state.clone()),
        app_state,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let (app, _) = app_from_config();
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
        let (app, _) = app_from_config();
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
        let (app, _) = app_from_config();
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
        let (app, _) = app_from_config();
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
        let (app, _) = app_from_config();
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
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let response = server
            .get("/authorize")
            .add_query_params(valid_authorize_args())
            .await;

        response.assert_status_internal_server_error();
        response.assert_text("Missing x-webauth-user header");
    }

    /// Returns /token args that match the hardcoded config (except for code).
    fn valid_token_args() -> TokenArgs {
        TokenArgs {
            grant_type: "authorization_code".to_string(),
            code: "default from _valid_token_args()".to_string(),
            client_id: "foo-client".to_string(),
            client_secret: "hunter2".to_string(),
        }
    }

    #[tokio::test]
    async fn test_signed_token_can_be_retrieved_after_authorize_call() {
        let (app, app_state) = app_from_config();
        let server = TestServer::new(app).unwrap();
        let (_, authorize_response_params) = parse_authorize_response(
            proxy(
                server
                    .get("/authorize")
                    .add_query_params(valid_authorize_args()),
            )
            .await,
        );
        let code = authorize_response_params.get("code").unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                code: code.to_string(),
                ..valid_token_args()
            })
            .await;

        token_response.assert_status_ok();
        let token_response_bytes = token_response.into_bytes();
        let token_json: TokenResponse = serde_json::from_slice(&token_response_bytes).unwrap();
        assert_eq!(token_json.token_type, "Bearer");
        assert_eq!(token_json.expires_in, 60);

        let claims: JwtClaims = token_json
            .access_token
            .verify_with_key(&app_state.jwt_hmac)
            .unwrap();
        assert_eq!(claims.iss, DOMAIN);
        assert_eq!(claims.sub, "alice@example.com");
        assert_eq!(claims.aud, "foo-client");
        assert_eq!(claims.exp - claims.iat, 60);
    }

    #[tokio::test]
    async fn test_token_rejects_unrecognized_grant_type() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                grant_type: "bad-grant-type".to_string(),
                ..valid_token_args()
            })
            .await;

        token_response.assert_status_bad_request();
        token_response.assert_text("Invalid grant_type");
    }

    #[tokio::test]
    async fn test_token_rejects_unrecognized_authorize_code() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                code: "bad-code".to_string(),
                ..valid_token_args()
            })
            .await;

        token_response.assert_status_bad_request();
        token_response.assert_text("Invalid code");
    }

    #[tokio::test]
    async fn test_token_rejects_unrecognized_client_id() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                client_id: "unknown-client".to_string(),
                ..valid_token_args()
            })
            .await;

        token_response.assert_status_bad_request();
        token_response.assert_text("Invalid client_id");
    }

    #[tokio::test]
    async fn test_token_rejects_unrecognized_client_secret() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                client_secret: "wrong secret".to_string(),
                ..valid_token_args()
            })
            .await;

        token_response.assert_status_bad_request();
        token_response.assert_text("Invalid client_secret");
    }

    #[tokio::test]
    async fn test_userinfo_returns_userinfo_given_token() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();
        let (_, authorize_response_params) = parse_authorize_response(
            proxy(
                server
                    .get("/authorize")
                    .add_query_params(valid_authorize_args()),
            )
            .await,
        );
        let code = authorize_response_params.get("code").unwrap();

        let token_response = server
            .post("/token")
            .form(&TokenArgs {
                code: code.to_string(),
                ..valid_token_args()
            })
            .await;
        token_response.assert_status_ok();
        let token_response_bytes = token_response.into_bytes();
        let token = serde_json::from_slice::<TokenResponse>(&token_response_bytes)
            .unwrap()
            .access_token;

        let userinfo_response = proxy(
            server
                .get("/userinfo")
                .add_header("authorization", format!("Bearer {token}")),
        )
        .await;
        userinfo_response.assert_json(&Userinfo {
            sub: "alice@example.com".to_string(),
            email: "alice@example.com".to_string(),
        });
    }

    #[tokio::test]
    async fn test_userinfo_rejects_bad_token() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let userinfo_response = proxy(
            server
                .get("/userinfo")
                .add_header("authorization", "Bearer bad-token"),
        )
        .await;
        userinfo_response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_openid_config_serves_config() {
        let (app, _) = app_from_config();
        let server = TestServer::new(app).unwrap();

        let response = proxy(server.get("/.well-known/openid-configuration")).await;
        response.assert_json(&OpenIdConfig {
            issuer: "https://oauth.example.com".into(),
            authorization_endpoint: "https://oauth.example.com/authorize".into(),
            token_endpoint: "https://oauth.example.com/token".into(),
            userinfo_endpoint: "https://oauth.example.com/userinfo".into(),
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
            response_types_supported: vec!["code".into()],
            grant_types_supported: vec!["authorization_code".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["HS256".into()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".into()],
        });
    }
}
