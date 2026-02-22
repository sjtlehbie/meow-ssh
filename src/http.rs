use crate::db::Db;
use crate::pty::{self, ShellConfig};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use rust_embed::Embed;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_http::cors::CorsLayer;
use webauthn_rs::prelude::*;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Embed)]
#[folder = "src/public/"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub shell_config: Arc<ShellConfig>,
    pub domain: String,
    pub web_port: u16,
    pub no_registration: bool,
    pub registration_secret: String,
}

pub fn router(state: AppState) -> Router {
    let origin = if state.domain == "localhost" || state.domain == "127.0.0.1" {
        format!("http://{}:{}", state.domain, state.web_port)
    } else {
        format!("https://{}", state.domain)
    };
    let cors = CorsLayer::new()
        .allow_origin(origin.parse::<HeaderValue>().expect("valid origin"))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        // Pages
        .route("/", get(serve_index))
        .route("/auth/{token}", get(serve_auth))
        .route("/terminal", get(serve_terminal))
        .route("/register", get(serve_register))
        // API
        .route("/health", get(health))
        .route("/api/register/options", post(register_options))
        .route("/api/register/verify", post(register_verify))
        .route("/api/auth/options/{token}", post(auth_options))
        .route("/api/auth/verify/{token}", post(auth_verify))
        .route("/api/terminal/auth/options", post(terminal_auth_options))
        .route("/api/terminal/auth/verify", post(terminal_auth_verify))
        .route("/api/session/{token}", get(session_status))
        .route("/ws/terminal", get(ws_terminal))
        // Static assets
        .fallback(get(serve_static))
        .layer(cors)
        .with_state(state)
}

// --- Static file serving ---

async fn serve_index() -> impl IntoResponse {
    serve_html("index.html")
}

async fn serve_auth(Path(_token): Path<String>) -> impl IntoResponse {
    serve_html("auth.html")
}

async fn serve_terminal() -> impl IntoResponse {
    serve_html("terminal.html")
}

async fn serve_register() -> impl IntoResponse {
    serve_html("register.html")
}

fn serve_html(name: &str) -> impl IntoResponse {
    match Assets::get(name) {
        Some(file) => Html(String::from_utf8_lossy(file.data.as_ref()).into_owned()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_static(axum::extract::Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    match Assets::get(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// --- Health ---

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "meow-ssh" }))
}

// --- WebAuthn helpers ---

fn build_webauthn(domain: &str, web_port: u16) -> Result<Webauthn, ApiError> {
    let origin = if domain == "localhost" || domain == "127.0.0.1" {
        format!("http://{}:{}", domain, web_port)
    } else {
        format!("https://{}", domain)
    };
    let url = url::Url::parse(&origin)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Invalid domain"))?;
    WebauthnBuilder::new(domain, &url)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn init failed"))?
        .rp_name(domain)
        .build()
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn build failed"))
}

// --- Registration ---

#[derive(Deserialize)]
struct RegisterReq {
    secret: Option<String>,
}

async fn register_options(
    State(state): State<AppState>,
    Json(body): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if state.no_registration {
        return Err(err(StatusCode::FORBIDDEN, "Registration disabled"));
    }

    let provided = body.secret.unwrap_or_default();
    if provided != state.registration_secret {
        return Err(err(StatusCode::FORBIDDEN, "Invalid registration secret"));
    }

    let webauthn = build_webauthn(&state.domain, state.web_port)?;
    let user_id = Uuid::new_v4();

    let exclude: Vec<CredentialID> = state.db.get_all_credentials()
        .iter()
        .filter_map(|c| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &c.id).ok()
        })
        .map(CredentialID::from)
        .collect();

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_id, "user", "user", Some(exclude))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("WebAuthn error: {}", e)))?;

    let state_json = serde_json::to_string(&reg_state)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;
    let challenge_id = uuid::Uuid::new_v4().to_string();
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;

    state.db.set_config(
        &format!("reg_state_{}", challenge_id),
        &state_json,
        Some(expires),
    ).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({
        "options": ccr,
        "challengeId": challenge_id,
    })))
}

#[derive(Deserialize)]
struct RegisterVerifyReq {
    #[serde(rename = "challengeId")]
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

async fn register_verify(
    State(state): State<AppState>,
    Json(body): Json<RegisterVerifyReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let webauthn = build_webauthn(&state.domain, state.web_port)?;

    let state_json = state.db.get_config(&format!("reg_state_{}", body.challenge_id))
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Challenge expired or invalid"))?;
    state.db.delete_config(&format!("reg_state_{}", body.challenge_id)).ok();

    let reg_state: PasskeyRegistration = serde_json::from_str(&state_json)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "State deserialization error"))?;

    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Verification failed: {}", e)))?;

    // Store credential
    let cred_id = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, passkey.cred_id().as_ref());
    let pk_bytes = serde_json::to_vec(&passkey)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;

    state.db.store_credential(&cred_id, &pk_bytes, 0, None, None)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({ "success": true })))
}

// --- SSH Auth ---

async fn auth_options(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify token exists and is pending
    let session = state.db.get_session(&token)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Invalid or expired token"))?;
    if session.status != "pending" {
        return Err(err(StatusCode::BAD_REQUEST, "Session already processed"));
    }

    let webauthn = build_webauthn(&state.domain, state.web_port)?;
    let passkeys = load_passkeys(&state.db)?;

    if passkeys.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "No passkeys registered"));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("WebAuthn error: {}", e)))?;

    let state_json = serde_json::to_string(&auth_state)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;

    state.db.set_config(
        &format!("auth_state_{}", token),
        &state_json,
        Some(expires),
    ).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({ "options": rcr })))
}

#[derive(Deserialize)]
struct AuthVerifyReq {
    credential: PublicKeyCredential,
}

async fn auth_verify(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(body): Json<AuthVerifyReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let webauthn = build_webauthn(&state.domain, state.web_port)?;

    let state_json = state.db.get_config(&format!("auth_state_{}", token))
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Challenge expired or invalid"))?;
    state.db.delete_config(&format!("auth_state_{}", token)).ok();

    let auth_state: PasskeyAuthentication = serde_json::from_str(&state_json)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "State deserialization error"))?;

    let auth_result = webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Verification failed: {}", e)))?;

    // Update stored passkey with new counter
    update_stored_credential(&state.db, &auth_result);

    // Approve the SSH session
    state.db.approve_session(&token, "authenticated")
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({ "approved": true })))
}

// --- Terminal Auth ---

async fn terminal_auth_options(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let webauthn = build_webauthn(&state.domain, state.web_port)?;
    let passkeys = load_passkeys(&state.db)?;

    if passkeys.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "No passkeys registered"));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("WebAuthn error: {}", e)))?;

    let challenge_id = uuid::Uuid::new_v4().to_string();
    let state_json = serde_json::to_string(&auth_state)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Serialization error"))?;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300;

    state.db.set_config(
        &format!("terminal_auth_{}", challenge_id),
        &state_json,
        Some(expires),
    ).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({
        "options": rcr,
        "challengeId": challenge_id,
    })))
}

#[derive(Deserialize)]
struct TerminalAuthVerifyReq {
    #[serde(rename = "challengeId")]
    challenge_id: String,
    credential: PublicKeyCredential,
}

async fn terminal_auth_verify(
    State(state): State<AppState>,
    Json(body): Json<TerminalAuthVerifyReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let webauthn = build_webauthn(&state.domain, state.web_port)?;

    let state_json = state.db.get_config(&format!("terminal_auth_{}", body.challenge_id))
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Challenge expired or invalid"))?;
    state.db.delete_config(&format!("terminal_auth_{}", body.challenge_id)).ok();

    let auth_state: PasskeyAuthentication = serde_json::from_str(&state_json)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "State deserialization error"))?;

    let auth_result = webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("Verification failed: {}", e)))?;

    update_stored_credential(&state.db, &auth_result);

    // Create terminal token
    let token = hex::encode(rand::random::<[u8; 16]>());
    state.db.create_terminal_token(&token)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    Ok(Json(serde_json::json!({ "token": token })))
}

// --- Session status ---

async fn session_status(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = state.db.get_session(&token)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Not found"))?;
    Ok(Json(serde_json::json!({ "status": session.status })))
}

// --- WebSocket terminal ---

#[derive(Deserialize)]
struct WsQuery {
    token: Option<String>,
}

async fn ws_terminal(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let token = query.token.ok_or_else(|| err(StatusCode::BAD_REQUEST, "Missing token"))?;
    state.db.consume_terminal_token(&token)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    let shell_config = state.shell_config.clone();
    Ok(ws.on_upgrade(move |socket| handle_ws_terminal(socket, shell_config)))
}

async fn handle_ws_terminal(socket: WebSocket, shell_config: Arc<ShellConfig>) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let (pty, mut child) = match pty::spawn_pty(&shell_config, 80, 24) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("WS: Failed to spawn PTY: {:?}", e);
            ws_tx.send(Message::Close(None)).await.ok();
            return;
        }
    };

    let (mut pty_reader, mut pty_writer) = pty.into_split();

    // PTY output → WebSocket
    let send_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        ws_tx.send(Message::Close(None)).await.ok();
    });

    // WebSocket → PTY input
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) => {
                    if data.first() == Some(&1) {
                        // Resize: 0x01 + JSON { cols, rows }
                        if let Ok(size) = serde_json::from_slice::<serde_json::Value>(&data[1..]) {
                            let cols = size["cols"].as_u64().unwrap_or(80) as u16;
                            let rows = size["rows"].as_u64().unwrap_or(24) as u16;
                            pty_writer.resize(pty_process::Size::new(rows, cols)).ok();
                        }
                    } else if pty_writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Message::Text(text) => {
                    if pty_writer.write_all(text.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        pty_writer.shutdown().await.ok();
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
    child.kill().await.ok();
}

// --- Helpers ---

fn update_stored_credential(db: &Db, auth_result: &AuthenticationResult) {
    let cred_id = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        auth_result.cred_id().as_ref(),
    );
    if let Some(stored) = db.get_credential(&cred_id) {
        if let Ok(mut passkey) = serde_json::from_slice::<Passkey>(&stored.public_key) {
            let _ = passkey.update_credential(auth_result);
            if let Ok(updated) = serde_json::to_vec(&passkey) {
                db.update_credential_blob(&cred_id, &updated).ok();
            }
        }
    }
}

fn load_passkeys(db: &Db) -> Result<Vec<Passkey>, ApiError> {
    let creds = db.get_all_credentials();
    let mut passkeys = Vec::new();
    for c in creds {
        let pk: Passkey = serde_json::from_slice(&c.public_key)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Credential deserialization error"))?;
        passkeys.push(pk);
    }
    Ok(passkeys)
}
