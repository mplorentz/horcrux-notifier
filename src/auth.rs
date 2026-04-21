//! NIP-98 HTTP Auth verification.
//!
//! A client authenticates a request by signing a kind-27235 Nostr event
//! and sending it base64-encoded in the `Authorization: Nostr <b64>` header.
//!
//! The server MUST verify:
//!   - `kind == 27235`
//!   - `created_at` is within a small window of now (configurable)
//!   - a `u` tag equal to the full request URL
//!   - a `method` tag equal to the request HTTP method (uppercase)
//!   - for POST/PUT: a `payload` tag equal to the hex SHA-256 of the body
//!   - the event id matches the canonical hash of the event
//!   - the Schnorr signature is valid for the claimed pubkey
//!
//! The returned [`Nip98Principal`] carries the authenticated pubkey, which
//! route handlers MUST cross-check against any claimed identity in the body.

use std::time::Duration;

use axum::{
    body::{self, Body, Bytes},
    extract::{FromRequest, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, Uri},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use secp256k1::{
    hashes::{sha256, Hash},
    schnorr, Secp256k1, XOnlyPublicKey,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{error::ApiError, state::AppState};

const METHODS_WITH_BODY: &[Method] = &[Method::POST, Method::PUT, Method::PATCH];

/// Request extension that carries the authenticated NIP-98 principal (the
/// signer's pubkey) and the raw request body so handlers can re-parse it.
#[derive(Debug, Clone)]
pub struct Nip98Context {
    pub pubkey: String,
    pub body: Bytes,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub async fn nip98_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".into()))?
        .to_string();

    let encoded = auth_header
        .strip_prefix("Nostr ")
        .or_else(|| auth_header.strip_prefix("nostr "))
        .ok_or_else(|| ApiError::Unauthorized("Authorization scheme must be 'Nostr'".into()))?
        .trim();

    let event_bytes = BASE64
        .decode(encoded)
        .map_err(|_| ApiError::Unauthorized("Authorization value is not valid base64".into()))?;

    let event: RawEvent = serde_json::from_slice(&event_bytes).map_err(|e| {
        ApiError::Unauthorized(format!("Authorization event is not valid JSON: {e}"))
    })?;

    let (parts, body_stream) = request.into_parts();
    let body_bytes = body::to_bytes(body_stream, usize::MAX)
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to buffer request body: {e}")))?;

    let pubkey = verify_nip98_event(
        &event,
        &method,
        &uri,
        &parts.headers,
        &body_bytes,
        state.config.nip98_max_age,
    )?;

    let mut request = Request::from_parts(parts, Body::from(body_bytes.clone()));
    request.extensions_mut().insert(Nip98Context {
        pubkey,
        body: body_bytes,
    });

    Ok(next.run(request).await)
}

fn verify_nip98_event(
    event: &RawEvent,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    max_age: Duration,
) -> Result<String, ApiError> {
    if event.kind != 27235 {
        return Err(ApiError::Unauthorized(format!(
            "auth event has kind {}, expected 27235",
            event.kind
        )));
    }

    let now = Utc::now().timestamp();
    let drift = now.saturating_sub(event.created_at).abs();
    let max_age_secs = max_age.as_secs() as i64;
    if drift > max_age_secs {
        return Err(ApiError::Unauthorized(format!(
            "auth event timestamp drift {drift}s exceeds {max_age_secs}s"
        )));
    }

    let u_tag = find_tag(&event.tags, "u")?;
    let expected_url = reconstruct_url(uri, headers);
    if !url_equivalent(u_tag, &expected_url) {
        return Err(ApiError::Unauthorized(format!(
            "auth event `u` tag {u_tag:?} does not match request URL {expected_url:?}"
        )));
    }

    let method_tag = find_tag(&event.tags, "method")?;
    if !method_tag.eq_ignore_ascii_case(method.as_str()) {
        return Err(ApiError::Unauthorized(format!(
            "auth event `method` tag {method_tag:?} does not match request method {method:?}"
        )));
    }

    if METHODS_WITH_BODY.iter().any(|m| m == method) && !body.is_empty() {
        let expected = hex::encode(Sha256::digest(body));
        let payload_tag = find_tag(&event.tags, "payload")?;
        if !payload_tag.eq_ignore_ascii_case(&expected) {
            return Err(ApiError::Unauthorized(
                "auth event `payload` tag does not match SHA-256 of request body".into(),
            ));
        }
    }

    let canonical_id = compute_event_id(event)?;
    if canonical_id != event.id {
        return Err(ApiError::Unauthorized(
            "auth event id does not match canonical event hash".into(),
        ));
    }

    verify_schnorr_signature(&event.id, &event.pubkey, &event.sig)?;

    Ok(event.pubkey.to_ascii_lowercase())
}

fn find_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Result<&'a str, ApiError> {
    tags.iter()
        .find(|t| t.first().map(String::as_str) == Some(name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
        .ok_or_else(|| ApiError::Unauthorized(format!("auth event missing `{name}` tag")))
}

fn compute_event_id(event: &RawEvent) -> Result<String, ApiError> {
    let canonical = serde_json::to_string(&serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]))
    .map_err(|e| ApiError::Unauthorized(format!("failed to canonicalize event: {e}")))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

fn verify_schnorr_signature(id_hex: &str, pubkey_hex: &str, sig_hex: &str) -> Result<(), ApiError> {
    let id_bytes = hex::decode(id_hex)
        .map_err(|_| ApiError::Unauthorized("auth event id is not valid hex".into()))?;
    if id_bytes.len() != 32 {
        return Err(ApiError::Unauthorized(
            "auth event id must be 32 bytes".into(),
        ));
    }

    let pk_bytes = hex::decode(pubkey_hex)
        .map_err(|_| ApiError::Unauthorized("auth event pubkey is not valid hex".into()))?;
    if pk_bytes.len() != 32 {
        return Err(ApiError::Unauthorized(
            "auth event pubkey must be 32 bytes (x-only)".into(),
        ));
    }

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| ApiError::Unauthorized("auth event signature is not valid hex".into()))?;
    if sig_bytes.len() != 64 {
        return Err(ApiError::Unauthorized(
            "auth event signature must be 64 bytes".into(),
        ));
    }

    let secp = Secp256k1::verification_only();
    let pk = XOnlyPublicKey::from_slice(&pk_bytes)
        .map_err(|e| ApiError::Unauthorized(format!("invalid auth pubkey: {e}")))?;
    let sig = schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|e| ApiError::Unauthorized(format!("invalid auth signature: {e}")))?;
    let msg = sha256::Hash::from_slice(&id_bytes)
        .map_err(|e| ApiError::Unauthorized(format!("invalid id hash: {e}")))?
        .to_byte_array();

    secp.verify_schnorr(&sig, &msg, &pk).map_err(|e| {
        ApiError::Unauthorized(format!("schnorr signature verification failed: {e}"))
    })?;

    Ok(())
}

fn reconstruct_url(uri: &Uri, headers: &HeaderMap) -> String {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return uri.to_string();
    }

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    format!("{scheme}://{host}{path_and_query}")
}

fn url_equivalent(a: &str, b: &str) -> bool {
    normalize_url(a) == normalize_url(b)
}

fn normalize_url(input: &str) -> String {
    let trimmed = input.trim_end_matches('/');
    trimmed.to_string()
}

/// Extract the [`Nip98Context`] that the middleware inserted and re-parse the
/// body as JSON. Route handlers should use this instead of `Json<T>` directly,
/// because the middleware has already consumed and buffered the body.
pub struct AuthedJson<T>(pub T, pub Nip98Context);

impl<S, T> FromRequest<S> for AuthedJson<T>
where
    S: Send + Sync,
    T: for<'de> Deserialize<'de>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let ctx = req
            .extensions()
            .get::<Nip98Context>()
            .cloned()
            .ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!("NIP-98 middleware not installed"))
            })?;

        if ctx.body.is_empty() {
            return Err(ApiError::BadRequest("request body is required".into()));
        }

        let value: T = serde_json::from_slice(&ctx.body)
            .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {e}")))?;

        Ok(AuthedJson(value, ctx))
    }
}

/// Handler extractor for routes that require NIP-98 auth but no body.
pub struct AuthedEmpty(pub Nip98Context);

impl<S> FromRequest<S> for AuthedEmpty
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let ctx = req
            .extensions()
            .get::<Nip98Context>()
            .cloned()
            .ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!("NIP-98 middleware not installed"))
            })?;
        Ok(AuthedEmpty(ctx))
    }
}

// Silence unused import if `Value` isn't used elsewhere in the module.
#[allow(dead_code)]
fn _unused(_: Value) {}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey};

    fn sign_event(
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        secret: &SecretKey,
        created_at: i64,
    ) -> RawEvent {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, secret);
        let pk = XOnlyPublicKey::from_keypair(&kp).0;
        let pubkey_hex = hex::encode(pk.serialize());

        let mut tags = vec![
            vec!["u".to_string(), url.to_string()],
            vec!["method".to_string(), method.to_string()],
        ];
        if let Some(b) = body {
            tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(b))]);
        }

        let canonical = serde_json::to_string(&serde_json::json!([
            0, pubkey_hex, created_at, 27235u16, tags, "",
        ]))
        .unwrap();
        let id_hash = Sha256::digest(canonical.as_bytes());
        let id_hex = hex::encode(id_hash);

        let msg = sha256::Hash::from_slice(&id_hash).unwrap().to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let sig_hex = hex::encode(sig.as_ref());

        RawEvent {
            id: id_hex,
            pubkey: pubkey_hex,
            created_at,
            kind: 27235,
            tags,
            content: String::new(),
            sig: sig_hex,
        }
    }

    fn keypair() -> SecretKey {
        SecretKey::from_slice(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn accepts_valid_get() {
        let sk = keypair();
        let ev = sign_event(
            "GET",
            "https://notify.example.com/devices/me",
            None,
            &sk,
            Utc::now().timestamp(),
        );
        let uri = Uri::from_static("https://notify.example.com/devices/me");
        let pk = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn rejects_wrong_kind() {
        let sk = keypair();
        let mut ev = sign_event(
            "GET",
            "https://notify.example.com/x",
            None,
            &sk,
            Utc::now().timestamp(),
        );
        ev.kind = 1;
        let uri = Uri::from_static("https://notify.example.com/x");
        let err = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let sk = keypair();
        let ev = sign_event(
            "GET",
            "https://notify.example.com/x",
            None,
            &sk,
            Utc::now().timestamp() - 3600,
        );
        let uri = Uri::from_static("https://notify.example.com/x");
        let err = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn rejects_wrong_url() {
        let sk = keypair();
        let ev = sign_event(
            "GET",
            "https://notify.example.com/wrong",
            None,
            &sk,
            Utc::now().timestamp(),
        );
        let uri = Uri::from_static("https://notify.example.com/right");
        let err = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn rejects_wrong_method() {
        let sk = keypair();
        let ev = sign_event(
            "POST",
            "https://notify.example.com/x",
            Some(b"{}"),
            &sk,
            Utc::now().timestamp(),
        );
        let uri = Uri::from_static("https://notify.example.com/x");
        let err = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn rejects_tampered_body() {
        let sk = keypair();
        let ev = sign_event(
            "POST",
            "https://notify.example.com/x",
            Some(b"{\"hello\":1}"),
            &sk,
            Utc::now().timestamp(),
        );
        let uri = Uri::from_static("https://notify.example.com/x");
        let err = verify_nip98_event(
            &ev,
            &Method::POST,
            &uri,
            &HeaderMap::new(),
            b"{\"hello\":2}",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[test]
    fn accepts_reconstructed_url_from_host_header() {
        let sk = keypair();
        let url = "https://notify.example.com/push";
        let body = b"{\"recipient_pubkey\":\"x\"}";
        let ev = sign_event("POST", url, Some(body), &sk, Utc::now().timestamp());
        let uri = Uri::from_static("/push");
        let mut headers = HeaderMap::new();
        headers.insert("host", "notify.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let pk = verify_nip98_event(
            &ev,
            &Method::POST,
            &uri,
            &headers,
            body,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn rejects_bad_signature() {
        let sk = keypair();
        let mut ev = sign_event(
            "GET",
            "https://notify.example.com/x",
            None,
            &sk,
            Utc::now().timestamp(),
        );
        let mut bytes = hex::decode(&ev.sig).unwrap();
        bytes[0] ^= 0xff;
        ev.sig = hex::encode(bytes);
        let uri = Uri::from_static("https://notify.example.com/x");
        let err = verify_nip98_event(
            &ev,
            &Method::GET,
            &uri,
            &HeaderMap::new(),
            b"",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }
}
