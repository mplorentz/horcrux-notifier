use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{HeaderValue, Method, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use horcrux_notifier::{
    build_router_with_state,
    config::Config,
    db,
    fcm::{test_util::MockSender, FcmMessage},
    state::AppState,
};
use secp256k1::{
    hashes::{sha256, Hash},
    rand::{rngs::OsRng, RngCore},
    Keypair, Secp256k1, SecretKey, XOnlyPublicKey,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub fcm: MockSender,
    _tempdir: TempDir,
}

pub async fn spawn_app() -> TestApp {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let db_path = tempdir.path().join("test.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());

    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: db_url.clone(),
        fcm_service_account_path: tempdir.path().join("unused.json"),
        nip98_max_age: Duration::from_secs(60),
        push_pair_window: Duration::from_secs(30),
        push_pair_max: 1,
        push_recipient_window: Duration::from_secs(3600),
        push_recipient_max: 60,
        register_window: Duration::from_secs(3600),
        register_max: 10,
    };

    let pool = db::connect(&db_url).await.expect("db connect");
    let fcm = MockSender::default();
    let fcm_arc: Arc<dyn horcrux_notifier::fcm::FcmSender> = Arc::new(fcm.clone());
    let (router, state) = build_router_with_state(config, pool, fcm_arc)
        .await
        .expect("build router");

    TestApp {
        router,
        state,
        fcm,
        _tempdir: tempdir,
    }
}

pub fn new_keypair() -> (SecretKey, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let sk = SecretKey::from_slice(&bytes).unwrap();
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let pk = XOnlyPublicKey::from_keypair(&kp).0;
    (sk, hex::encode(pk.serialize()))
}

pub fn sign_nip98_header(method: &str, url: &str, body: &[u8], sk: &SecretKey) -> HeaderValue {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, sk);
    let pk = XOnlyPublicKey::from_keypair(&kp).0;
    let pubkey_hex = hex::encode(pk.serialize());

    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if matches!(method, "POST" | "PUT" | "PATCH") && !body.is_empty() {
        tags.push(vec![
            "payload".to_string(),
            hex::encode(Sha256::digest(body)),
        ]);
    }

    let created_at = Utc::now().timestamp();
    let canonical = serde_json::to_string(&serde_json::json!([
        0, pubkey_hex, created_at, 27235u16, tags, "",
    ]))
    .unwrap();
    let id_hash = Sha256::digest(canonical.as_bytes());
    let id_hex = hex::encode(id_hash);
    let msg = sha256::Hash::from_slice(&id_hash).unwrap().to_byte_array();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let sig_hex = hex::encode(sig.as_ref());

    let event = serde_json::json!({
        "id": id_hex,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": 27235,
        "tags": tags,
        "content": "",
        "sig": sig_hex,
    });
    let encoded = BASE64.encode(event.to_string().as_bytes());
    HeaderValue::from_str(&format!("Nostr {encoded}")).unwrap()
}

pub async fn send_json(
    app: &TestApp,
    method: Method,
    path: &str,
    body: Option<Value>,
    sk: Option<&SecretKey>,
) -> (StatusCode, Value) {
    let url = format!("https://notify.test{path}");
    let body_bytes = body
        .as_ref()
        .map(|v| serde_json::to_vec(v).unwrap())
        .unwrap_or_default();

    let mut req = Request::builder()
        .method(method.clone())
        .uri(path)
        .header("host", "notify.test")
        .header("x-forwarded-proto", "https");
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    if let Some(sk) = sk {
        let header = sign_nip98_header(method.as_str(), &url, &body_bytes, sk);
        req = req.header("authorization", header);
    }
    let request = req.body(Body::from(body_bytes)).unwrap();
    let response = app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router response");

    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

pub async fn recorded_messages(app: &TestApp) -> Vec<FcmMessage> {
    app.fcm.messages.lock().await.clone()
}
