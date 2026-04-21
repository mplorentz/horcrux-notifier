mod common;

use axum::http::{Method, StatusCode};
use serde_json::json;

use common::{new_keypair, recorded_messages, send_json, spawn_app};

#[tokio::test]
async fn health_is_unauthenticated() {
    let app = spawn_app().await;
    let (status, body) = send_json(&app, Method::GET, "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn register_requires_auth() {
    let app = spawn_app().await;
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok", "platform": "android"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_upserts_device() {
    let app = spawn_app().await;
    let (sk, pk) = new_keypair();

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok1", "platform": "android"})),
        Some(&sk),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pubkey"], pk);
    assert_eq!(body["platform"], "android");

    // Upsert with a new token.
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok2", "platform": "ios"})),
        Some(&sk),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let device = horcrux_notifier::db::get_device(&app.state.pool, &pk)
        .await
        .unwrap()
        .expect("device should exist");
    assert_eq!(device.device_token, "tok2");
    assert_eq!(device.platform, "ios");
}

#[tokio::test]
async fn delete_register_removes_device() {
    let app = spawn_app().await;
    let (sk, pk) = new_keypair();

    send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok1", "platform": "android"})),
        Some(&sk),
    )
    .await;

    let (status, _) = send_json(&app, Method::DELETE, "/register", None, Some(&sk)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let device = horcrux_notifier::db::get_device(&app.state.pool, &pk)
        .await
        .unwrap();
    assert!(device.is_none());
}

#[tokio::test]
async fn register_rejects_bad_platform() {
    let app = spawn_app().await;
    let (sk, _) = new_keypair();
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok", "platform": "windows"})),
        Some(&sk),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("platform"));
}

#[tokio::test]
async fn consent_replace_and_delete() {
    let app = spawn_app().await;
    let (recipient_sk, recipient_pk) = new_keypair();
    let (_sender_sk, sender_pk) = new_keypair();
    let (_other_sk, other_pk) = new_keypair();

    let (status, body) = send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk.clone(), other_pk.clone()]})),
        Some(&recipient_sk),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authorized_senders"].as_array().unwrap().len(), 2);

    assert!(
        horcrux_notifier::db::is_consented(&app.state.pool, &recipient_pk, &sender_pk)
            .await
            .unwrap()
    );

    // Replace with a smaller set.
    send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk.clone()]})),
        Some(&recipient_sk),
    )
    .await;
    assert!(
        !horcrux_notifier::db::is_consented(&app.state.pool, &recipient_pk, &other_pk)
            .await
            .unwrap()
    );

    // Delete the remaining one.
    let (status, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/consent/{sender_pk}"),
        None,
        Some(&recipient_sk),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        !horcrux_notifier::db::is_consented(&app.state.pool, &recipient_pk, &sender_pk)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn consent_rejects_bad_pubkey() {
    let app = spawn_app().await;
    let (sk, _) = new_keypair();
    let (status, _) = send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": ["not-hex"]})),
        Some(&sk),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn push_requires_consent() {
    let app = spawn_app().await;
    let (recipient_sk, recipient_pk) = new_keypair();
    let (sender_sk, _sender_pk) = new_keypair();

    // Recipient registers.
    send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "device-token", "platform": "android"})),
        Some(&recipient_sk),
    )
    .await;

    // Sender tries to push without consent.
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/push",
        Some(json!({
            "recipient_pubkey": recipient_pk,
            "title": "hi",
            "body": "there",
            "event_id": "a".repeat(64),
        })),
        Some(&sender_sk),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(recorded_messages(&app).await.is_empty());
}

#[tokio::test]
async fn push_delivers_when_consented() {
    let app = spawn_app().await;
    let (recipient_sk, recipient_pk) = new_keypair();
    let (sender_sk, sender_pk) = new_keypair();

    send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "device-token", "platform": "android"})),
        Some(&recipient_sk),
    )
    .await;
    send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk.clone()]})),
        Some(&recipient_sk),
    )
    .await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/push",
        Some(json!({
            "recipient_pubkey": recipient_pk,
            "title": "Alice is requesting recovery",
            "body": "Tap to respond for Family Vault.",
            "event_id": "b".repeat(64),
            "event_json": {"kind": 1059, "content": "ciphertext"},
        })),
        Some(&sender_sk),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    let msgs = recorded_messages(&app).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].title, "Alice is requesting recovery");
    assert_eq!(msgs[0].token, "device-token");
    assert!(msgs[0].data.get("event_json").is_some());
    assert_eq!(msgs[0].data["sender_pubkey"], sender_pk);
}

#[tokio::test]
async fn push_pair_rate_limit() {
    let app = spawn_app().await;
    let (recipient_sk, recipient_pk) = new_keypair();
    let (sender_sk, sender_pk) = new_keypair();

    send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok", "platform": "android"})),
        Some(&recipient_sk),
    )
    .await;
    send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk.clone()]})),
        Some(&recipient_sk),
    )
    .await;

    let req = json!({
        "recipient_pubkey": recipient_pk,
        "title": "t", "body": "b",
        "event_id": "c".repeat(64),
    });
    let (status1, _) = send_json(
        &app,
        Method::POST,
        "/push",
        Some(req.clone()),
        Some(&sender_sk),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    let (status2, body2) =
        send_json(&app, Method::POST, "/push", Some(req), Some(&sender_sk)).await;
    assert_eq!(status2, StatusCode::TOO_MANY_REQUESTS, "body={body2}");
}

#[tokio::test]
async fn push_missing_event_id_and_json() {
    let app = spawn_app().await;
    let (recipient_sk, recipient_pk) = new_keypair();
    let (sender_sk, sender_pk) = new_keypair();

    send_json(
        &app,
        Method::POST,
        "/register",
        Some(json!({"device_token": "tok", "platform": "android"})),
        Some(&recipient_sk),
    )
    .await;
    send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk]})),
        Some(&recipient_sk),
    )
    .await;

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/push",
        Some(json!({
            "recipient_pubkey": recipient_pk,
            "title": "t", "body": "b",
        })),
        Some(&sender_sk),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn push_unknown_recipient_returns_not_found() {
    let app = spawn_app().await;
    let (sender_sk, sender_pk) = new_keypair();
    let (recipient_sk, recipient_pk) = new_keypair();

    // Grant consent but never register the recipient's device.
    send_json(
        &app,
        Method::PUT,
        "/consent",
        Some(json!({"authorized_senders": [sender_pk.clone()]})),
        Some(&recipient_sk),
    )
    .await;

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/push",
        Some(json!({
            "recipient_pubkey": recipient_pk,
            "title": "t", "body": "b",
            "event_id": "d".repeat(64),
        })),
        Some(&sender_sk),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
