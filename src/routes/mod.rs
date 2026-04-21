use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use crate::{auth::nip98_middleware, state::AppState};

pub mod consent;
pub mod health;
pub mod push;
pub mod register;

pub fn router(state: AppState) -> Router {
    let public = Router::new().route("/health", get(health::health));

    let authed = Router::new()
        .route(
            "/register",
            post(register::register).delete(register::unregister),
        )
        .route("/consent", put(consent::replace_consent))
        .route("/consent/{sender_pubkey}", delete(consent::delete_consent))
        .route("/push", post(push::push))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            nip98_middleware,
        ));

    public.merge(authed).with_state(state)
}
