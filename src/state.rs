use std::sync::Arc;

use crate::{config::Config, db::Pool, fcm::FcmSender};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: Pool,
    pub fcm: Arc<dyn FcmSender>,
}

impl AppState {
    pub fn new(config: Config, pool: Pool, fcm: Arc<dyn FcmSender>) -> Self {
        Self {
            config: Arc::new(config),
            pool,
            fcm,
        }
    }
}
