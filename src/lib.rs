mod bags;
mod albert;
mod apns;
mod ids;
mod util;
mod imessage;

use std::{rc::Rc, future::Future, io::Error, sync::Arc};

use apns::{APNSState, APNSConnection};
use ids::{user::{IDSState, IDSUser}, IDSError};
use imessage::{IMClient, IMessage, RecievedMessage};
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;

uniffi::setup_scaffolding!();

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    auth: IDSState
}

#[derive(PartialEq, uniffi::Enum)]
pub enum RegistrationPhase {
    NOT_STARTED,
    WANTS_USER_PASS,
    WANTS_VALID_ID,
    REGISTERED
}

struct PushStateInner {
    conn: Option<Arc<APNSConnection>>,
    user: Option<IDSUser>,
    client: Option<IMClient>
}

#[derive(uniffi::Object)] 
pub struct PushState(Mutex<PushStateInner>);

#[derive(uniffi::Error)]
pub enum PushError {
    TwoFaError,
    UnknownError {
        text: String
    }
}

impl From<IDSError> for PushError {
    fn from(value: IDSError) -> Self {
        match value {
            IDSError::TwoFaError =>
                PushError::TwoFaError,
            _error => PushError::UnknownError { text: format!("{:?}", _error) }
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PushState {
    #[uniffi::constructor]
    pub fn new() -> Arc<PushState> {
        Arc::new(PushState(Mutex::new(PushStateInner {
            conn: None,
            user: None,
            client: None
        })))
    }

    pub async fn recv_wait(&self) -> Option<RecievedMessage> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (recv_wait)")
        }
        let mut inner = self.0.lock().await;
        inner.client.as_mut().unwrap().recieve_wait().await
    }

    pub async fn send(&self, mut msg: IMessage) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (send)")
        }
        let mut inner = self.0.lock().await;
        inner.client.as_mut().unwrap().send(&mut msg).await?;
        Ok(())
    }

    pub async fn new_msg(&self, text: String, targets: Vec<String>) -> IMessage {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (new_msg)")
        }
        let mut inner = self.0.lock().await;
        inner.client.as_mut().unwrap().new_msg(&text, &targets)
    }

    pub async fn validate_targets(&self, targets: Vec<String>) -> Result<Vec<String>, PushError> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (validate_targets)")
        }
        let mut inner = self.0.lock().await;
        Ok(inner.client.as_mut().unwrap().validate_targets(&targets).await?)
    }

    pub async fn get_phase(&self) -> RegistrationPhase {
        let inner = self.0.lock().await;
        if inner.conn.is_none() {
            return RegistrationPhase::NOT_STARTED
        }
        if inner.user.is_none() && inner.client.is_none() {
            return RegistrationPhase::WANTS_USER_PASS
        }
        if inner.client.is_none() {
            return RegistrationPhase::WANTS_VALID_ID
        }
        RegistrationPhase::REGISTERED
    }

    pub async fn restore(&self, data: String) {
        if self.get_phase().await != RegistrationPhase::NOT_STARTED {
            panic!("Wrong phase! (restore)")
        }

        let state: SavedState = serde_json::from_str(&data).unwrap();

        let connection = Arc::new(APNSConnection::new(Some(state.push.clone())).await.unwrap());
        connection.submitter.set_state(1).await;
        connection.submitter.filter(&["com.apple.madrid"]).await;
        let mut inner = self.0.lock().await;
        inner.conn = Some(connection);

        let user = Arc::new(IDSUser::restore_authentication(state.auth.clone()));

        inner.client = Some(IMClient::new(inner.conn.as_ref().unwrap().clone(), user.clone()).await);
    }

    pub async fn new_push(&self) {
        if self.get_phase().await != RegistrationPhase::NOT_STARTED {
            panic!("Wrong phase! (new_push)")
        }
        let mut inner = self.0.lock().await;
        let connection = Arc::new(APNSConnection::new(None).await.unwrap());
        connection.submitter.set_state(1).await;
        connection.submitter.filter(&["com.apple.madrid"]).await;
        inner.conn = Some(connection);
    }

    pub async fn try_auth(&self, username: String, password: String) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::WANTS_USER_PASS {
            panic!("Wrong phase! (try_auth)")
        }
        let mut inner = self.0.lock().await;
        inner.user = 
            Some(IDSUser::authenticate(inner.conn.as_ref().unwrap().clone(), username.trim(), password.trim()).await?);
        
        Ok(())
    }

    pub async fn register_ids(&self, validation_data: String) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::WANTS_USER_PASS {
            panic!("Wrong phase! (register_ids)")
        }
        let mut inner = self.0.lock().await;
        let conn_state = inner.conn.as_ref().unwrap().state.clone();
        inner.user.as_mut().unwrap().register_id(&conn_state, &validation_data).await?;
        Ok(())
    }

    pub async fn save_push(&self) -> String {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (save_push)")
        }
        let inner = self.0.lock().await;
        let state = SavedState {
            push: inner.conn.as_ref().unwrap().state.clone(),
            auth: inner.user.as_ref().unwrap().state.clone()
        };
        serde_json::to_string(&state).unwrap()
    }
}