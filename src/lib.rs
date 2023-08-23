mod bags;
mod albert;
mod apns;
mod ids;
mod util;
mod imessage;

use std::sync::Arc;

use apns::{APNSState, APNSConnection};
use ids::{user::{IDSState, IDSUser}, IDSError};
use imessage::{IMClient, IMessage, RecievedMessage};
use serde::{Serialize, Deserialize};
use tokio::sync::{Mutex, RwLock};

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

pub struct InnerPushState {
    conn: Option<Arc<APNSConnection>>,
    user: Option<IDSUser>,
    client: Option<IMClient>
}

#[derive(uniffi::Object)] 
pub struct PushState (RwLock<InnerPushState>);

#[derive(uniffi::Error)]
pub enum PushError {
    TwoFaError,
    AuthError,
    RegisterFailed {
        code: u64
    },
    UnknownError {
        text: String
    }
}

impl From<IDSError> for PushError {
    fn from(value: IDSError) -> Self {
        match value {
            IDSError::TwoFaError =>
                PushError::TwoFaError,
            IDSError::AuthError(_) =>
                PushError::AuthError,
            IDSError::RegisterFailed(err) =>
                PushError::RegisterFailed { code: err },
            _error => PushError::UnknownError { text: format!("{:?}", _error) }
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PushState {
    #[uniffi::constructor]
    pub fn new() -> Arc<PushState> {
        Arc::new(PushState(RwLock::new(InnerPushState {
            conn: None,
            user: None,
            client: None
        })))
    }

    pub async fn recv_wait(&self) -> Option<RecievedMessage> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (recv_wait)")
        }
        self.0.read().await.client.as_ref().unwrap().recieve_wait().await
    }

    pub async fn send(&self, mut msg: IMessage) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (send)")
        }
        self.0.read().await.client.as_ref().unwrap().send(&mut msg).await?;
        Ok(())
    }

    pub async fn get_handles(&self) -> Result<Vec<String>, PushError> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (send)")
        }
        Ok(self.0.read().await.client.as_ref().unwrap().get_handles().to_vec())
    }

    pub async fn new_msg(&self, text: String, targets: Vec<String>, group_id: String) -> IMessage {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (new_msg)")
        }
        self.0.read().await.client.as_ref().unwrap().new_msg(&text, &targets, &group_id)
    }

    pub async fn validate_targets(&self, targets: Vec<String>) -> Result<Vec<String>, PushError> {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (validate_targets)")
        }
        Ok(self.0.read().await.client.as_ref().unwrap().validate_targets(&targets).await?)
    }

    pub async fn cancel_registration(&self) {
        if self.get_phase().await != RegistrationPhase::WANTS_VALID_ID {
            return
        }
        let mut inner = self.0.write().await;
        inner.user = None
    }

    pub async fn get_phase(&self) -> RegistrationPhase {
        let inner = self.0.read().await;
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
        let mut inner = self.0.write().await;
        inner.conn = Some(connection);

        let user = Arc::new(IDSUser::restore_authentication(state.auth.clone()));

        inner.client = Some(IMClient::new(inner.conn.as_ref().unwrap().clone(), user.clone()).await);
    }

    pub async fn new_push(&self) {
        if self.get_phase().await != RegistrationPhase::NOT_STARTED {
            panic!("Wrong phase! (new_push)")
        }
        let mut inner = self.0.write().await;
        let connection = Arc::new(APNSConnection::new(None).await.unwrap());
        connection.submitter.set_state(1).await;
        connection.submitter.filter(&["com.apple.madrid"]).await;
        inner.conn = Some(connection);
    }

    pub async fn try_auth(&self, username: String, password: String) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::WANTS_USER_PASS {
            panic!("Wrong phase! (try_auth)")
        }
        let mut inner = self.0.write().await;
        inner.user = 
            Some(IDSUser::authenticate(inner.conn.as_ref().unwrap().clone(), username.trim(), password.trim()).await?);
        
        Ok(())
    }

    pub async fn register_ids(&self, validation_data: String) -> Result<(), PushError> {
        if self.get_phase().await != RegistrationPhase::WANTS_VALID_ID {
            panic!("Wrong phase! (register_ids)")
        }
        let mut inner = self.0.write().await;
        let conn_state = inner.conn.as_ref().unwrap().state.clone();
        inner.user.as_mut().unwrap().register_id(&conn_state, &validation_data).await?;
        inner.client = Some(IMClient::new(inner.conn.as_ref().unwrap().clone(), Arc::new(inner.user.take().unwrap())).await);
        Ok(())
    }

    pub async fn save_push(&self) -> String {
        if self.get_phase().await != RegistrationPhase::REGISTERED {
            panic!("Wrong phase! (save_push)")
        }
        let inner = self.0.read().await;
        let state = SavedState {
            push: inner.conn.as_ref().unwrap().state.clone(),
            auth: inner.client.as_ref().unwrap().user.state.clone()
        };
        serde_json::to_string(&state).unwrap()
    }
}