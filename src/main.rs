
use std::rc::Rc;

use apns::APNSState;
use ids::user::IDSState;
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;

use crate::apns::APNSConnection;
use crate::ids::user::IDSUser;
use serde::{Serialize, Deserialize};
mod bags;
mod albert;
mod apns;
mod ids;
mod util;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    auth: IDSState
}

#[tokio::main]
async fn main() {
    let data = fs::read_to_string("config.json").await.expect("Unable to read file");
    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();

    let connection = Rc::new(APNSConnection::new(saved_state.as_ref().map(|state| state.push.clone())).await.unwrap());
    connection.submitter.set_state(1).await;
    connection.submitter.filter(&["com.apple.madrid"]).await;

    let user = if let Some(state) = saved_state.as_ref() {
        IDSUser::restore_authentication(connection.clone(), state.auth.clone())
    } else {
        let stdin = io::stdin();
        print!("Username: ");
        io::stdout().flush().await.unwrap();
        let mut reader = BufReader::new(stdin);
        let mut username = String::new();
        reader.read_line(&mut username).await.unwrap();
        print!("Password: ");
        io::stdout().flush().await.unwrap();
        let mut password = String::new();
        reader.read_line(&mut password).await.unwrap();

        IDSUser::authenticate(connection.clone(), username.trim(), password.trim(), || async {
            println!("2fa code: ");
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin);
            let mut code = String::new();
            reader.read_line(&mut code).await.unwrap();
            code.trim().to_string()
        }).await.unwrap()
    };

    let state = SavedState {
        push: connection.state.clone(),
        auth: user.state.clone()
    };
    let serialized = serde_json::to_string(&state).unwrap();
    fs::write("config.json", serialized).await.unwrap();
}
