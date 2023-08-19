
use std::{rc::Rc, sync::Arc};

use apns::APNSState;
use ids::user::{IDSState, get_handles};
use imessage::IMClient;
use plist::Dictionary;
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;
use util::{base64_encode, base64_decode};
use crate::ids::IDSError;
use crate::imessage::RecievedMessage;

use tokio::time::{sleep, Duration};

use crate::apns::APNSConnection;
use crate::ids::user::IDSUser;
use serde::{Serialize, Deserialize};
mod bags;
mod albert;
mod apns;
mod ids;
mod util;
mod imessage;

uniffi::setup_scaffolding!();

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    auth: IDSState
}

#[tokio::main]
async fn main() {
    let data = fs::read_to_string("config.json").await.expect("Unable to read file");
    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();

    let connection = Arc::new(APNSConnection::new(saved_state.as_ref().map(|state| state.push.clone())).await.unwrap());
    connection.submitter.set_state(1).await;
    connection.submitter.filter(&["com.apple.madrid"]).await;

    let mut user = if let Some(state) = saved_state.as_ref() {
        IDSUser::restore_authentication(state.auth.clone())
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

        let mut twofa_code = "".to_string();
        loop {
            let resp = IDSUser::authenticate(connection.clone(), username.trim(), &(password.trim().to_string() + &twofa_code)).await;
            match resp {
                Ok(user) => {
                    break user
                }
                Err(IDSError::TwoFaError) => {
                    println!("2fa code: ");
                    let stdin = io::stdin();
                    let mut reader = BufReader::new(stdin);
                    let mut code = String::new();
                    reader.read_line(&mut code).await.unwrap();
                    twofa_code = code.trim().to_string();
                }
                Err(err) => {
                    panic!("{:?}", err);
                }
            }
        }
    };

    if user.state.identity.is_none() {
        println!("Registering new identity...");
        print!("Enter validation data: ");
        io::stdout().flush().await.unwrap();
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut validation = String::new();
        reader.read_line(&mut validation).await.unwrap();
        user.register_id(&connection.state, &validation).await.unwrap();
    }

    //let lookup = user.lookup(connection.clone(), vec!["tel:+17203818329".to_string(),"mailto:tae.hagen@gmail.com".to_string()]).await.unwrap();

    let state = SavedState {
        push: connection.state.clone(),
        auth: user.state.clone()
    };
    let serialized = serde_json::to_string(&state).unwrap();
    fs::write("config.json", serialized).await.unwrap();
    
    let user = Arc::new(user);
    let mut client = IMClient::new(connection.clone(), user.clone()).await;

    //let mut msg = client.new_msg("ya test", &["tel:+17203818329".to_string()]);
    //let mut msg = client.new_msg("woah test", &["mailto:jjtech@jjtech.dev".to_string()]);
    //client.send(&mut msg).await.unwrap();

    //sleep(Duration::from_millis(10000)).await;
    
    loop {
        let msg = client.recieve().await;
        if let Some(msg) = msg {
            match msg {
                RecievedMessage::Message { msg } => {
                    println!("[{}]: {}", msg.sender, msg.text);
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}
