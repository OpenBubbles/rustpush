
use std::sync::Arc;

use log::{info, error};
use rustpush::{APNSState, IDSUser, APNSConnection, IDSAppleUser, IDSError, register, IMClient, Attachment, ConversationData, Message, NormalMessage, MessageParts, MessagePart, RecievedMessage};
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use tokio::time::{sleep, Duration};
use serde::{Serialize, Deserialize};
use std::io::Write;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    users: Vec<IDSUser>
}

#[tokio::main]
async fn main() {
    let data: String = match fs::read_to_string("config.json").await {
		Ok(v) => v,
		Err(e) => {
			match e.kind() {
				io::ErrorKind::NotFound => {
					let _ = fs::File::create("config.json").await.expect("Unable to create file").write_all(b"{}");
					"{}".to_string()
				}
				_ => {
				    error!("Unable to read file");
					std::process::exit(1);
				}
			}
		}
	};
	
    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();

    let connection = Arc::new(APNSConnection::new(saved_state.as_ref().map(|state| state.push.clone())).await.unwrap());

    let mut users = if let Some(state) = saved_state.as_ref() {
        state.users.clone()
    } else {
        let stdin = io::stdin();
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        let mut reader = BufReader::new(stdin);
        let mut username = String::new();
        reader.read_line(&mut username).await.unwrap();
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let mut password = String::new();
        reader.read_line(&mut password).await.unwrap();

        let mut twofa_code = "".to_string();
        loop {
            let resp = IDSAppleUser::authenticate(connection.clone(), username.trim(), &(password.trim().to_string() + &twofa_code)).await;
            match resp {
                Ok(user) => {
                    break vec![user]
                }
                Err(IDSError::TwoFaError) => {
                    print!("2fa code: ");
                    std::io::stdout().flush().unwrap();
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

    if users[0].identity.is_none() {
        info!("Registering new identity...");
        print!("Enter validation data: ");
        std::io::stdout().flush().unwrap();
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut validation = String::new();
        reader.read_line(&mut validation).await.unwrap();
        register(&validation, &mut users, connection.clone()).await.unwrap();
    }

    let state = SavedState {
        push: connection.state.clone(),
        users: users.clone()
    };
    let serialized = serde_json::to_string(&state).unwrap();
    fs::write("config.json", serialized).await.unwrap();
    
    let users = Arc::new(users);
    let mut client = IMClient::new(connection.clone(), users.clone()).await;

    //client.validate_targets(&["mailto:testu3@icloud.com".to_string()]).await.unwrap();


    //let mut msg = client.new_msg("ya test", &["tel:+17203818329".to_string()]);
    //let mut msg = client.new_msg("woah test", &["mailto:jjtech@jjtech.dev".to_string()]);
    /*let data = fs::read("upload.png").await.expect("Unable to read file");
    let attachment = Attachment::new_mmcs(&connection, &data, "image/jpeg", "public.jpeg", "3f80ecc9-2ca9-4a77-a208-cfe3104ca27f.jpeg", 1).await.unwrap();
    let mut msg = client.new_msg(ConversationData {
        participants: vec!["mailto:tanay@neotia.in".to_string()],
        cv_name: None,
        sender_guid: Some(Uuid::new_v4().to_string())
    }, imessage::Message::Message(NormalMessage {
        text: "".to_string(),
        attachments: vec![attachment],
        body: None,
        effect: None,
        reply_guid: None,
        reply_part: None
    })).await;
    println!("sendingrun");
    client.send(&mut msg).await.unwrap();
    println!("sendingdone");*/

    let data = fs::read("upload.png").await.expect("Unable to read file");
    println!("upload attachment");
    let attachment = Attachment::new_mmcs(&connection, &data, "application/octet-stream", "public.data", "upload.png").await.unwrap();
    println!("uploaded attachment");
    let mut msg = client.new_msg(ConversationData {
        participants: vec!["tel:+17203818329".to_string()],
        cv_name: None,
        sender_guid: Some(Uuid::new_v4().to_string())
    }, Message::Message(NormalMessage {
        parts: MessageParts(vec![
            MessagePart::Attachment(attachment),
            MessagePart::Text("Sent from pure rust!".to_string())
        ]),
        body: None,
        effect: None,
        reply_guid: None,
        reply_part: None
    })).await;
    println!("sendingrun");
    client.send(&mut msg).await.unwrap();
    println!("sendingdone");

    //sleep(Duration::from_millis(10000)).await;
    
    loop {
        let msg = client.recieve().await;
        if let Some(msg) = msg {
            match msg {
                RecievedMessage::Message { msg } => {
                    if msg.has_payload() {
                        println!("{}", msg);
                        if let Message::Message(msg) = msg.message {
                            for part in msg.parts.0 {
                                if let MessagePart::Attachment(attachment) = part {
                                    let data = attachment.get_attachment(&connection).await.unwrap();
                                    fs::write("download.png", data).await.unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}
