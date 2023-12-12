use std::sync::Arc;

use log::{error, info};
use rustpush::{
    init_logger, register, APNSConnection, APNSState, ConversationData, IDSAppleUser, IDSUser,
    IMClient, Message, NormalMessage, PushError, RecievedMessage,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, BufReader},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    users: Vec<IDSUser>,
}

#[tokio::main]
async fn main() {
    init_logger();
    let data: String = match fs::read_to_string("config.json").await {
        Ok(v) => v,
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => {
                let _ = fs::File::create("config.json")
                    .await
                    .expect("Unable to create file")
                    .write_all(b"{}");
                "{}".to_string()
            }
            _ => {
                error!("Unable to read file");
                std::process::exit(1);
            }
        },
    };

    // Read serial number from command line arg, otherwise prompt for it
    let mut serial_number: Option<String> = None;
    for arg in std::env::args() {
        if arg.starts_with("--serial=") {
            serial_number = Some(arg.split("=").collect::<Vec<&str>>()[1].to_string());
        }
    }
    let serial_number = match serial_number {
        Some(v) => v,
        None => {
            let stdin = io::stdin();
            print!("Serial Number: ");
            std::io::stdout().flush().unwrap();
            let mut reader = BufReader::new(stdin);
            let mut serial_number = String::new();
            reader.read_line(&mut serial_number).await.unwrap();
            serial_number.trim().to_string()
        }
    };

    let saved_state: Option<SavedState> = serde_json::from_str(&data).ok();

    let connection = Arc::new(
        APNSConnection::new(
            serial_number.as_str(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await
        .unwrap(),
    );

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
            let resp = IDSAppleUser::authenticate(
                connection.clone(),
                username.trim(),
                &(password.trim().to_string() + &twofa_code),
            )
            .await;
            match resp {
                Ok(user) => break vec![user],
                Err(PushError::TwoFaError) => {
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
        register(&validation, &mut users, connection.clone())
            .await
            .unwrap();
    }

    let state = SavedState {
        push: connection.state.clone(),
        users: users.clone(),
    };
    let serialized = serde_json::to_string(&state).unwrap();
    fs::write("config.json", serialized).await.unwrap();

    let users = Arc::new(users);
    let mut client = IMClient::new(connection.clone(), users.clone()).await;
    let handle = client.get_handles()[0].clone();

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

    /*println!("prepare attachment");
    let mut data = std::fs::File::open("upload.png").unwrap();
    let prepared = MMCSFile::prepare_put(&mut data).await.unwrap();
    println!("upload attachment");
    data.rewind().unwrap();
    let attachment = MMCSFile::new(&connection, &prepared, &mut data, &mut |curr, total| {
        println!("uploaded attachment bytes {} of {}", curr, total);
    }).await.unwrap();
    println!("uploaded attachment");
    let mut msg = client.new_msg(ConversationData {
        participants: vec!["mailto:testu3@icloud.com".to_string(), "mailto:textgpt@icloud.com".to_string()],
        cv_name: Some("Hjiih".to_string()),
        sender_guid: Some(Uuid::new_v4().to_string())
    }, Message::IconChange(IconChangeMessage { file: attachment, group_version: 87 })).await;
    println!("sendingrun");
    client.send(&mut msg).await.unwrap();
    println!("sendingdone");*/

    /*println!("prepare attachment");
    let mut data = std::fs::File::open("upload.png").unwrap();
    let prepared = MMCSFile::prepare_put(&mut data).await.unwrap();
    println!("upload attachment");
    data.rewind().unwrap();
    let attachment = MMCSFile::new(&connection, &prepared, &mut data, &mut |curr, total| {
        println!("uploaded attachment bytes {} of {}", curr, total);
    }).await.unwrap();
    println!("uploaded attachment");*/
    let mut msg = client
        .new_msg(
            ConversationData {
                participants: vec!["mailto:sandboxalt@gmail.com".to_string()],
                cv_name: None,
                sender_guid: Some(Uuid::new_v4().to_string()),
            },
            &handle,
            Message::Message(NormalMessage::new("hello world!".to_string())),
        )
        .await;
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
                        match msg.message {
                            Message::Message(inner) => {
                                let mut msg2 = client
                                    .new_msg(msg.conversation.unwrap(), &handle, Message::Delivered)
                                    .await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            }
                            Message::React(inner) => {
                                let mut msg2 = client
                                    .new_msg(msg.conversation.unwrap(), &handle, Message::Delivered)
                                    .await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            }
                            Message::Typing => {
                                let mut msg2 = client
                                    .new_msg(msg.conversation.unwrap(), &handle, Message::Delivered)
                                    .await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            }
                            _ => {}
                        }
                        /*if let Message::IconChange(msg) = msg.message {
                            let mut file = std::fs::File::create("download.png").unwrap();
                            msg.file.get_attachment(&connection, &mut file, &mut |curr, total| {
                                //println!("downloaded attachment bytes {} of {}", curr, total);
                            }).await.unwrap();
                            file.flush().unwrap();
                        }*/
                    }
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}
