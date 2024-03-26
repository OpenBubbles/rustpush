
use std::{io::{Cursor, Seek}, sync::Arc};

use base64::engine::general_purpose;
use log::{info, error};
use open_abinsthe::nac::HardwareConfig;
use openssl::ex_data::Index;
use rustpush::{init_logger, register, APNSConnection, APNSState, ConversationData, IDSAppleUser, IDSUser, IMClient, IconChangeMessage, IndexedMessagePart, MMCSFile, MacOSConfig, Message, MessagePart, MessageParts, NormalMessage, OSConfig, PushError, RecievedMessage};
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use tokio::time::{sleep, Duration};
use serde::{Serialize, Deserialize};
use std::io::Write;
use base64::Engine;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APNSState,
    users: Vec<IDSUser>
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

#[tokio::main]
async fn main() {
    init_logger();
    let data: String = match fs::read_to_string("config.plist").await {
		Ok(v) => v,
		Err(e) => {
			match e.kind() {
				io::ErrorKind::NotFound => {
					let _ = fs::File::create("config.plist").await.expect("Unable to create file").write_all(b"{}");
					"{}".to_string()
				}
				_ => {
				    error!("Unable to read file");
					std::process::exit(1);
				}
			}
		}
	};
    
    
    
    let config: MacOSConfig = if let Ok(config) = plist::from_file("hwconfig.plist") {
        config
    } else {
        println!("Missing hardware config!");
        println!("The easiest way to get your hardware config is to extract it from validation data from a Mac.");
        println!("This validation data will not be used to authenticate, and therefore does not need to be recent or valid.");
        println!("If you need help obtaining validation data, please visit https://github.com/beeper/mac-registration-provider");
        println!("As long as the hardware identifiers are valid rustpush will work fine.");
        println!("Validation data will not be required for subsequent re-registrations.");
        // save hardware config
        let stdin = io::stdin();
        print!("Validation data: ");
        std::io::stdout().flush().unwrap();
        let mut reader = BufReader::new(stdin);
        let mut validation_data_b64 = String::new();
        reader.read_line(&mut validation_data_b64).await.unwrap();

        let validation_data = general_purpose::STANDARD.decode(validation_data_b64.trim()).unwrap();
        let extracted = HardwareConfig::from_validation_data(&validation_data).unwrap();

        MacOSConfig {
            inner: extracted,
            version: "13.6.4".to_string(),
            protocol_version: 1660,
            device_id: Uuid::new_v4().to_string(),
        }
    };
    fs::write("hwconfig.plist", plist_to_string(&config).unwrap()).await.unwrap();
	
    let saved_state: Option<SavedState> = plist::from_reader_xml(Cursor::new(&data)).ok();

    let connection = Arc::new(
        APNSConnection::new(
            &config,
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
            let resp = IDSAppleUser::authenticate(connection.clone(), username.trim(), &(password.trim().to_string() + &twofa_code), &config).await;
            match resp {
                Ok(user) => {
                    break vec![user]
                }
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
        register(&config, &mut users, connection.clone()).await.unwrap();
    }

    println!("registration expires at {}", users[0].identity.as_ref().unwrap().get_exp().unwrap());

    let mut state = SavedState {
        push: connection.state.clone(),
        users: users.clone()
    };
    fs::write("config.plist", plist_to_string(&state).unwrap()).await.unwrap();

    let os_config: Arc<dyn OSConfig> = Arc::new(config);
    
    let mut client = IMClient::new(connection.clone(), users, "cached_ids.plist".to_string(), os_config, Box::new(move |updated_keys| {
        state.users = updated_keys;
        std::fs::write("config.plist", plist_to_string(&state).unwrap()).unwrap();
    })).await;
    let handle = client.get_handles().await[0].clone();

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
    let mut msg = client.new_msg(ConversationData {
        participants: vec!["mailto:jjtech@jjtech.dev".to_string()],
        cv_name: None,
        sender_guid: Some(Uuid::new_v4().to_string())
    }, &handle, Message::Message(NormalMessage::new("hi".to_string()))).await;
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
                                let mut msg2 = client.new_msg(msg.conversation.unwrap(), &handle, Message::Delivered).await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            },
                            Message::React(inner) => {
                                let mut msg2 = client.new_msg(msg.conversation.unwrap(), &handle, Message::Delivered).await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            },
                            Message::Typing => {
                                let mut msg2 = client.new_msg(msg.conversation.unwrap(), &handle, Message::Delivered).await;
                                msg2.id = msg.id;
                                client.send(&mut msg2).await.unwrap();
                            },
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
