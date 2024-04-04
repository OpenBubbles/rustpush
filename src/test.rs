
use std::{io::Cursor, path::PathBuf, sync::Arc};

use base64::engine::general_purpose;
use icloud_auth::{AnisetteConfiguration, AppleAccount};
use log::{info, error};
use open_absinthe::nac::HardwareConfig;
use rustpush::{init_logger, register, APNSConnection, APNSState, ConversationData, IDSAppleUser, IDSUser, IMClient, MacOSConfig, Message, NormalMessage, OSConfig, RecievedMessage};
use tokio::{fs, io::{self, BufReader, AsyncBufReadExt}};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::io::Write;
use base64::Engine;
use std::str::FromStr;

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

async fn read_input() -> String {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut username = String::new();
    reader.read_line(&mut username).await.unwrap();
    username
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
        print!("Validation data: ");
        std::io::stdout().flush().unwrap();
        let validation_data_b64 = read_input().await;

        let validation_data = general_purpose::STANDARD.decode(validation_data_b64.trim()).unwrap();
        let extracted = HardwareConfig::from_validation_data(&validation_data).unwrap();

        MacOSConfig {
            inner: extracted,
            version: "13.6.4".to_string(),
            protocol_version: 1660,
            device_id: Uuid::new_v4().to_string(),
            icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
            aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
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
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        let username = read_input().await;
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let password = read_input().await;

        let user_trimmed = username.trim().to_string();
        let pw_trimmed = password.trim().to_string();

        let user_two = user_trimmed.clone();
        let appleid_closure = move || (user_two.clone(), pw_trimmed.clone());
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        let acc = AppleAccount::login(appleid_closure, tfa_closure, AnisetteConfiguration::new()
            .set_configuration_path(PathBuf::from_str("anisette_test").unwrap())).await;

        let account = acc.unwrap();
        let pet = account.get_pet().unwrap();

        let user = IDSAppleUser::authenticate(&connection, &user_trimmed, &pet, &config).await.unwrap();

        vec![user]
    };

    if users[0].identity.is_none() {
        info!("Registering new identity...");
        register(&config, &mut users, &connection).await.unwrap();
    }

    println!("registration expires at {}", users[0].identity.as_ref().unwrap().get_exp().unwrap());

    let mut state = SavedState {
        push: connection.state.clone(),
        users: users.clone()
    };
    fs::write("config.plist", plist_to_string(&state).unwrap()).await.unwrap();

    let os_config: Arc<dyn OSConfig> = Arc::new(config);
    
    let client = IMClient::new(connection.clone(), users, "id_cache.plist".into(), os_config, Box::new(move |updated_keys| {
        state.users = updated_keys;
        std::fs::write("config.plist", plist_to_string(&state).unwrap()).unwrap();
    })).await;
    let handle = client.get_handles().await[0].clone();


    //sleep(Duration::from_millis(10000)).await;

    let mut filter_target = String::new();

    let mut read_task = tokio::spawn(read_input());

    print!(">> ");
    std::io::stdout().flush().unwrap();

    let mut received_msgs = vec![];
    
    loop {
        tokio::select! {
            msg = client.recieve_wait() => {
                if let Some(msg) = msg {
                    match msg {
                        RecievedMessage::Message { msg } => {
                            if msg.has_payload() && !received_msgs.contains(&msg.id) {
                                received_msgs.push(msg.id.clone());
                                println!("{}", msg);
                                print!(">> ");
                                std::io::stdout().flush().unwrap();
                                match msg.message {
                                    Message::Message(_inner) => {
                                        let mut msg2 = client.new_msg(msg.conversation.unwrap(), &handle, Message::Delivered).await;
                                        msg2.id = msg.id;
                                        client.send(&mut msg2).await.unwrap();
                                    },
                                    Message::React(_inner) => {
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
                            }
                        }
                    }
                }
            },
            input = &mut read_task => {
                let Ok(input) = input else {
                    read_task = tokio::spawn(read_input());
                    continue;
                };
                if input.trim() == "" {
                    print!(">> ");
                    std::io::stdout().flush().unwrap();
                    read_task = tokio::spawn(read_input());
                    continue;
                }
                if input.starts_with("filter ") {
                    filter_target = input.strip_prefix("filter ").unwrap().to_string().trim().to_string();
                    println!("Filtering to {}", filter_target);
                } else {
                    if filter_target == "" {
                        println!("Usage: filter [target]");
                    } else {
                        let mut msg = client.new_msg(ConversationData {
                            participants: vec![filter_target.clone()],
                            cv_name: None,
                            sender_guid: Some(Uuid::new_v4().to_string())
                        }, &handle, Message::Message(NormalMessage::new(input.trim().to_string()))).await;
                        client.send(&mut msg).await.unwrap();
                    }
                }
                print!(">> ");
                std::io::stdout().flush().unwrap();
                read_task = tokio::spawn(read_input());
            },
        }
    }
}
