
use std::{io::Cursor, path::PathBuf, sync::Arc};

use base64::engine::general_purpose;
use icloud_auth::{AnisetteConfiguration, AppleAccount};
use log::{info, error};
use open_absinthe::nac::HardwareConfig;
use rustpush::{authenticate_apple, get_gateways_for_mccmnc, init_logger, register, APSConnectionResource, APSState, ConversationData, IDSUser, IMClient, MessageInst, MacOSConfig, Message, MessageType, NormalMessage, RelayConfig};
use tokio::{fs, io::{self, AsyncBufReadExt, BufReader}};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::io::Write;
use base64::Engine;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APSState,
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

#[tokio::main(worker_threads = 1)]
async fn main() {
    init_logger();

    // info!("here {}", get_gateways_for_mccmnc("310160").await.unwrap());

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
    
    
    
    let config: Arc<MacOSConfig> = Arc::new(if let Ok(config) = plist::from_file("hwconfig.plist") {
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
    });
    // let host = "https://registration-relay.beeper.com".to_string();
    // let code = "BZUL-7TB6-JUGN-6Q6W".to_string();
    // let token = Some("5c175851953ecaf5209185d897591badb6c3e712".to_string());
    // let config: Arc<RelayConfig> = Arc::new(RelayConfig {
    //     version: RelayConfig::get_versions(&host, &code, &token).await.unwrap(),
    //     icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
    //     aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
    //     dev_uuid: Uuid::new_v4().to_string(),
    //     protocol_version: 1640,
    //     host,
    //     code,
    //     beeper_token: token,
    // });
    // fs::write("hwconfig.plist", plist_to_string(config.as_ref()).unwrap()).await.unwrap();
	
    let saved_state: Option<SavedState> = plist::from_reader_xml(Cursor::new(&data)).ok();

    let (connection, error) = 
        APSConnectionResource::new(
            config.clone(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await;

    
    if let Some(error) = error {
        panic!("{}", error);
    }
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

        let user = authenticate_apple(&user_trimmed, &pet, config.as_ref()).await.unwrap();

        vec![user]
    };

    if users[0].registration.is_none() {
        info!("Registering new identity...");
        register(config.as_ref(), &*connection.state.read().await, &mut users).await.unwrap();
    }

    let mut state = SavedState {
        push: connection.state.read().await.clone(),
        users: users.clone()
    };
    fs::write("config.plist", plist_to_string(&state).unwrap()).await.unwrap();
    
    let client = IMClient::new(connection.clone(), users, "id_cache.plist".into(), config, Box::new(move |updated_keys| {
        state.users = updated_keys;
        std::fs::write("config.plist", plist_to_string(&state).unwrap()).unwrap();
    })).await;
    let handle = client.identity.get_handles().await[0].clone();


    //sleep(Duration::from_millis(10000)).await;

    let mut filter_target = String::new();

    let mut read_task = tokio::spawn(read_input());

    print!(">> ");
    std::io::stdout().flush().unwrap();

    let mut received_msgs = vec![];
    
    loop {
        tokio::select! {
            msg = client.receive_wait() => {
                if msg.is_err() {
                    error!("Failed to receive {}", msg.err().unwrap());
                    continue;
                }
                if let Ok(Some(msg)) = msg {
                    if msg.has_payload() && !received_msgs.contains(&msg.id) {
                        received_msgs.push(msg.id.clone());
                        println!("{}", msg);
                        print!(">> ");
                        std::io::stdout().flush().unwrap();
                        if msg.send_delivered {
                            println!("sending delivered");
                            let mut msg2 = MessageInst::new(msg.conversation.unwrap(), &handle, Message::Delivered);
                            msg2.id = msg.id;
                            msg2.target = msg.target;
                            let _ = client.send(&mut msg2).await;
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
                } else if input.trim() == "sms" {
                    let mut msg = MessageInst::new(ConversationData {
                        participants: vec![],
                        cv_name: None,
                        sender_guid: Some(Uuid::new_v4().to_string()),
                        after_guid: None,
                    }, &handle, Message::EnableSmsActivation(true));
                    client.send(&mut msg).await.unwrap();
                    println!("sms activated");
                } else {
                    if filter_target == "" {
                        println!("Usage: filter [target]");
                    } else {
                        let mut msg = MessageInst::new(ConversationData {
                            participants: vec![filter_target.clone()],
                            cv_name: None,
                            sender_guid: Some(Uuid::new_v4().to_string()),
                            after_guid: None,
                        }, &handle, Message::Message(NormalMessage::new(input.trim().to_string(), MessageType::IMessage)));
                        if let Err(err) = client.send(&mut msg).await {
                            error!("Error sending message {err}");
                        }
                    }
                }
                print!(">> ");
                std::io::stdout().flush().unwrap();
                read_task = tokio::spawn(read_input());
            },
        }
    }
}
