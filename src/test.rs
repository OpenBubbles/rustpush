
use std::{fs::File, io::Cursor, path::PathBuf, sync::Arc, time::{Duration, SystemTime}};

use base64::engine::general_purpose;
use icloud_auth::AppleAccount;
use log::{debug, error, info};
use omnisette::{default_provider, AnisetteHeaders};
use open_absinthe::nac::HardwareConfig;
use rustpush::{authenticate_apple, findmy::{FindMyClient, FindMyState, MULTIPLEX_SERVICE}, get_gateways_for_mccmnc, login_apple_delegates, prepare_put, register, sharedstreams::{round_seconds, AssetDetails, AssetFile, AssetMetadata, CollectionMetadata, FileMetadata, FilePackager, PreparedAsset, PreparedFile, SharedStreamClient, SharedStreamsState, SyncController, SyncState, FFMpegFilePackager}, APSConnectionResource, APSState, Attachment, ConversationData, FileContainer, IDSUser, IDSUserIdentity, IMClient, IndexedMessagePart, LoginDelegate, MMCSFile, MacOSConfig, Message, MessageInst, MessageParts, MessageType, NormalMessage, PushError, RelayConfig, MADRID_SERVICE};
use tokio::{fs, io::{self, AsyncBufReadExt, BufReader}, process::Command};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::io::Write;
use base64::Engine;
use std::str::FromStr;
use std::io::Seek;
use rustpush::OSConfig;
use std::fmt::{Display, Write as FmtWrite};

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APSState,
    users: Vec<IDSUser>,
    identity: IDSUserIdentity,
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
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::try_init().unwrap();

    // debug!("item {}", plist_to_string(&IDSUserIdentity::new().unwrap()).unwrap());

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
    fs::write("hwconfig.plist", plist_to_string(config.as_ref()).unwrap()).await.unwrap();
	
    let saved_state: Option<SavedState> = plist::from_reader_xml(Cursor::new(&data)).ok();

    let (connection, error) = 
        APSConnectionResource::new(
            config.clone(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await;

    let mut subscription = connection.messages_cont.subscribe();

    let mut anisette_client = default_provider(config.get_gsa_config(&*connection.state.read().await), PathBuf::from_str("anisette_test").unwrap());

    
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


        
        let acc = AppleAccount::login(appleid_closure, tfa_closure, 
                config.get_gsa_config(&*connection.state.read().await), anisette_client.clone()).await;

        let account: AppleAccount<_> = acc.unwrap();
        let pet = account.get_pet().unwrap();
        let spd = account.spd.as_ref().unwrap();

        let delegates = login_apple_delegates(&user_trimmed, &pet, spd["adsid"].as_string().unwrap(), None, &mut *anisette_client.lock().await, config.as_ref(), &[LoginDelegate::IDS, LoginDelegate::MobileMe]).await.unwrap();
        let user = authenticate_apple(delegates.ids.unwrap(), config.as_ref()).await.unwrap();

        let mobileme = delegates.mobileme.unwrap();
        let findmy = FindMyState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), spd["acname"].as_string().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("findmy.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&findmy).unwrap()).unwrap();

        let sharedstreams = SharedStreamsState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&sharedstreams).unwrap()).unwrap();

        vec![user]
    };
    
    let services = &[&MADRID_SERVICE, &MULTIPLEX_SERVICE];

    let identity = saved_state.as_ref().map(|state| state.identity.clone()).unwrap_or(IDSUserIdentity::new().unwrap());

    if users[0].registration.is_empty() {
        info!("Registering new identity...");
        register(config.as_ref(), &*connection.state.read().await, services, &mut users, &identity).await.unwrap();
    }

    let mut state = SavedState {
        push: connection.state.read().await.clone(),
        identity: identity.clone(),
        users: users.clone()
    };
    fs::write("config.plist", plist_to_string(&state).unwrap()).await.unwrap();
    
    let client = IMClient::new(connection.clone(), users, identity, services, "id_cache.plist".into(), config.clone(), Box::new(move |updated_keys| {
        state.users = updated_keys;
        std::fs::write("config.plist", plist_to_string(&state).unwrap()).unwrap();
    })).await;
    let handle = client.identity.get_handles().await[0].clone();


    let id_path = PathBuf::from_str("findmy.plist").unwrap();
    let state: FindMyState = plist::from_file(id_path).unwrap();

    let findmy_client = FindMyClient::new(connection.clone(), config.clone(), state, anisette_client.clone(), client.identity.clone()).await.unwrap();


    let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
    let state: SharedStreamsState = plist::from_file(&id_path).unwrap();

    let shared_streams = SharedStreamClient::new(state, Box::new(move |update| {
        plist::to_file_xml(&id_path, update).unwrap();
    }), connection.clone(), anisette_client.clone(), config.clone()).await;
    shared_streams.get_changes().await.unwrap();
    let album = shared_streams.state.read().await.albums[0].albumguid.clone();
    shared_streams.get_album_summary(&album).await.unwrap();



    let manager = SyncController::new(shared_streams, PathBuf::from_str("syncstate.plist").unwrap(), FFMpegFilePackager::default(), Duration::from_secs(60 * 30)).await;


    
    // plist::to_file_xml("syncstate.plist", &syncstate).unwrap();



    // pub fn encode_hex(bytes: &[u8]) -> String {
    //     let mut s = String::with_capacity(bytes.len() * 2);
    //     for &b in bytes {
    //         write!(&mut s, "{:02x}", b).unwrap();
    //     }
    //     s
    // }


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut file = File::open("IMG_0153.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let derivative_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let mut file = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let thumb_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let asset = AssetDetails {
    //     filename: format!("{}.HEIC", Uuid::new_v4().to_string().to_uppercase()),
    //     assetguid: Uuid::new_v4().to_string().to_uppercase(),
    //     createdbyme: "1".to_string(),
    //     candelete: "1".to_string(),
    //     collectionmetadata: CollectionMetadata {
    //         batch_date_created: round_seconds(batch_date_created).into(),
    //         batch_guid,
    //         date_created: round_seconds(fs::metadata("149E5C12-E3BD-4A82-B8B8-5F2E44DA0260.HEIC").await.unwrap().created().unwrap()).into(),
    //         playback_variation: 0,
    //     },
    //     files: vec![AssetFile {
    //         size: derivative_pre.total_len.to_string(),
    //         checksum: encode_hex(&derivative_pre.total_sig),
    //         width: "1536".to_string(),
    //         height: "2048".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "derivative".to_string(),
    //             asset_type_flags: 2,
    //         }
    //     },AssetFile {
    //         size: thumb_pre.total_len.to_string(),
    //         checksum: encode_hex(&thumb_pre.total_sig),
    //         width: "257".to_string(),
    //         height: "342".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "thumbnail".to_string(),
    //             asset_type_flags: 1,
    //         }
    //     }]
    // };

    // let mut der = File::open("IMG_0153.HEIC").unwrap();
    // let mut thum = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(derivative_pre, &mut der), (thumb_pre, &mut thum)], &mut |_a, _b| {}).await.unwrap();


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut der = File::open("JPG_Test.jpg").unwrap();
    // let (asset, prepared) = AssetDetails::from_file(PathBuf::from_str("JPG_Test.jpg").unwrap(), batch_date_created, batch_guid).await.unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(prepared, &mut der)], &mut |_a, _b| {}).await;


    // shared_streams.get_album_summary(&shared_streams.albums[0].albumguid.clone()).await.unwrap();
    // let assets = shared_streams.get_assets(&shared_streams.albums[0].albumguid.clone(), &shared_streams.albums[0].assets.clone()).await.unwrap();
    // let mut files: Vec<_> = assets.iter().flat_map(|a| {
    //     a.files.iter().map(|file| (file, File::create(format!("mine{}_{}", file.metadata.asset_type, &a.filename)).unwrap()))
    // }).collect();
    // let mut copy: Vec<_> = files.iter_mut().map::<(&AssetFile, &mut (dyn Write + Send + Sync)), _>(|a| {
    //     (a.0, &mut a.1)
    // }).collect();
    // shared_streams.get_file(&mut copy, &mut |_a, _b| {}).await.unwrap();


    // println!("here {:?}", shared_streams.albums);

    // client.identity.refresh_now().await.unwrap();


    //sleep(Duration::from_millis(10000)).await;

    let mut filter_target = String::new();

    let mut read_task = tokio::spawn(read_input());

    print!(">> ");
    std::io::stdout().flush().unwrap();

    let mut received_msgs = vec![];
    
    loop {
        tokio::select! {
            msg = subscription.recv() => {
                let msg = msg.unwrap();
                let _ = findmy_client.handle(msg.clone()).await;
                let _ = manager.handle(msg.clone()).await;
                let msg = client.handle(msg).await;
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
                        let mut msg = NormalMessage::new(input.trim().to_string(), MessageType::IMessage);
                        msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);
                        let mut msg = MessageInst::new(ConversationData {
                            participants: vec![filter_target.clone()],
                            cv_name: None,
                            sender_guid: Some(Uuid::new_v4().to_string()),
                            after_guid: None,
                        }, &handle, Message::Message(msg));

                        // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);

                        if let Err(err) = client.send(&mut msg).await {
                            error!("Error sending message {err}");
                        }

                        tokio::time::sleep(Duration::from_secs(10)).await;

                        msg.message = Message::Unschedule;
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
