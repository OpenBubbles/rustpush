
use std::{fs::File, io::{Cursor, Read}, num::ParseIntError, path::PathBuf, sync::{Arc, Mutex}, time::{Duration, SystemTime}};

use aes_siv::{Aes256SivAead, Nonce};
use base64::{alphabet::STANDARD, engine::general_purpose};
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{CloudKitRecord, CloudKitValue, CuttlefishSerializedKey, ZoneRetrieveRequest, base64_encode};
use hkdf::Hkdf;
use icloud_auth::{AppleAccount, LoginState};
use log::{debug, error, info, warn};
use omnisette::{default_provider, AnisetteHeaders, DefaultAnisetteProvider};
use open_absinthe::nac::HardwareConfig;
use openssl::sha::sha256;
use plist::{Data, Dictionary, Value};
use rustpush::{APSConnectionResource, APSState, Attachment, CircleClientSession, CircleServerSession, CompactECKey, ConversationData, EntitlementAuthState, FileContainer, IDSNGMIdentity, IDSUser, IDSUserIdentity, IMClient, IdmsAuthListener, IdmsMessage, IndexedMessagePart, KeyedArchive, LoginDelegate, MADRID_SERVICE, MMCSFile, Message, MessageInst, MessageParts, MessageType, NormalMessage, PushError, RelayConfig, ShareProfileMessage, SharedPoster, TokenProvider, UpdateProfileMessage, authenticate_apple, authenticate_smsless, cloud_messages::{CloudMessagesClient, MESSAGES_SERVICE}, cloudkit::{CloudKitClient, CloudKitContainer, CloudKitSession, CloudKitState, DeleteRecordOperation, FetchZoneOperation, ZoneDeleteOperation, ZoneSaveOperation, record_identifier}, facetime::{FACETIME_SERVICE, FTClient, FTMember, FTMessage, FTState, VIDEO_SERVICE}, findmy::{BeaconNamingRecord, FindMyClient, FindMyState, FindMyStateManager, MULTIPLEX_SERVICE}, get_gateways_for_mccmnc, keychain::{CloudKey, KEYCHAIN_ZONES, KeychainClient, KeychainClientState}, login_apple_delegates, macos::MacOSConfig, name_photo_sharing::{IMessageNameRecord, IMessageNicknameRecord, IMessagePosterRecord, ProfilesClient}, pcs::{PCSKey, PCSPrivateKey}, posterkit::{PhotoPosterContentsFrame, PosterType, SimplifiedIncomingCallPoster, SimplifiedPoster, SimplifiedTranscriptPoster, TranscriptDynamicUserData}, prepare_put, register, sharedstreams::{AssetDetails, AssetFile, AssetMetadata, CollectionMetadata, FFMpegFilePackager, FileMetadata, FilePackager, PreparedAsset, PreparedFile, SharedStreamClient, SharedStreamsState, SyncController, SyncState, round_seconds}, statuskit::{StatusKitClient, StatusKitState, StatusKitStatus}};
use sha2::Sha256;
use tokio::{fs, io::{self, AsyncBufReadExt, BufReader}, process::Command, sync::RwLock};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zip::ZipArchive;
use std::io::Write;
use base64::Engine;
use std::str::FromStr;
use std::io::Seek;
use rustpush::OSConfig;
use std::fmt::{Display, Write as FmtWrite};
use omnisette::AnisetteProvider;
use rand::Rng;
use serde_json::json;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APSState,
    users: Vec<IDSUser>,
    identity: IDSNGMIdentity,
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for i in arr {
                sort_value(i);
            }
        },
        Value::Dictionary(dict) => {
            dict.sort_keys();
            for val in dict.values_mut() {
                sort_value(val);
            }
        },
        _ => {}
    }
}
fn read_file<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_bytes(&manifest)?)
}

fn read_archive<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_value(&KeyedArchive::expand_root(&manifest)?)?)
}

pub fn parse_poster(poster: &IMessagePosterRecord) -> Result<String, PushError> {
    let meta: Value = plist::from_bytes(&poster.meta)?;

    let mut archive = ZipArchive::new(Cursor::new(&poster.package))?;
    let manifest: Value = read_file(&mut archive, "manifest.plist").unwrap();
    
    let suggestion: Value = read_archive(&mut archive, "configuration/com.apple.posterkit.provider.identifierURL.suggestionMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let complication: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.complicationLayout.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let rendering: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.renderingConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // monogram/animoji
    let title_style: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let user_info: Value = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // animoji
    let color_variations: Value = read_file(&mut archive, "configuration/versions/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // image only
    let color_variations2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let titlestyle2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let other_meta: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.otherMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let homescreen: Value = read_archive(&mut archive, "configuration/versions/0/supplements/0/com.apple.posterkit.provider.supplementURL.homescreenConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let model: Value = read_archive(&mut archive, "configuration/versions/0/contents/ConfigurationModel.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let style: Value = read_file(&mut archive, "configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/style.plist").unwrap_or(Value::Dictionary(Dictionary::new()));

    let mut json = vec![];
    if let Ok(mut file) = archive.by_name("configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/Contents.json") {
        file.read_to_end(&mut json).unwrap();
    }

    let mut end = Value::Dictionary(Dictionary::from_iter([
        ("meta", meta),
        ("manifest", manifest),
        ("suggestion", suggestion),
        ("complication", complication),
        ("rendering", rendering),
        ("homescreen", homescreen),
        ("other_meta", other_meta),
        ("model", model),
        ("json", Value::String(String::from_utf8(json).unwrap())),
        ("style", style),
        ("title_style", title_style),
        ("user_info", user_info),
        ("color_variations", color_variations),
        ("titlestyle2", titlestyle2),
        ("color_variations2", color_variations2),
    ]));
    sort_value(&mut end);
    debug!("Poster data {end:?}");

    Ok(plist_to_string(&end)?)
}


async fn handle_record(mut record: IMessageNicknameRecord, client: &IMClient, photo: &ProfilesClient<DefaultAnisetteProvider>, existing: &ShareProfileMessage) {
    if let Some(profile) = record.poster {
        let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        fs::create_dir(format!("posters/{stamp}")).await.unwrap();
        let profile_2 = profile.clone();
        fs::write(format!("posters/{stamp}/image.heif"), profile.low_res_poster).await.unwrap();
        fs::write(format!("posters/{stamp}/data.zip"), profile.package).await.unwrap();
        fs::write(format!("posters/{stamp}/meta.plist"), profile.meta).await.unwrap();
        fs::write(format!("posters/{stamp}/file.plist"), parse_poster(&profile_2).unwrap()).await.unwrap();

        let mut to_poster = SimplifiedIncomingCallPoster::from_poster(&profile_2).unwrap();


        // let PosterType::Photo { assets } = &mut to_poster.r#type else { panic !()};

        // let contents = &mut assets[0].files;

        // contents.remove("portrait-layer_background.HEIC");
        // contents.insert("portrait-layer_background.HEIC".to_string(), fs::read("posters/photo_cropped_2/configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/portrait-layer_background.jpg").await.unwrap());

        // let layer = assets[0].contents.layers.iter_mut().find(|l| l.identifier == "background").unwrap();
        // layer.filename = "portrait-layer_background.PNG".to_string();
        
        // contents.properties.portrait_layout.time_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.properties.portrait_layout.inactive_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.layers[0].frame.y += 200f64;
        // contents.properties.portrait_layout.visible_frame.y -= 200f64; // (slid viewport *DOWN* (could see further down image))

        to_poster.poster.r#type = PosterType::TranscriptDynamic { data: TranscriptDynamicUserData { identifier: "aurora_1".to_string() } };

        let mut by = to_poster.to_poster().unwrap();
        record.poster = Some(by);

        let mut existing = Some(existing.clone());
        photo.set_record(record, &mut existing).await.unwrap();

        client.send(&mut MessageInst::new(
            ConversationData { participants: vec!["mailto:tag3@copper.jjtech.dev".to_string()], cv_name: None, sender_guid: None, after_guid: None }, 
            "mailto:tag3@copper.jjtech.dev", Message::UpdateProfile(UpdateProfileMessage { profile: Some(existing.unwrap()), share_contacts: false }))).await.unwrap();
        
        // fs::write(format!("posters/{stamp}/poster.zip"), &by.package).await.unwrap();
    }
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

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[tokio::main(worker_threads = 1)]
async fn main() {
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::try_init().unwrap();

    // let record = IMessagePosterRecord {
    //     low_res_poster: fs::read("posters/image_style_plain/image.png").await.unwrap(),
    //     package: fs::read("posters/image_style_plain/data.zip").await.unwrap(),
    //     meta: fs::read("posters/image_style_plain/meta.plist").await.unwrap(),
    // };
    

    // panic!();

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

    #[derive(Serialize, Deserialize)]
    struct GSAConfig {
        user: String,
        pass: Data,
    }

    let gsa: GSAConfig = if let Ok(config) = plist::from_file("gsa.plist") {
        config
    } else {
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        let username = read_input().await;
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let password = read_input().await;

        GSAConfig { user: username.trim().to_string(), pass: sha256(password.trim().as_bytes()).to_vec().into() }
    };

    plist::to_file_xml("gsa.plist", &gsa).unwrap();
    
    
    
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
            udid: Some("55A1CFBF5BB56AD1159BD2CB7D6FF546E48EAAE4BF16188A07B1FB9C83138CA2".to_string()),
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
    // let saved_state: Option<SavedState> = None;

    let state: Arc<Mutex<Option<SavedState>>> = Arc::new(Mutex::new(None));
    let (connection, error) = 
        APSConnectionResource::new(
            config.clone(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await;

    let mut subscription = connection.messages_cont.subscribe();

    let mut anisette_client = default_provider(config.get_gsa_config(&*connection.state.read().await, false), PathBuf::from_str("anisette_test").unwrap());

    let mut session: Option<CircleClientSession<DefaultAnisetteProvider>> = None;
    
    if let Some(error) = error {
        panic!("{}", error);
    }
    let mut users = if let Some(state) = saved_state.as_ref() {
        state.users.clone()
    } else {
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        
        let mut account = AppleAccount::new_with_anisette(config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).unwrap();
        let result = account.login_email_pass(&gsa.user, gsa.pass.as_ref()).await.unwrap();


        let spd = account.spd.as_ref().unwrap();
        let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap();

        // account.send_2fa_to_devices().await.unwrap();
        // let result = account.verify_2fa(tfa_closure()).await.unwrap();

        let done = Arc::new(tokio::sync::Mutex::new(account));

        if let LoginState::NeedsDevice2FA = result {
            let mut s = CircleClientSession::new(dsid, done.clone(), connection.get_token().await).await.unwrap();

            let listener = IdmsAuthListener::new(connection.clone()).await;
            let mut subscription = connection.messages_cont.subscribe();

            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let item = input.trim().to_string();

            s.send_code(&item).await.unwrap();


            loop {
                let msg = subscription.recv().await.unwrap();
                
                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("here {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            if s.handle_circle_request(&c).await.unwrap().is_some() {
                                session = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let account = done.lock().await;

        // account.update_postdata("Testing").await.unwrap();
        let pet = account.get_pet().unwrap();
        let spd = account.spd.as_ref().unwrap();

        let delegates = login_apple_delegates(&gsa.user, &pet, spd["adsid"].as_string().unwrap(), None, &mut *anisette_client.lock().await, config.as_ref(), &[LoginDelegate::IDS, LoginDelegate::MobileMe]).await.unwrap();
        let user = authenticate_apple(delegates.ids.unwrap(), config.as_ref()).await.unwrap();

        let mobileme = delegates.mobileme.unwrap();
        let findmy = FindMyState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());

        let id_path = PathBuf::from_str("findmy.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&findmy).unwrap()).unwrap();

        let sharedstreams = SharedStreamsState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&sharedstreams).unwrap()).unwrap();

        let trustedpeers = KeychainClientState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), spd["adsid"].as_string().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&trustedpeers).unwrap()).unwrap();

        let cloudkitstate = CloudKitState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());
        let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&cloudkitstate).unwrap()).unwrap();

        vec![user]
    };

    // TODO DO NOT COMMIT
    let conf = (gsa.user.clone(), gsa.pass.as_ref().to_vec());
    let appleid_closure = move || conf.clone();
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };

    let acc = AppleAccount::login(appleid_closure, tfa_closure, 
        config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).await;
    

    // let mut entitlementstate = EntitlementAuthState::new("0310260600163417@nai.epc.mnc260.mcc310.3gppnetwork.org".to_string(), "310260".to_string(), "358565077172633".to_string());

    // let entitlementresult = entitlementstate.get_entitlements(config.as_ref(), &connection, |challenge| async move {
    //     #[derive(Deserialize)]
    //     struct Response {
    //         response: String,
    //     }

    //     let result: Response = reqwest::Client::new()
    //         .post("http://192.168.99.200:8080/eap_aka")
    //         .json(&json!({
    //             "challenge": challenge
    //         }))
    //         .send().await?
    //         .json().await?;
    //     Ok(result.response)
    // }).await.expect("Failed to get entitlements");
    
    // authenticate_smsless(&entitlementresult.phone, &entitlementresult.host, config.as_ref(), &connection).await.unwrap();

    // panic!("test {:?}", entitlementresult.phone);


    let account = Arc::new(tokio::sync::Mutex::new(acc.unwrap()));
    
    account.lock().await.update_postdata("Apple Device", None, &["icloud", "imessage", "facetime"]).await.unwrap();

    let services = &[&MADRID_SERVICE, &MULTIPLEX_SERVICE, &FACETIME_SERVICE, &VIDEO_SERVICE];

    let identity = saved_state.as_ref().map(|state| state.identity.clone()).unwrap_or(IDSNGMIdentity::new().unwrap());

    if users[0].registration.is_empty() {
        info!("Registering new identity...");
        register(config.as_ref(), &*connection.state.read().await, services, &mut users, &identity).await.unwrap();
    }

    *state.lock().unwrap() = Some(SavedState {
        push: connection.state.read().await.clone(),
        identity: identity.clone(),
        users: users.clone()
    });
    fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).await.unwrap();
    
    let client = IMClient::new(connection.clone(), users, identity, services, "id_cache.plist".into(), config.clone(), Box::new(move |updated_keys| {
        state.lock().unwrap().as_mut().unwrap().users = updated_keys;
        std::fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).unwrap();
    })).await;
    let handle = client.identity.get_handles().await[0].clone();
    client.identity.ensure_private_self(&mut *client.identity.cache.lock().await, &handle, true).await.unwrap();

    // client.identity.refresh_now().await.unwrap();
    // println!("handle {}", handle);


    


    let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
    let state: CloudKitState = plist::from_file(&id_path).unwrap();

    let token_provider = TokenProvider::new(account.clone(), config.clone());

    let cloudkit = Arc::new(CloudKitClient {
        state: RwLock::new(state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });



    let id_path = PathBuf::from_str("profiles.plist").unwrap();
    let mut state: Option<ShareProfileMessage> = plist::from_file(&id_path).unwrap_or_default();
    let name_photo_client = ProfilesClient::new(cloudkit.clone());

    let listener = IdmsAuthListener::new(connection.clone()).await;

    error!("2fa code: {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap());
    // plist::to_file_xml(&id_path, &state).unwrap();

    // let state: StatusKitState = plist::from_file("statuskit.plist").unwrap_or_default();
    // let statuskit_client = StatusKitClient::new(state, Box::new(|state| {
    //     plist::to_file_xml("statuskit.plist", state).unwrap();
    // }), , connection.clone(), config.clone(), client.identity.clone()).await;

    // statuskit_client.invite_to_channel("mailto:sandboxalt@gmail.com", &["mailto:jerrylandgreen@copper.jjtech.dev".to_string()]).await.unwrap();
    // statuskit_client.share_status(&StatusKitStatus::new_active()).await.unwrap();


    // let (token, _) = statuskit_client.request_handles(&["mailto:jerrylandgreen@copper.jjtech.dev".to_string(), "mailto:cooper@copper.jjtech.dev".to_string()]).await;

    // let session: CloudKitSession = CloudKitSession::new();
    // let (record, data) = name_photo_client.container.get_record::<_, TestRecord>(&session, &cloudkit, rustpush::cloudkit_proto::AssetsToDownload {
    //     all_assets: Some(true),
    //     asset_fields: None,
    // }, "+1ZvgjukQfNbTOQ4KJfjvA==-wp").await.unwrap();

            // let record = name_photo_client.get_record(&ShareProfileMessage {
            //     cloud_kit_decryption_record_key: vec![252, 89, 106, 62, 98, 168, 206, 27, 85, 204, 233, 177, 226, 226, 250, 105],
            //     cloud_kit_record_key: "+1ZvgjukQfNbTOQ4KJfjvA==".to_string(),
            //     poster: Some(SharedPoster {
            //         low_res_wallpaper_tag: vec![129, 56, 178, 150, 254, 45, 242, 22, 100, 117, 75, 159, 41, 71, 124, 179, 223, 216, 33, 32, 243, 16, 49, 208, 246, 222, 124, 232, 133, 190, 163, 168],
            //         wallpaper_tag: vec![224, 248, 168, 14, 40, 131, 159, 194, 205, 43, 88, 103, 235, 249, 191, 107, 30, 51, 116, 242, 199, 186, 3, 155, 150, 128, 156, 108, 30, 80, 86, 110],
            //         message_tag: vec![105, 108, 56, 149, 123, 86, 208, 11, 168, 187, 193, 190, 222, 121, 120, 69, 136, 245, 181, 223, 149, 195, 17, 38, 226, 187, 62, 200, 138, 143, 57, 239],
            //     }),
            // }).await.unwrap();

    // name_photo_client.set_record(record, &mut state).await.unwrap();

    // name_photo_client.set_record(IMessageNicknameRecord {
    //     name: IMessageNameRecord {
    //         name: "Testing Now".to_string(),
    //         first: "Testing".to_string(),
    //         last: "Now".to_string(),
    //     },
    //     image: fs::read("upload.png").await.unwrap()
    // }, &mut state).await.unwrap();

    // println!("name {:?}", record.n);

    let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
    let state: SharedStreamsState = plist::from_file(&id_path).unwrap();

    // let shared_streams = SharedStreamClient::new(state, Box::new(move |update| {
    //     plist::to_file_xml(&id_path, update).unwrap();
    // }), accou, connection.clone(), anisette_client.clone(), config.clone()).await;
    // shared_streams.get_changes().await.unwrap();
    // let album = shared_streams.state.read().await.albums[0].albumguid.clone();
    // shared_streams.get_album_summary(&album).await.unwrap();

    // let state: FTState = plist::from_file(&PathBuf::from_str("facetime.plist").unwrap()).unwrap_or_default();
    // let facetime = FTClient::new(state, Box::new(|state| {
    //     plist::to_file_xml(&PathBuf::from_str("facetime.plist").unwrap(), state).expect("Failed to serialize plist!");
    // }), connection.clone(), client.identity.clone(), config.clone()).await;

    let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
    let state: KeychainClientState = plist::from_file(&id_path).unwrap();

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: RwLock::new(state),
        config: config.clone(),
        update_state: Box::new(move |update| {
            plist::to_file_xml(&id_path, update).unwrap();
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    let id_path = PathBuf::from_str("findmy.plist").unwrap();
    let state: FindMyState = plist::from_file(&id_path).unwrap();
    let findmy_client = FindMyClient::new(connection.clone(), cloudkit.clone(), keychain.clone(), config.clone(), Arc::new(FindMyStateManager {
        state: tokio::sync::Mutex::new(state),
        update: Box::new(move |state| {
            plist::to_file_xml(&id_path, state).unwrap()
        }),
    }), token_provider.clone(), anisette_client.clone(), client.identity.clone()).await.unwrap();


    if let Some(mut s) = session {
        let mut subscription = connection.messages_cont.subscribe();
        s.setup_trusted_peers(keychain.clone(), b"antifa").await.unwrap();
        let listener = IdmsAuthListener::new(connection.clone()).await;
        let anisette_client = anisette_client.clone();
        tokio::task::spawn(async move {
            loop {
                let msg = subscription.recv().await.unwrap();
                
                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("here {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            s.handle_circle_request(&c).await.unwrap();
                        }
                    }
                }
            }
        });
    } else {
        pub fn base64_encode(data: &[u8]) -> String {
            general_purpose::STANDARD.encode(data)
        }

        pub fn base64_decode(data: &str) -> Vec<u8> {
            general_purpose::STANDARD.decode(data).unwrap()
        }
        // keychain.sync_changes().await.unwrap();
        // info!("Fetching tlk");

        // let container = keychain.get_security_container().await.unwrap();

        let cloud_messages = CloudMessagesClient::new(cloudkit.clone(), keychain.clone());
        // cloud_messages.sync_attachments(None).await.unwrap();
        
        // cloud_messages.fix().await.unwrap();
        // // cloud_messages.get_msg().await.unwrap();
        // let storage_info = token_provider.get_storage_info().await.unwrap();
        // println!("{:#?}", storage_info);
        // keychain.sync_keychain(&KEYCHAIN_ZONES).await.unwrap();

        // keychain.reset_clique(b"antifa").await.unwrap();

        // findmy_client.sync_item_positions().await.unwrap();
        // findmy_client.update_beacon_name(&BeaconNamingRecord {
        //     emoji: "🎧".to_string(),
        //     name: "test4’s hielalf".to_string(),
        //     associated_beacon: "2793F9C5-5660-4F56-96D3-26A91859F982".to_string(),
        //     role_id: 10,
        // }).await.unwrap();

        // let bottles = keychain.get_viable_bottles().await.unwrap().remove(`0);
        // let mut input = String::new();
        // std::io::stdin().read_line(&mut input).unwrap();
        // let item = input.trim().to_string();
        // println!("import password for {}", bottles.1.serial);
        // keychain.join_clique_from_escrow(&bottles.0, item.as_bytes(), b"antifa").await.unwrap();`

        // findmy_client.accept_item_share("CA065844-8DA5-4F99-AE74-858DEABA34DE").await.unwrap();
        // findmy_client.sync_items(true).await.unwrap();
        // findmy_client.delete_shared_item("404B1239-49C2-4670-B9AA-E51313015540").await.unwrap();


        findmy_client.sync_item_positions().await.unwrap();

        // let state = findmy_client.state.state.lock().await;
        // let i = state.share_state.secrets.values().find_map(|i| i.circle_shared_secret()).unwrap();
        // let plaint = i.decrypt(&base64_decode("YnBsaXN0MDCjAQIDTHlKsVsp07xJc17kmU8QEMsGEV485/wUHWXNp9+5rLJPEK3d3u3/TgCaEVyHoEaF/R7dYoTkXBnGA6//m5Z9FT0kkUcqsikEbWabeJqDIVjwyHTIQX5BqApt0J36Gsf2N/pU+zEXIrkkNcRRsENNSABVpd1iBP474tG24rhPlksfHgDIrvUIiHG4xwbnNSDWaHMuFk6pqDwqsuHolXYJAOko147a6oIEnLi9OifR6RNRyxL4+REDSmNP5/Dd4cd6AzcX+JcSDBm4yO79pCzy3wgMGSwAAAAAAAABAQAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA3A==")).unwrap();

        // println!("here {}", base64_encode(&plaint));

        // println!("{}", base64_encode(&decrypt_shared_key(&s, 114)));
        

        // keychain.change_escrow_password(b"escraw!").await.unwrap();
        // cloud_messages.insert_message().await.unwrap();

        // let messages_container = cloud_messages.get_container().await.unwrap();

        // let chat_zone = messages_container.private_zone("chatManateeZone".to_string());

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("chatManateeZone".to_string()))).await.unwrap();

        // let key = messages_container.get_zone_encryption_config(&chat_zone, &keychain).await.unwrap();

        // panic!();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(container.private_zone("Engram".to_string()))).await.unwrap();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("Engram".to_string()), None).unwrap()).await.unwrap();

        
        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("messageManateeZone".to_string()))).await.unwrap();

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("attachmentManateeZone".to_string()))).await.unwrap();

        // cloud_messages.insert_message().await.unwrap();

        
        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("chatManateeZone".to_string()), Some(&key.key())).unwrap()).await.unwrap();

        // let key = keychain.state.read().await;
        // let (item, record) = &key.items["50BE8D1A-ED50-7D7F-3BE5-D51A26953A90"];
        // let decoded = item.decrypt("50BE8D1A-ED50-7D7F-3BE5-D51A26953A90", &record.0, &key);
        
        // panic!("here {}", encode_hex(&decoded));


        // let key = keychain.state.read().await;
        // let item = key.get_key_id("A6F86BA3-9A98-4F12-B34C-309682A5B05C").unwrap();
        // let result = item.decrypt(&base64_decode("4LAUq+5FDtCUx0JD451YLW9AgYOyE2vtnvqUmjF0oZ7qZf7pGjqaqYiUCC9MeJn3IrsgGMNZh2Q5BwIObynz80Q+k/uke99KPxn0kCkY8uE="));

        // let payload = decode_hex("f6e83f171e336dbbce643a843b339797716f0a8300c08c3828cb9abe2c47e7fb9f57e4950c7b764678ce9db0863585648b8829007734acc3682dcdb217afb0e01dd0ae0bc7e195a71786c14190058aaf609ca656acb52896397a680af50ce856bb2e898dbb7ff8d5b7fdf91a0215d70f7a8d2313dcc506100f12f36666512d417059fe0dcdb46f56449f58b66c66124929e1fa74c2c4878bb2e5f422e09062bcd9ad9cde6e4e4209033888f946793e0f885e5d5c685466b3e6f6201bf15ebb8b70c20a3e14498ab29b54356e6bbbcaa9b7c48fe116801fcee0376ee563065ba190674f340d60cce0328fe502ba2bffdbcf6eb8afa60190ef7b5d224b60ac4f850668a1094639113685edf53189588ff4e7d876651946bb19efee28f2893912dbc4c89c82862616d3e4bbaf36e780bc6f71a0cf230450134a4af9458906e8c08b968e4a1e2f4d62f96ab03a5ab75dd838efbb03d14a2361232cc7f7b3206782e2a4c084ff2a76bab0891062c855e7b6bb9336f35f17cdf53ea1ce8ab3ff00806ab8894c9848e79beea45baeb7233539b4aea4ea8a11bc3588a19779fa7778f0318acc067ca79e45dbafdeaaec080d04aaeb3c359ee5f764644adfbe2bd18a46d1ba9d7551c1482e305c39c1b176eeaa6e53d234169865e475cc4a5720cc017f4b0a4e1b4d22efa7cfa51a91a20d585e782a25a98da4318a9f0f560e190a8eb5a081187e78b27af2d5cb1f9ccbe46420e4e380df424fab609248ae58e58588c53ed75d992ca54f98807073fadeb253021b45335bf79e719fd67b9775258703c46e570c4ce85e7d3f2fa06cba6e7670c1c5de75f943827866fdd7849274828708476fe9b8ba50e6149734f284ea7fe7e7d4e1eb6b3f56da2b93288b2e8874186f71c333604cc916aecadb2fd25dc5a1fc0cbfacdb2d310d18d6c8b8a0ba0b14017751e9cb5e3f48689c13e09366ca7fcf2d39c468c30dee0cf9022d92614c2917185f752e1565230268fa5e04d454b73702e5857ebf14f1060c3fc6322c3abbaf5ea9ed2b5738da5fdeb2fa5054ae0aa28aef1968269569212f5d370ddf5d4ccfa84487f0b5db29adb3bcb4d218237f9136c488a1b08e1c4e938c4a437f84500d8bea65226a750fd62da5a2de0ceb1a79cc1f77cc98bfc06abff241711fdbd66aa4").unwrap();
       
        // use aes_siv::KeyInit;
        // use aes_siv::aead::Aead;
        // let cipher = Aes256SivAead::new_from_slice(&result).unwrap();
        // let nonce = Nonce::from_slice(&payload[..16]); // 96-bits; unique per message
        // let plaintext = cipher.decrypt(nonce, &payload[16..]).unwrap();
        // panic!("here {}", encode_hex(&plaintext));
    }


    // keychain.delete("com.apple.icdp.record.SHA256:s6BbbQzQwtlO+zxiVS/OXOeNXJkGBnS4dtiCeguTbYI=").await.unwrap();
    // keychain.enroll().await.unwrap();
    // keychain.recover_bottle("com.apple.icdp.record.lJjYEopJu5QWIF+W7wjsavhZ16", "000000".as_bytes()).await.unwrap();

    // keychain.sync_trust().await.unwrap();
    // keychain.reset_trust().await.unwrap();

    // panic!("result {}", general_purpose::STANDARD.encode(&dec));
    


    // let mut ft_lock = facetime.state.write().await;
    // facetime.remove_members(&mut ft_lock.sessions.values_mut().next().unwrap(), vec![
    //     FTMember {
    //         nickname: None,
    //         handle: "tel:+18183857117".to_string(),
    //     }
    // ]).await.expect("Could not remove");
    // drop(ft_lock);

    // let link = facetime.generate_link(&handle).await.expect("Failed to create facetime link!");
    // info!("Facetime link {}", link);



    // facetime.create_session(Uuid::new_v4().to_string().to_uppercase(), handle.clone(), &["".to_string()]).await.expect("Failed to create session!");
    // info!("Rung!");


    // let manager = SyncController::new(shared_streams, PathBuf::from_str("syncstate.plist").unwrap(), FFMpegFilePackager::default(), Duration::from_secs(60 * 30)).await;


    
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
    let mut last_ft_guid = "AE271F00-2F67-42C4-8EF2-74600055A2B7".to_string();
    
    let mut circle_session: Option<CircleServerSession<DefaultAnisetteProvider>> = None;

    let push_token = connection.get_token().await;
    
    loop {
        tokio::select! {
            msg = subscription.recv() => {
                let msg = msg.unwrap();
                if let Err(e) = findmy_client.handle(msg.clone()).await {
                    info!("err {e}");
                }
                // let _ = manager.handle(msg.clone()).await;
                
                // if let Some(test) = listener.handle(msg.clone()).unwrap() {
                //     info!("here {test:?}");
                //     match test {
                //         IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                //         IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                //         IdmsMessage::CircleRequest(c, _) => {
                //             if circle_session.is_none() {
                //                 let mut rng = rand::thread_rng();
                //                 let otp: u32 = rng.gen_range(0..1_000_000);
                //                 info!("requested sign in code {}", otp);
                //                 circle_session = Some(CircleServerSession::new(21635836012, otp, account.clone(), push_token, Some(keychain.clone())))
                //             }

                //             circle_session.as_mut().unwrap().handle_circle_request(&c).await.unwrap();
                //         }
                //     }
                // }

                // keychain.handle(msg.clone()).await.unwrap();

                // if let Err(e) = statuskit_client.handle(msg.clone()).await {
                //     error!("Statuskit error {e}");
                //     continue;
                // }
                // match facetime.handle(msg.clone()).await {
                //     Err(e) => {
                //         error!("Failed to receive {}", e);
                //         continue;
                //     },
                //     Ok(None) => {},
                //     Ok(Some(a)) => {
                //         info!("Got ftmessage {a:?}");
                //         match a {
                //             FTMessage::LetMeInRequest(request) => {
                //                 if request.delegation_uuid.is_none() {
                //                     if let Err(e) = facetime.respond_letmein(request, Some(&last_ft_guid)).await {
                //                         warn!("Failed {e}");
                //                     }
                //                     // facetime.respond_letmein(request, None).await.expect("Request failed");
                //                 }
                //             },
                //             FTMessage::JoinEvent { guid, ring, .. } => {
                //                 // if ring {
                //                 //     warn!("Preparing to decline!");
                //                 //     tokio::time::sleep(Duration::from_secs(10)).await;
                //                 //     let mut lock = facetime.state.write().await;
                //                 //     let state = lock.sessions.values_mut().find(|a| a.group_id == guid).expect("state");
                //                 //     facetime.ensure_allocations(state, &[]).await.expect("state");
                //                 //     facetime.decline_invite(state).await.expect("failed to unprop?");
                //                 // }
                //                 last_ft_guid = guid;
                //             },
                //             _ => {}
                //         }
                //     }
                // }
                let msg = client.handle(msg).await;
                if msg.is_err() {
                    error!("Failed to receive {}", msg.err().unwrap());
                    continue;
                }
                if let Ok(Some(msg)) = msg {
                    if msg.has_payload() && !received_msgs.contains(&msg.id) {
                        received_msgs.push(msg.id.clone());
                        // if let Message::ShareProfile(message) = &msg.message {
                        //     if let Err(e) = name_photo_client.get_record(&message).await {
                        //         error!("{e}");
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::SetTranscriptBackground(msg) = &msg.message {
                        //     if let Some(mmcs) = msg.to_mmcs() {
                        //         let mut output = vec![];
                        //         let file = Cursor::new(&mut output);
                        //         mmcs.get_attachment(&*connection, file, |a, b| { }).await.unwrap();
                        //         SimplifiedTranscriptPoster::parse_payload(&output).unwrap();
                        //     }
                        // }
                        println!("{}", msg);
                        print!(">> ");
                        std::io::stdout().flush().unwrap();
                        if let Some(context) = msg.certified_context {
                            println!("sending delivered {}", msg.send_delivered);
                            client.identity.certify_delivery("com.apple.madrid", &context, false).await.unwrap();
                        }
                    }
                }
            // },
            // input = &mut read_task => {
            //     let Ok(input) = input else {
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     };
            //     if input.trim() == "" {
            //         print!(">> ");
            //         std::io::stdout().flush().unwrap();
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     }
            //     if input.starts_with("filter ") {
            //         filter_target = input.strip_prefix("filter ").unwrap().to_string().trim().to_string();
            //         println!("Filtering to {}", filter_target);
            //     } else if input.trim() == "sms" {
            //         let mut msg = MessageInst::new(ConversationData {
            //             participants: vec![],
            //             cv_name: None,
            //             sender_guid: Some(Uuid::new_v4().to_string()),
            //             after_guid: None,
            //         }, &handle, Message::EnableSmsActivation(true));
            //         client.send(&mut msg).await.unwrap();
            //         println!("sms activated");
            //     } else {
            //         if filter_target == "" {
            //             println!("Usage: filter [target]");
            //         } else {
            //             let mut msg = NormalMessage::new(input.trim().to_string(), MessageType::IMessage);
            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);
            //             let mut msg = MessageInst::new(ConversationData {
            //                 participants: vec![filter_target.clone()],
            //                 cv_name: None,
            //                 sender_guid: Some(Uuid::new_v4().to_string()),
            //                 after_guid: None,
            //             }, &handle, Message::Message(msg));

            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);

            //             if let Err(err) = client.send(&mut msg).await {
            //                 error!("Error sending message {err}");
            //             }

            //             // tokio::time::sleep(Duration::from_secs(10)).await;

            //             // msg.message = Message::Unschedule;
            //             // if let Err(err) = client.send(&mut msg).await {
            //             //     error!("Error sending message {err}");
            //             // }
            //         }
            //     }
                print!(">> ");
                std::io::stdout().flush().unwrap();
                read_task = tokio::spawn(read_input());
            },
        }
    }
}


#[test]
fn test() {
    let client_nonce: [u8; 32] = rand::random();
    panic!("e {}", base64_encode(&client_nonce))
}