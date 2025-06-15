
use std::{collections::HashMap, io::{Cursor, Read, Seek, Write}};

use log::{debug, warn};
use plist::{Data, Dictionary, Value};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

use crate::{util::{base64_decode, bin_deserialize, bin_serialize, plist_to_bin, plist_to_string, KeyedArchive, NSDictionary}, NSArray, PushError};

use super::name_photo_sharing::IMessagePosterRecord;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", tag = "$class")]
struct PFPosterMedia {
    #[serde(rename = "assetUUID")]
    asset_uuid: String,
    edit_configuration: String,
    media_type: u32, // not UID
    subpath: String,
    version: u32, // not UID
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PFPosterConfigurationUserInfo {
    #[serde(rename = "assetUUID")]
    asset_uuid: String,
    represents_device_owner: bool,
}

pub fn ns_serialize<S, T>(x: &Vec<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + Clone,
{
    NSArray {
        objects: x.clone(),
        class: crate::NSArrayClass::NSArray,
    }.serialize(s)
}

pub fn ns_deserialize<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Clone,
{
    let s: NSArray<T> = Deserialize::deserialize(d)?;
    Ok(s.objects)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", tag = "$class")]
struct PFPosterConfiguration {
    configuration_type: u32,
    options: u32,
    version: u32,
    edit_configuration: Value,
    identifier: String,
    layout_configuration: Value,
    media: NSArray<PFPosterMedia>,
    user_info: Option<NSDictionary<PFPosterConfigurationUserInfo>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all_fields = "camelCase", tag = "$class")]
pub enum PRPosterContentMaterialStyle {
    PRPosterContentDiscreteColorsStyle {
        variation: f32,
        #[serde(serialize_with = "ns_serialize", deserialize_with = "ns_deserialize")]
        colors: Vec<UIColor>,
        vibrant: bool,
        supports_variation: bool,
        needs_to_resolve_variation: bool,
    },
    PRPosterContentVibrantMaterialStyle,
    PRPosterContentGradientStyle {
        gradient_type: u32,
        #[serde(serialize_with = "ns_serialize", deserialize_with = "ns_deserialize")]
        colors: Vec<UIColor>,
        start_point: String,
        #[serde(serialize_with = "ns_serialize", deserialize_with = "ns_deserialize")]
        locations: Vec<f64>,
        end_point: String,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct PRPosterSystemTimeFontConfiguration {
    pub is_system_item: bool,
    pub time_font_identifier: String,
    pub weight: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UIColor { // no uid items
    RGBAColorSpace {
        #[serde(rename = "UIColorComponentCount")]
        color_components: u32,
        #[serde(rename = "UIGreen")]
        green: f64,
        #[serde(rename = "UIBlue")]
        blue: f64,
        #[serde(rename = "UIRed")]
        red: f64,
        #[serde(rename = "UIGreen-Double")]
        green_dbl: Option<f64>,
        #[serde(rename = "UIBlue-Double")]
        blue_dbl: Option<f64>,
        #[serde(rename = "UIRed-Double")]
        red_dbl: Option<f64>,
        #[serde(rename = "UIAlpha-Double")]
        alpha_dbl: Option<f64>,
        #[serde(rename = "UIAlpha")]
        alpha: f64,
        #[serde(rename = "NSRGB", serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
        rgb: Vec<u8>,
        #[serde(rename = "NSColorSpace")]
        color_space: u32, // 2
        #[serde(rename = "$class")]
        class: String,
    },
    GrayscaleAlphaColorSpace {
        #[serde(rename = "UIColorComponentCount")]
        color_components: u32,
        #[serde(rename = "UIWhite")]
        white: f64,
        #[serde(rename = "UIAlpha")]
        alpha: f64,
        #[serde(rename = "NSWhite", serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
        bin: Vec<u8>,
        #[serde(rename = "NSColorSpace")]
        color_space: u32, // 4
        #[serde(rename = "$class")]
        class: String,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct PRPosterColor {
    pub preferred_style: u32,
    pub identifier: String,
    pub suggested: bool, // not uid
    pub color: UIColor,
}

pub fn vec_serialize<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.as_ref().map(|i| plist::from_bytes::<Value>(i).unwrap()).serialize(s)
}

pub fn vec_deserialize<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Value> = Deserialize::deserialize(d)?;
    Ok(s.map(|s| plist_to_bin(&s).unwrap()))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct PRPosterTitleStyleConfiguration {
    pub alternate_date_enabled: bool,
    pub contents_luminence: f64,
    pub group_name: String,
    pub preferred_title_alignment: u32,
    pub preferred_title_layout: u32,
    pub time_font_configuration: PRPosterSystemTimeFontConfiguration,
    #[serde(serialize_with = "vec_serialize", deserialize_with = "vec_deserialize")]
    pub time_numbering_system: Option<Vec<u8>>,
    pub title_color: PRPosterColor,
    #[serde(default, serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub title_content_style: Vec<u8>,
    pub user_configured: bool,
    #[serde(default)]
    pub title_style: Option<PRPosterContentMaterialStyle>,
}

impl PRPosterTitleStyleConfiguration {
    fn unpack(&mut self) -> Result<(), PushError> {
        if self.title_content_style.is_empty() {
            self.title_style = Some(PRPosterContentMaterialStyle::PRPosterContentVibrantMaterialStyle);
            return Ok(())
        }
        self.title_style = Some(plist::from_value(&KeyedArchive::expand(self.title_content_style.as_ref())?)?);
        self.title_content_style.clear();
        Ok(())
    }
    
    fn pack(&mut self) -> Result<(), PushError> {
        self.title_content_style = plist_to_bin(&KeyedArchive::archive_item(plist::to_value(self.title_style.as_ref().expect("no title style?"))?)?)?;
        self.title_style = None; // prepare for serialization
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PosterManifest {
    archive_version: u32,
    #[serde(rename = "configurationUUID")]
    configuration_uuid: String,
    extension_identifier: String,
    latest_configuration_supplement: u32,
    latest_configuration_version: u32,
    role: PosterRole,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct PosterColor {
    pub alpha: f64,
    pub blue: f64,
    pub green: f64,
    pub red: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WallpaperMetadata {
    pub background_color_key: Option<PosterColor>,
    pub font_color_key: PosterColor,
    pub font_name_key: String,
    pub font_size_key: f32,
    pub font_weight_key: f32,
    pub is_vertical_key: bool,
    pub type_key: String,
}

impl PosterManifest {
    fn new(extension: String, role: PosterRole) -> Self {
        Self {
            archive_version: 1,
            configuration_uuid: Uuid::new_v4().to_string().to_uppercase(),
            extension_identifier: extension,
            latest_configuration_supplement: 0,
            latest_configuration_version: 0,
            role
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PhotoPosterContentsFrame {
    pub width: f64,
    pub height: f64,
    pub x: f64,
    pub y: f64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PhotoPosterContentsSize {
    pub width: f64,
    pub height: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPosterLayer {
    pub frame: PhotoPosterContentsFrame,
    pub filename: String,
    pub z_position: f32,
    pub identifier: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPosterLayout {
    pub clock_intersection: u32,
    pub device_resolution: PhotoPosterContentsSize,
    pub visible_frame: PhotoPosterContentsFrame,
    pub time_frame: PhotoPosterContentsFrame,
    pub clock_layer_order: String,
    pub has_top_edge_contact: bool,
    pub inactive_frame: PhotoPosterContentsFrame,
    pub image_size: PhotoPosterContentsSize,
    pub parallax_padding: PhotoPosterContentsSize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPosterProperties {
    pub portrait_layout: PhotoPosterLayout,
    pub settling_effect_enabled: bool,
    pub depth_enabled: bool,
    pub clock_area_luminance: f64,
    pub parallax_disabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PhotoPosterContents {
    pub version: u32,
    pub layers: Vec<PhotoPosterLayer>,
    pub properties: PhotoPosterProperties,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MonogramData {
    pub top_background_color_description: PosterColor,
    pub background_color_description: PosterColor,
    pub initials: String,
    pub monogram_supported_for_name: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MemojiData {
    pub background_color_description: PosterColor,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub avatar_record_data: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub avatar_pose_data: Vec<u8>,
    pub has_body: bool,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub avatar_image_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PosterAsset {
    pub contents: PhotoPosterContents,
    pub files: HashMap<String, Vec<u8>>,
    pub uuid: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TranscriptDynamicUserData {
    pub identifier: String,
}

#[derive(Serialize, Deserialize)]
struct TranscriptGradientUserData {
    custom: String,
}

impl TranscriptGradientUserData {
    fn to_colors(&self) -> Vec<PosterColor> {
        self.custom.split("//").map(|a| {
            let mut parts = a.split("/");
            PosterColor {
                red: parts.next().expect("No red").parse().unwrap(),
                green: parts.next().expect("No green").parse().unwrap(),
                blue: parts.next().expect("No blue").parse().unwrap(),
                alpha: parts.next().expect("No alpha").parse().unwrap(),
            }
        }).collect()
    }
    fn from_colors(colors: &[PosterColor]) -> Self {
        Self {
            custom: colors.iter().map(|c| format!("{}/{}/{}/{}", c.red, c.green, c.blue, c.alpha)).collect::<Vec<_>>().join("//")
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PosterType {
    // com.apple.PhotosUIPrivate.PhotosPosterProvider
    Photo {
        assets: Vec<PosterAsset>,
    },
    Monogram {
        data: MonogramData,
        background: PosterColor,
    },
    Memoji {
        data: MemojiData,
        background: PosterColor,
    },
    TranscriptDynamic {
        data: TranscriptDynamicUserData,
    },
    TranscriptGradient {
        colors: Vec<PosterColor>,
    },
}

impl PosterType {
    fn get_identifier(&self) -> &'static str {
        match self {
            Self::Photo { .. } => "com.apple.PhotosUIPrivate.PhotosPosterProvider",
            Self::Monogram { .. } => "com.apple.ContactsUI.MonogramPosterExtension",
            Self::Memoji { .. } => "com.apple.AvatarUI.AvatarPosterExtension",
            Self::TranscriptDynamic { .. } => "com.apple.transcriptBackgroundPoster.DynamicExtension",
            Self::TranscriptGradient { .. } => "com.apple.transcriptBackgroundPoster.GradientExtension",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WallpaperMetadataWrapper {
    wallpaper_file_name_key: String,
    wallpaper_low_res_file_name_key: String,
    wallpaper_metadata_key: WallpaperMetadata,
    wallpaper_version_key: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserDataWrapper {
    background_color_description: Data,
    data_representation: Data,
    bounding_shape: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimplifiedIncomingCallPoster {
    pub poster: SimplifiedPoster,
    pub text_metadata: WallpaperMetadata,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub low_res: Vec<u8>,
}

impl SimplifiedIncomingCallPoster {
    pub fn to_poster(&mut self) -> Result<IMessagePosterRecord, PushError> {
        self.text_metadata.type_key = self.poster.r#type.get_identifier().to_string();
        let meta = plist_to_bin(&WallpaperMetadataWrapper {
            wallpaper_file_name_key: "Wallpaper".to_string(),
            wallpaper_low_res_file_name_key: "Wallpaper".to_string(),
            wallpaper_version_key: 0,
            wallpaper_metadata_key: self.text_metadata.clone(),
        })?;

        Ok(IMessagePosterRecord {
            low_res_poster: self.low_res.clone(),
            package: self.poster.to_archive()?,
            meta
        })
    }
    
    pub fn from_poster(poster: &IMessagePosterRecord) -> Result<Self, PushError> {
        let meta: WallpaperMetadataWrapper = plist::from_bytes(&poster.meta)?;
        
        Ok(Self {
            poster: SimplifiedPoster::from_archive(Cursor::new(&poster.package))?,
            text_metadata: meta.wallpaper_metadata_key,
            low_res: poster.low_res_poster.clone(),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchBackground {
    pub is_high_key: bool,
    pub luminance: f64,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub background_image_data: Vec<u8>,
    pub extension_identifier: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimplifiedTranscriptPoster {
    pub watch: WatchBackground,
    pub poster: SimplifiedPoster,
}

impl SimplifiedTranscriptPoster {
    pub fn parse_payload(payload: &[u8]) -> Result<Self, PushError> {
        let mut archive = ZipArchive::new(Cursor::new(&payload))?;
        let watch: WatchBackground = read_file(&mut archive, "transcriptBackground/watchBackground")?;

        let mut poster = vec![];
        archive.by_name("transcriptBackground/poster")?.read_to_end(&mut poster)?;
        Ok(Self {
            watch,
            poster: SimplifiedPoster::from_archive(Cursor::new(&poster))?,
        })
    }

    pub fn to_payload(&mut self) -> Result<Vec<u8>, PushError> {
        let mut new_zip = vec![];

        let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let mut writer = ZipWriter::new(Cursor::new(&mut new_zip));
        writer.add_directory("transcriptBackground/", stored.clone())?;

        
        writer.start_file("transcriptBackground/watchBackground", SimpleFileOptions::default())?;
        plist::to_writer_binary(&mut writer, &self.watch)?;

        writer.start_file("transcriptBackground/poster", SimpleFileOptions::default())?;
        let result = self.poster.to_archive()?;
        writer.write_all(&result)?;

        writer.finish()?;

        Ok(new_zip)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub enum PosterRole {
    PRPosterRoleBackdrop,
    PRPosterRoleIncomingCall,
}

// default for serde
impl Default for PosterRole {
    fn default() -> Self {
        Self::PRPosterRoleIncomingCall
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimplifiedPoster {
    pub title_configuration: PRPosterTitleStyleConfiguration,
    pub r#type: PosterType,
    #[serde(default)]
    pub role: PosterRole,
}

impl SimplifiedPoster {
    pub fn to_archive(&mut self) -> Result<Vec<u8>, PushError> {
        let mut new_zip = vec![];

        let mut writer = ZipWriter::new(Cursor::new(&mut new_zip));
        writer.start_file("manifest.plist", SimpleFileOptions::default())?;
        plist::to_writer_binary(&mut writer, &PosterManifest::new(self.r#type.get_identifier().to_string(), self.role))?;

        let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        writer.add_directory("configuration/", stored.clone())?;
        writer.start_file("configuration/com.apple.posterkit.provider.identifierURL.suggestionMetadata.plist", SimpleFileOptions::default())?;
        writer.write_all(include_bytes!("posterkit_static/com.apple.posterkit.provider.identifierURL.suggestionMetadata.plist"))?;

        writer.add_directory("configurations/versions/", stored.clone())?;
        writer.add_directory("configurations/versions/0/", stored.clone())?;

        writer.start_file("configuration/versions/0/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist", SimpleFileOptions::default())?;
        self.title_configuration.pack()?;
        plist::to_writer_binary(&mut writer, &KeyedArchive::archive_item(plist::to_value(&self.title_configuration)?)?)?;

        writer.start_file("configuration/versions/0/com.apple.posterkit.provider.instance.renderingConfiguration.plist", SimpleFileOptions::default())?;
        writer.write_all(include_bytes!("posterkit_static/com.apple.posterkit.provider.instance.renderingConfiguration.plist"))?;

        writer.start_file("configuration/versions/0/com.apple.posterkit.provider.instance.complicationLayout.plist", SimpleFileOptions::default())?;
        writer.write_all(include_bytes!("posterkit_static/com.apple.posterkit.provider.instance.complicationLayout.plist"))?;

        writer.add_directory("configurations/versions/0/contents/", stored.clone())?;
        writer.add_directory("configurations/versions/0/supplements/", stored.clone())?;
        writer.add_directory("configurations/versions/0/supplements/0/", stored.clone())?;

        match &self.r#type {
            PosterType::Photo { assets } => {
                let configuration_model = PFPosterConfiguration {
                    configuration_type: 0,
                    options: 32,
                    version: 1,
                    edit_configuration: Value::String("$null".to_string()),
                    identifier: assets.first().unwrap().uuid.clone(),
                    layout_configuration: plist::from_bytes(include_bytes!("posterkit_static/layout_configuration.plist"))?,
                    media: NSArray { objects: assets.iter().map(|a| PFPosterMedia {
                        asset_uuid: a.uuid.clone(),
                        edit_configuration: "$null".to_string(),
                        media_type: 1,
                        subpath: a.uuid.clone(),
                        version: 0,
                    }).collect(), class: crate::NSArrayClass::NSArray },
                    user_info: Some(NSDictionary { class: crate::NSDictionaryClass::NSDictionary, item: PFPosterConfigurationUserInfo {
                        asset_uuid: assets.first().unwrap().uuid.clone(),
                        represents_device_owner: false,
                    } })
                };

                writer.start_file("configuration/versions/0/contents/ConfigurationModel.plist", SimpleFileOptions::default())?;
                plist::to_writer_binary(&mut writer, &KeyedArchive::archive_item(plist::to_value(&configuration_model)?)?)?;

                writer.start_file("configuration/versions/0/contents/com.apple.posterkit.provider.contents.otherMetadata.plist", SimpleFileOptions::default())?;
                writer.write_all(include_bytes!("posterkit_static/com.apple.posterkit.provider.contents.otherMetadata.plist"))?;

                for asset in assets {
                    writer.add_directory(&format!("configurations/versions/0/contents/{}/", asset.uuid), stored.clone())?;
                    writer.start_file(&format!("configuration/versions/0/contents/{}/style.plist", asset.uuid), SimpleFileOptions::default())?;
                    writer.write_all(include_bytes!("posterkit_static/style.plist"))?;

                    writer.add_directory(&format!("configurations/versions/0/contents/{}/output.layerStack/", asset.uuid), stored.clone())?;
                    writer.start_file(&format!("configuration/versions/0/contents/{}/output.layerStack/Contents.json", asset.uuid), SimpleFileOptions::default())?;
                    serde_json::to_writer_pretty(&mut writer, &asset.contents)?; // apple loves pretty

                    for (file, data) in &asset.files {
                        writer.start_file(format!("configuration/versions/0/contents/{}/output.layerStack/{}", asset.uuid, file), SimpleFileOptions::default())?;
                        writer.write_all(data)?;
                    }
                }

                writer.start_file("configuration/versions/0/supplements/0/com.apple.posterkit.provider.supplementURL.homescreenConfiguration.plist", SimpleFileOptions::default())?;
                writer.write_all(include_bytes!("posterkit_static/com.apple.posterkit.provider.supplementURL.homescreenConfiguration.plist"))?;
            },
            PosterType::Monogram { data, background } => {
                writer.start_file("configuration/versions/0/com.apple.posterkit.provider.instance.colorVariations.plist", SimpleFileOptions::default())?;
                writer.write_all(include_bytes!("posterkit_static/monogram-com.apple.posterkit.provider.instance.colorVariations.plist"))?;

                let data = UserDataWrapper {
                    background_color_description: plist_to_bin(background)?.into(),
                    data_representation: plist_to_bin(data)?.into(),
                    bounding_shape: None,
                };
                writer.start_file("configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo", SimpleFileOptions::default())?;
                plist::to_writer_binary(&mut writer, &data)?;
            },
            PosterType::Memoji { data, background } => {
                let data = UserDataWrapper {
                    background_color_description: plist_to_bin(background)?.into(),
                    data_representation: plist_to_bin(data)?.into(),
                    bounding_shape: Some(0),
                };
                writer.start_file("configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo", SimpleFileOptions::default())?;
                plist::to_writer_binary(&mut writer, &data)?;
            },
            PosterType::TranscriptDynamic { data } => {
                writer.start_file("configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo", SimpleFileOptions::default())?;
                plist::to_writer_binary(&mut writer, &data)?;
            },
            PosterType::TranscriptGradient { colors } => {
                writer.start_file("configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo", SimpleFileOptions::default())?;
                plist::to_writer_binary(&mut writer, &TranscriptGradientUserData::from_colors(&colors))?;
            }
        }

        writer.finish()?;

        Ok(new_zip)
    }

    pub fn from_archive(archive: impl Read + Seek) -> Result<Self, PushError> {
        let mut archive = ZipArchive::new(archive)?;

        let manifest: PosterManifest = read_file(&mut archive, "manifest.plist")?;
        let mut configuration: PRPosterTitleStyleConfiguration = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist")
            .unwrap_or(PRPosterTitleStyleConfiguration { 
                alternate_date_enabled: false, 
                contents_luminence: 0.0, 
                group_name: "PREditingLook".to_string(), 
                preferred_title_alignment: 0, 
                preferred_title_layout: 0, 
                time_font_configuration: PRPosterSystemTimeFontConfiguration { 
                    is_system_item: true, 
                    time_font_identifier: "PRTimeFontIdentifierSFPro".to_string(), 
                    weight: 400.0,
                }, 
                time_numbering_system: None, 
                title_color: PRPosterColor { 
                    preferred_style: 2, 
                    identifier: "vibrantMaterialColor".to_string(), 
                    suggested: false, 
                    color: UIColor::GrayscaleAlphaColorSpace { color_components: 2, white: 1.0, alpha: 0.5, bin: base64_decode("MSAwLjU="), color_space: 4, class: "PRPosterColor".to_string() }
                }, 
                title_content_style: vec![], 
                user_configured: false, 
                title_style: Some(PRPosterContentMaterialStyle::PRPosterContentVibrantMaterialStyle)
            });

        configuration.unpack()?;

        Ok(Self {
            title_configuration: configuration,
            r#type: match manifest.extension_identifier.as_str() {
                "com.apple.PhotosUIPrivate.PhotosPosterProvider" => {
                    let poster_config: PFPosterConfiguration = read_archive(&mut archive, "configuration/versions/0/contents/ConfigurationModel.plist")?;

                    let mut assets = vec![];
                    for asset in &*poster_config.media {
                        let mut json = vec![];
                        archive.by_name(&format!("configuration/versions/0/contents/{}/output.layerStack/Contents.json", asset.subpath))?.read_to_end(&mut json)?;
                        let contents: PhotoPosterContents = serde_json::from_slice(&json)?;                    
                        let mut files: HashMap<String, Vec<u8>> = HashMap::new();
                        for layer in &contents.layers {
                            let mut file = vec![];
                            archive.by_name(&format!("configuration/versions/0/contents/{}/output.layerStack/{}", asset.subpath, layer.filename))?.read_to_end(&mut file)?;
                            files.insert(layer.filename.clone(), file);
                        }

                        assets.push(PosterAsset {
                            contents,
                            files,
                            uuid: asset.asset_uuid.clone()
                        });
                    }


                    PosterType::Photo {
                        assets
                    }
                },
                "com.apple.ContactsUI.MonogramPosterExtension" => {
                    let file: UserDataWrapper = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo")?;
                    PosterType::Monogram {
                        data: plist::from_bytes(file.data_representation.as_ref())?,
                        background: plist::from_bytes(file.background_color_description.as_ref())?
                    }
                },
                "com.apple.AvatarUI.AvatarPosterExtension" => {
                    let file: UserDataWrapper = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo")?;
                    PosterType::Memoji {
                        data: plist::from_bytes(file.data_representation.as_ref())?,
                        background: plist::from_bytes(file.background_color_description.as_ref())?
                    }
                },
                "com.apple.transcriptBackgroundPoster.DynamicExtension" => {
                    let file: TranscriptDynamicUserData = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo")?;
                    PosterType::TranscriptDynamic {
                        data: file,
                    }
                },
                "com.apple.transcriptBackgroundPoster.GradientExtension" => {
                    let file: TranscriptGradientUserData = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo")?;
                    PosterType::TranscriptGradient {
                        colors: file.to_colors(),
                    }
                }
                _provider => {
                    return Err(PushError::UnknownPoster(_provider.to_string()))
                }
            },
            role: manifest.role,
        })
    }
}


fn read_file<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    if let Err(_) = archive.by_name(path) {
        warn!("Error reading file {path}");
    }
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_bytes(&manifest)?)
}

fn read_archive<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    if let Err(_) = archive.by_name(path) {
        warn!("Error reading file {path}");
    }
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_value(&KeyedArchive::expand(&manifest)?)?)
}

