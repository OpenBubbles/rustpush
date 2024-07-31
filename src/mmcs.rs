use std::{io::Cursor, collections::HashMap};

use crate::{aps::get_message, error::PushError, mmcsp::{self, authorize_get_response, authorize_put_response::UploadTarget, Container as ProtoContainer, HttpRequest}, util::{encode_hex, get_reqwest, get_reqwest_system, plist_to_bin}, APSConnectionResource};
use log::{debug, info, warn};
use openssl::{sha::{Sha1, sha256}, hash::{MessageDigest, Hasher}};
use plist::Data;
use prost::Message;
use reqwest::{Client, Response, Body};
use tokio::task::JoinHandle;
use uuid::Uuid;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use rand::RngCore;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MMCSTransferData {
    pub mmcs_owner: String,
    pub mmcs_url: String,
    pub mmcs_signature_hex: String,
    pub file_size: String,
    pub decryption_key: String
}

async fn send_mmcs_req(client: &Client, url: &str, method: &str, auth: &str, dsid: &str, body: &[u8]) -> Result<Response, PushError> {
    Ok(client.post(format!("{}/{}", url, method))
        .header("x-apple-mmcs-dataclass", "com.apple.Dataclass.Messenger")
        .header("x-apple-mmcs-auth", auth)
        .header("Accept", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("x-apple-mme-dsid", dsid)
        .header("x-mme-client-info", "<iMac13,1> <macOS;12.6.9;21G726> <com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)>")
        .header("Accept-Language", "en-us")
        .header("Content-Type", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("User-Agent", "IMTransferAgent/1000 CFNetwork/1335.0.3.4 Darwin/21.6.0")
        .header("x-apple-mmcs-proto-version", "5.0")
        .header("x-apple-mmcs-plist-version", "v1.0")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Proxy-Connection", "keep-alive")
        .header("Connection", "keep-alive")
        .header("x-apple-mmcs-plist-sha256", "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=")
        .body(body.to_owned())
        .send().await?)
}

// build confirm request, mostly a bunch of analytics I don't care to track accurately
fn confirm_for_resp(resp: &Response, url: &str, conf_token: &str, up_md5: Option<&[u8]>) -> mmcsp::confirm_response::Request {
    let edge_info = resp.headers().get("x-apple-edge-info").clone().map(|i| i.to_str().unwrap().to_string());
    let status = resp.status();
    let etag = resp.headers().get("ETag").clone().map(|i| i.to_str().unwrap().to_string());
    mmcsp::confirm_response::Request {
        url: url.to_string(),
        status: status.as_u16() as u32,
        edge_info: [
            if up_md5.is_some() {
                vec![
                    mmcsp::confirm_response::request::Metric {
                        n: "Etag".to_string(),
                        v: etag.unwrap()
                    }
                ]
            } else {
                vec![]
            },
            if let Some(info) = edge_info {
                vec![
                    mmcsp::confirm_response::request::Metric {
                        n: "x-apple-edge-info".to_string(),
                        v: info
                    }
                ]
            } else { vec![] }
        ].concat(),
        upload_md5: up_md5.map(|md5| md5.to_vec()),
        metrics: vec![],
        metrics2: vec![],
        token: conf_token.to_string(),
        f13: 0
    }
}

// double sha256 because apple said so
fn gen_chunk_sig(chunk: &[u8]) -> [u8; 21] {
    let out = sha256(chunk);
    [
        vec![0x01],
        sha256(&out)[..20].to_vec()
    ].concat().try_into().unwrap()
}

pub struct PreparedPut {
    pub total_sig: Vec<u8>,
    pub chunk_sigs: Vec<([u8; 21], usize)>,
    pub total_len: usize
}

pub async fn prepare_put(reader: &mut (dyn Container + Send + Sync)) -> Result<PreparedPut, PushError> {
    let mut total_len = 0;
    let mut total_hasher = Sha1::new();
    total_hasher.update(b"com.apple.XattrObjectSalt\0com.apple.DataObjectSalt\0");
    let mut chunk_sigs: Vec<([u8; 21], usize)> = vec![];

    let mut chunk = reader.read(5242880).await?;
    // chunk data into chunks of 5MB, generating a signature for each chunk
    while chunk.len() > 0 {
        total_hasher.update(&chunk);
        chunk_sigs.push((gen_chunk_sig(&chunk), chunk.len()));
        total_len += chunk.len();
        chunk = reader.read(5242880).await?;
    }
    Ok(PreparedPut {
        total_sig: [
            vec![0x81],
            total_hasher.finish().to_vec()
        ].concat(),
        chunk_sigs,
        total_len
    })
}

// a `Container` that transfers to an MMCS bucket
// handles putting into a bucket
struct MMCSPutContainer {
    target: UploadTarget,
    hasher: Hasher,
    sender: Option<flume::Sender<Result<Vec<u8>, PushError>>>,
    finalize: Option<JoinHandle<Result<Response, PushError>>>,
    length: usize,
    transfer_progress: usize,
    finish_binary: Option<Vec<u8>>,
    for_object: String,
    confirm_url: String,
}

impl MMCSPutContainer {
    fn new(target: UploadTarget, length: usize, finish_binary: Option<Vec<u8>>, for_object: String, confirm_url: String) -> MMCSPutContainer {
        MMCSPutContainer {
            target,
            hasher: Hasher::new(MessageDigest::md5()).unwrap(),
            sender: None,
            finalize: None,
            length,
            transfer_progress: 0,
            finish_binary,
            for_object,
            confirm_url,
        }
    }
    
    fn get_chunks(&self) -> Vec<([u8; 21], usize)> {
        self.target.chunks.iter().enumerate().map(|(idx, chunk)| {
            let len = if idx == self.target.chunks.len() - 1 {
                self.length % 5242880
            } else {
                5242880
            };
            ((&chunk.chunk_id[..]).try_into().unwrap(), len)
        }).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.sender.is_none() {
            let (sender, receiver) = flume::bounded(0);
            self.sender = Some(sender);
            let body: Body = Body::wrap_stream(receiver.into_stream());
            let request = self.target.request.clone().unwrap();
            let task = tokio::spawn(async move {
                let response = transfer_mmcs_container(&get_reqwest_system(), &request, Some(body)).await?;
                Ok::<_, PushError>(response)
            });
            self.finalize = Some(task);

        }
    }

}

#[async_trait]
impl Container for MMCSPutContainer {
    async fn read(&mut self, _len: usize) -> Result<Vec<u8>, PushError> {
        panic!("cannot write to put container!")
    }
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        self.ensure_stream().await;
        if let Err(err) = self.sender.as_ref().unwrap().send_async(Ok(data.to_vec())).await {
            err.into_inner()?;
        }
        self.hasher.update(data).unwrap();
        self.transfer_progress += data.len();
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    // finalize the http stream
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, PushError> {
        let result = self.hasher.finish()?;
        
        return Ok(if complete_req_at_edge(self.target.request.as_ref().unwrap()) {
            debug!("MMCS complete at edge");
            let footer = mmcsp::PutFooter {
                md5_sum: result.to_vec(),
                confirm_data: self.finish_binary.clone()
            };

            let mut buf: Vec<u8> = Vec::new();
            buf.reserve(footer.encoded_len());
            footer.encode(&mut buf).unwrap();

            let result = self.sender.as_ref().unwrap().send_async(Ok([
                (buf.len() as u32).to_be_bytes().to_vec(),
                buf
            ].concat())).await;
            if let Err(err) = result {
                err.into_inner()?;
            }
            self.sender = None;
            let reader = self.finalize.take().unwrap().await.unwrap()?;

            debug!("mmcs response {}", encode_hex(&reader.bytes().await?));

            None
        } else {
            debug!("MMCS complete normal");
            self.sender = None;
            let reader = self.finalize.take().unwrap().await.unwrap()?;
            let confirmed = confirm_for_resp(&reader, &get_container_url(&self.target.request.as_ref().unwrap()), &self.target.cl_auth_p2, Some(&result));
            reader.bytes().await?;

            let confirmation = mmcsp::ConfirmResponse {
                inner: vec![confirmed],
                confirm_data: self.finish_binary.clone(),
            };
            let mut buf: Vec<u8> = Vec::new();
            buf.reserve(confirmation.encoded_len());
            confirmation.encode(&mut buf).unwrap();
            let resp = send_mmcs_req(&get_reqwest(), &self.confirm_url, "putComplete", &format!("{} {} {}", self.target.cl_auth_p1, self.length, self.target.cl_auth_p2), &self.for_object, &buf).await?;
            if !resp.status().is_success() {
                return Err(PushError::MMCSUploadFailed(resp.status().as_u16()));
            }

            debug!("mmcs response {}", encode_hex(&resp.bytes().await?));

            None
        })
    }
}

#[derive(Serialize, Deserialize)]
struct RequestMMCSUpload {
    #[serde(rename = "mL")]
    length: usize,
    #[serde(rename = "mS")]
    signature: Data,
    v: u64,
    ua: String,
    c: u64,
    i: u32,
    #[serde(rename = "cV")]
    cv: u32,
    #[serde(rename = "cH")]
    headers: String,
    #[serde(rename = "cB")]
    body: Data,
}

#[derive(Serialize, Deserialize)]
struct MMCSUploadResponse {
    #[serde(rename = "cB")]
    response: Data,
    #[serde(rename = "mR")]
    domain: String,
    #[serde(rename = "mU")]
    object: String
}

// upload data to mmcs
pub async fn put_mmcs(source: &mut (dyn Container + Send + Sync), prepared: &PreparedPut, apns: &APSConnectionResource, progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<(String, String), PushError> {
    let get = mmcsp::AuthorizePut {
        data: Some(mmcsp::authorize_put::PutData {
            sig: prepared.total_sig.clone(),
            token: String::new(),
            chunks: prepared.chunk_sigs.iter().map(|chunk| mmcsp::authorize_put::put_data::Chunk {
                sig: chunk.0.to_vec(),
                size: chunk.1 as u32
            }).collect(),
            footer: Some(mmcsp::authorize_put::put_data::Footer {
                chunk_count: prepared.chunk_sigs.len() as u32,
                profile_type: "kCKProfileTypeFixed".to_string(),
                f103: 0
            })
        }),
        f3: 81
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(get.encoded_len());
    get.encode(&mut buf).unwrap();

    let msg_id = rand::thread_rng().next_u32();
    let complete = RequestMMCSUpload {
        c: 150,
        ua: "[macOS,12.6.9,21G726,iMac13,1]".to_string(),
        v: 3,
        i: msg_id,
        length: prepared.total_len,
        signature: prepared.total_sig.clone().into(),
        cv: 2,
        headers: [
            "x-apple-mmcs-proto-version:5.0",
            "x-apple-mmcs-plist-sha256:fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=",
            "x-apple-mmcs-plist-version:v1.0",
            "x-mme-client-info:<iMac13,1> <macOS;12.6.9;21G726> <com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)>",
            ""
        ].join("\n"),
        body: buf.into()
    };
    let binary = plist_to_bin(&complete)?;
    let recv = apns.subscribe().await;
    apns.send_message("com.apple.madrid", binary, Some(msg_id)).await?;

    let reader = apns.wait_for_timeout(recv, get_message(|loaded| {
        let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
            return None
        };
        let Some(i) = loaded.as_dictionary().unwrap().get("i") else {
            return None
        };
        if c.as_unsigned_integer().unwrap() == 150 && i.as_unsigned_integer().unwrap() as u32 == msg_id {
            Some(loaded)
        } else { None }
    }, &["com.apple.madrid"])).await?;
    let apns_response: MMCSUploadResponse = plist::from_value(&reader).unwrap();

    let response = mmcsp::AuthorizePutResponse::decode(&mut Cursor::new(apns_response.response)).unwrap();
    let sources = vec![ChunkedContainer::new(prepared.chunk_sigs.clone(), source)];

    let confirm_url = format!("{}/{}", apns_response.domain, apns_response.object);

    let mut put_containers: Vec<Box<MMCSPutContainer>> = response.targets.iter().map(|target| {
        let len = target.chunks.iter().fold(0, |acc, chunk| {
            let wanted_chunk = prepared.chunk_sigs.iter().find(|test| &test.0[..] == &chunk.chunk_id[..]).unwrap();
            wanted_chunk.1 + acc
        });
        Box::new(MMCSPutContainer::new(target.clone(), len, response.confirm_data.clone(), apns_response.object.clone(), confirm_url.clone()))
    }).collect();
    let targets = put_containers.iter_mut().map(|target| {
        ChunkedContainer::new(target.get_chunks(), target.as_mut())
    }).collect();

    // and, hopefully, everything "just works."
    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: prepared.total_len
    };
    matcher.transfer_chunks(progress).await?;

    Ok((apns_response.domain, apns_response.object))
}

fn get_container_url(req: &HttpRequest) -> String {
    format!("{}://{}:{}{}", req.scheme, req.domain, req.port, req.path)
}

fn complete_req_at_edge(req: &HttpRequest) -> bool {
    req.headers.iter().find_map(|header| if header.name == "x-apple-put-complete-at-edge-version" { Some(header.value.as_str()) } else { None }) == Some("2")
}

pub async fn transfer_mmcs_container(client: &Client, req: &HttpRequest, body: Option<Body>) -> Result<Response, PushError> {
    let data_url = get_container_url(req);
    let mut upload_resp = match req.method.as_str() {
        "GET" => client.get(&data_url),
        "PUT" => client.put(&data_url),
        _method => panic!("Cannot upload {}", _method)
    }
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("user-agent", "IMTransferAgent/1000 CFNetwork/1335.0.3.4 Darwin/21.6.0");
    let completing_at_edge = complete_req_at_edge(req);
    for header in &req.headers {
        if (header.name == "Content-Length" && completing_at_edge) || header.name == "Host" {
            continue // this isn't a rustpush hack, this is how you *think different*
        }
        upload_resp = upload_resp.header(header.name.clone(), header.value.clone());
    }

    if let Some(body) = body {
        upload_resp = upload_resp.body(body);
    }

    Ok(upload_resp.send().await?)
}

#[async_trait]
pub trait Container {
    // read ONE chunk
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError>;
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError>;
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, PushError>;
    // this should represent the byte count that represents transfer *progress*
    // if this is a file container, return 0 as writing to disk does not indicate progress
    fn get_progress_count(&self) -> usize;
}

// used for files on disk and containers, for files there is just one container with the chunks in "correct order"
struct ChunkedContainer<'a> {
    chunks: Vec<([u8; 21], usize)>,
    // either reading or writing
    current_chunk: usize,
    // only used when writing
    cached_chunks: HashMap<[u8; 21], Vec<u8>>,
    container: &'a mut (dyn Container + Send + Sync),
}

impl ChunkedContainer<'_> {
    fn new<'a>(chunks: Vec<([u8; 21], usize)>, container: &'a mut (dyn Container + Send + Sync)) -> ChunkedContainer<'a> {
        ChunkedContainer {
            chunks,
            current_chunk: 0,
            cached_chunks: HashMap::new(),
            container,
        }
    }

    // (chunk id, data)
    async fn read_next(&mut self) -> Result<([u8; 21], Vec<u8>), PushError> {
        let reading_chunk = &self.chunks[self.current_chunk];
        self.current_chunk += 1;
        Ok((reading_chunk.0, self.container.read(reading_chunk.1).await?))
    }

    fn complete(&self) -> bool {
        self.current_chunk == self.chunks.len()
    }

    fn wanted_chunk(&self) -> Option<[u8; 21]> {
        self.chunks.get(self.current_chunk).map(|c| c.0)
    }

    async fn write_chunk(&mut self, chunk: &([u8; 21], Vec<u8>)) -> Result<(), PushError> {
        // are we current chunk?
        if chunk.0 == self.wanted_chunk().unwrap() {
            // write right now (stream)
            self.container.write(&chunk.1).await?;
            self.current_chunk += 1;
            if !self.complete() {
                // try to catch up on any cached chunks
                while let Some(cached) = self.cached_chunks.remove(&self.wanted_chunk().unwrap()) {
                    self.container.write(&cached).await?;
                    self.current_chunk += 1;
                }
            }
        } else {
            warn!("Chunks out of order!");
            self.cached_chunks.insert(chunk.0, chunk.1.clone());
        }
        Ok(())
    }
}

// code that matches streams of chunks, and caches any extra chunks that are out of order
struct MMCSMatcher<'a, 'b> {
    targets: Vec<ChunkedContainer<'a>>,
    sources: Vec<ChunkedContainer<'b>>,
    reciepts: Vec<mmcsp::confirm_response::Request>,
    total: usize
}

impl MMCSMatcher<'_, '_> {
    // find best source, first figuring out start chunks that align, or failing that whichever ones aren't complete
    fn best_source<'a, 'b, 'c>(targets: &Vec<ChunkedContainer<'b>>, sources: &'a mut Vec<ChunkedContainer<'c>>) -> Option<&'a mut ChunkedContainer<'c>> {
        let wanted = sources.iter().enumerate()
            .filter(|source| !source.1.complete())
            .max_by_key(|source| targets.iter().filter(|target| target.wanted_chunk() == Some(source.1.chunks[0].0)).count())
            .or_else(|| sources.iter().enumerate().find(|source| !source.1.complete()));
        let wanted_idx = wanted.map(|w| w.0).unwrap_or(usize::MAX);
        // so now we know what we want, now we need to get a mutable reference
        sources.get_mut(wanted_idx)
    }

    async fn transfer_chunks(&mut self, progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<(), PushError> {
        let mut total_source_progress = 0;
        while let Some(source) = Self::best_source(&self.targets, &mut self.sources) {
            while !source.complete() {
                let chunk = source.read_next().await?;
                // finialize if the source was just completed
                if source.complete() {
                    if let Some(data) = source.container.finalize().await? {
                        self.reciepts.push(data);
                    }
                }
                for target in &mut self.targets {
                    if !target.chunks.iter().any(|c| c.0 == chunk.0) {
                        continue
                    }
                    target.write_chunk(&chunk).await?;
                    // finialize if the target was just completed
                    if target.complete() {
                        if let Some(data) = target.container.finalize().await? {
                            self.reciepts.push(data);
                        }
                    }
                }
                let total_progress = total_source_progress + source.container.get_progress_count() + 
                    self.targets.iter().fold(0, |acc, tar| acc + tar.container.get_progress_count());
                info!("transferred attachment bytes {} of {}", total_progress, self.total);
                progress(total_progress, self.total);
            }
            total_source_progress += source.container.get_progress_count();
        }
        Ok(())
    }

    fn get_confirm_reciepts(&self) -> &[mmcsp::confirm_response::Request] {
        &self.reciepts
    }
}

// simply caches data to be read in whole later
pub struct DataCacher {
    buf: Vec<u8>,
}

impl DataCacher {
    pub fn new() -> DataCacher {
        DataCacher { buf: vec![] }
    }

    pub fn data_avail(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn read_exact(&mut self, cnt: usize) -> Option<Vec<u8>> {
        return if self.buf.len() >= cnt {
            Some(self.buf.drain(..cnt).collect())
        } else {
            None
        }
    }

    pub fn read_all(&mut self) -> Vec<u8> {
        let buf = self.buf.clone();
        self.buf.clear();
        buf
    }
}

// a `Container` that transfers to an MMCS bucket
// simply allows reading exact amount of bytes from response
struct MMCSGetContainer {
    container: ProtoContainer,
    cacher: DataCacher,
    response: Option<Response>,
    confirm: Option<mmcsp::confirm_response::Request>,
    transfer_progress: usize
}

impl MMCSGetContainer {
    fn new(container: ProtoContainer) -> MMCSGetContainer {
        MMCSGetContainer {
            container,
            cacher: DataCacher::new(),
            response: None,
            confirm: None,
            transfer_progress: 0
        }
    }

    fn get_chunks(&self) -> Vec<([u8; 21], usize)> {
        self.container.chunks.iter().map(|chunk| (chunk.meta.clone().unwrap().checksum.try_into().unwrap(), chunk.meta.as_ref().unwrap().size as usize)).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.response.is_none() {
            let response = transfer_mmcs_container(&get_reqwest_system(), &self.container.request.as_ref().unwrap(), None).await.unwrap();
            self.confirm = Some(confirm_for_resp(&response, &get_container_url(&self.container.request.as_ref().unwrap()), &self.container.cl_auth_p2, None));
            self.response = Some(response);
        }
    }
}

#[async_trait]
impl Container for MMCSGetContainer {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        self.ensure_stream().await;

        let mut received = self.cacher.read_exact(len);
        while received.is_none() {
            let Some(bytes) = self.response.as_mut().unwrap().chunk().await? else {
                return Ok(self.cacher.read_all())
            };
            self.cacher.data_avail(&bytes);
            received = self.cacher.read_exact(len);
        }
        
        let read = received.unwrap();
        self.transfer_progress += read.len();
        Ok(read)
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    async fn write(&mut self, _data: &[u8]) -> Result<(), PushError> {
        panic!("cannot write to get container!")
    }

    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, PushError> {
        Ok(self.confirm.clone())
    }
}

#[derive(Serialize, Deserialize)]
struct RequestMMCSDownload {
    #[serde(rename = "mO")]
    object: String,
    #[serde(rename = "mS")]
    signature: Data,
    v: u64,
    ua: String,
    c: u64,
    i: u32,
    #[serde(rename = "cH")]
    headers: String,
    #[serde(rename = "mR")]
    domain: String,
    #[serde(rename = "cV")]
    cv: u32,
}

#[derive(Serialize, Deserialize)]
struct MMCSDownloadResponse {
    #[serde(rename = "cB")]
    response: Data,
    #[serde(rename = "mU")]
    object: String
}

pub async fn get_mmcs(sig: &[u8], url: &str, object: &str, apns: &APSConnectionResource, target: &mut (dyn Container + Send + Sync), progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<(), PushError> {
    let domain = url.replace(&format!("/{}", object), "");
    let msg_id = rand::thread_rng().next_u32();
    let request_download = RequestMMCSDownload {
        object: object.to_string(),
        c: 151,
        ua: "[macOS,12.6.9,21G726,iMac13,1]".to_string(),
        headers: [
            "x-apple-mmcs-proto-version:5.0",
            "x-apple-mmcs-plist-sha256:fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=",
            "x-apple-mmcs-plist-version:v1.0",
            "x-mme-client-info:<iMac13,1> <macOS;12.6.9;21G726> <com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)>",
            ""
        ].join("\n"),
        v: 8,
        domain,
        cv: 2,
        i: msg_id,
        signature: sig.to_vec().into()
    };

    info!("mmcs obj {} sig {}", object, encode_hex(sig));
    
    let binary = plist_to_bin(&request_download)?;
    let recv = apns.subscribe().await;
    apns.send_message("com.apple.madrid", binary, Some(msg_id)).await?;

    let reader = apns.wait_for_timeout(recv, get_message(|loaded| {
        let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
            return None
        };
        let Some(i) = loaded.as_dictionary().unwrap().get("i") else {
            return None
        };
        if c.as_unsigned_integer().unwrap() == 151 && i.as_unsigned_integer().unwrap() as u32 == msg_id {
            Some(loaded)
        } else { None }
    }, &["com.apple.madrid"])).await?;
    let apns_response: MMCSDownloadResponse = plist::from_value(&reader).unwrap();

    let data: Vec<u8> = apns_response.response.clone().into();
    debug!("get response hex {}", encode_hex(&data));
    let response = mmcsp::AuthorizeGetResponse::decode(&mut Cursor::new(data)).unwrap();

    if response.f1.is_none() {
        let Some(authorize_get_response::Error { 
            f2: Some(authorize_get_response::error::F2 { reason })
        }) = response.error else {
            return Err(PushError::MMCSGetFailed(None))
        };
        return Err(PushError::MMCSGetFailed(Some(reason)))
    }

    let total_bytes = response.f1.as_ref().expect("no container list?").containers.iter()
        .fold(0, |acc, container| acc + 
                container.chunks.iter().fold(0, |acc, chunk| acc + chunk.meta.as_ref().unwrap().size)) as usize;
    
    let mut mmcs_sources: Vec<Box<MMCSGetContainer>> = response.f1.as_ref().unwrap().containers.iter().map(|container| Box::new(MMCSGetContainer::new(container.clone()))).collect();
    let sources = mmcs_sources.iter_mut().map(|container| {
        ChunkedContainer::new(container.get_chunks(), container.as_mut())
    }).collect();
    
    let wanted_chunks = &response.f1.as_ref().unwrap().references.as_ref().unwrap().chunk_references;
    let data = &response.f1.as_ref().unwrap().containers;
    let targets = vec![ChunkedContainer::new(wanted_chunks.iter().map(|chunk| {
        let container = data.get(chunk.container_index as usize).unwrap();
        let chunk = &container.chunks[chunk.chunk_index as usize];
        (chunk.meta.clone().unwrap().checksum.try_into().unwrap(), chunk.meta.as_ref().unwrap().size as usize)
    }).collect(), target)];

    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: total_bytes
    };
    matcher.transfer_chunks(progress).await?;

    let confirmation = mmcsp::ConfirmResponse {
        inner: matcher.get_confirm_reciepts().to_vec(),
        confirm_data: None,
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(confirmation.encoded_len());
    confirmation.encode(&mut buf).unwrap();
    let resp = send_mmcs_req(&get_reqwest(), url, "getComplete", &format!("{} {}", data[0].cl_auth_p1, data[0].cl_auth_p2), &apns_response.object, &buf).await?;
    if !resp.status().is_success() {
        panic!("confirm failed {}", resp.status())
    }

    Ok(())
}