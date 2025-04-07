use std::{io::Cursor, collections::HashMap};

use crate::{aps::get_message, error::PushError, mmcsp::{self, authorize_get_response, authorize_put::put_data::Chunk, authorize_put_response::UploadTarget, Container as ProtoContainer, HttpRequest}, util::{decode_hex, encode_hex, plist_to_bin, REQWEST}, APSConnectionResource};
use log::{debug, info, warn};
use openssl::{hash::{Hasher, MessageDigest}, sha::{sha256, Sha1}, symm::{decrypt, encrypt, Cipher}};
use plist::Data;
use prost::Message;
use reqwest::{header::{HeaderMap, HeaderName}, Body, Client, Response};
use tokio::task::JoinHandle;
use uuid::Uuid;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use rand::{Rng, RngCore};
use std::io::{Read, Write};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MMCSTransferData {
    pub mmcs_owner: String,
    pub mmcs_url: String,
    pub mmcs_signature_hex: String,
    pub file_size: String,
    pub decryption_key: String
}

pub struct MMCSConfig {
    pub mme_client_info: String,
    pub user_agent: String,
    pub dataclass: &'static str,
    pub mini_ua: String,
    pub dsid: Option<String>,
    pub cloudkit_headers: HashMap<&'static str, String>,
    pub extra_1: Option<String>,
    pub extra_2: Option<String>,
}

async fn send_mmcs_req(client: &Client, config: &MMCSConfig, url: &str, method: &str, auth: &str, dsid: &str, body: &[u8]) -> Result<Response, PushError> {
    let cloudkit_headers: HeaderMap = config.cloudkit_headers.iter().map(|(a, b)| (HeaderName::from_str(a).unwrap(), b.parse().unwrap())).collect();

    Ok(client.post(format!("{}/{}", url, method))
        .header("x-apple-mmcs-dataclass", config.dataclass)
        .header("x-apple-mmcs-auth", auth)
        .header("Accept", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("x-apple-mme-dsid", dsid)
        .header("x-mme-client-info", &config.mme_client_info)
        .header("Accept-Language", "en-us")
        .header("Content-Type", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("User-Agent", &config.user_agent)
        .header("x-apple-mmcs-proto-version", "5.0")
        .header("x-apple-mmcs-plist-version", "v1.0")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Proxy-Connection", "keep-alive")
        .header("Connection", "keep-alive")
        .header("x-apple-mmcs-plist-sha256", "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=")
        .headers(cloudkit_headers)
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
fn gen_chunk_sig(chunk: &[u8], prefix: u8) -> ([u8; 21], [u8; 17]) {
    let out = sha256(chunk);

    let mut enc_key = [0u8; 17];
    enc_key[0] = 0x1;
    for i in 0..16 {
        enc_key[i + 1] = out[i] ^ out[i + 16];
    }

    ([
        vec![prefix],
        sha256(&out)[..20].to_vec()
    ].concat().try_into().unwrap(), enc_key)
}

pub struct PreparedPut {
    pub total_sig: Vec<u8>,
    pub chunk_sigs: Vec<ChunkDesc>,
    pub total_len: usize
}

pub async fn prepare_put(mut reader: impl ReadContainer + Send + Sync, encrypt: bool, prefix: u8) -> Result<PreparedPut, PushError> {
    let mut total_len = 0;
    let mut total_hasher = Sha1::new();
    total_hasher.update(b"com.apple.XattrObjectSalt\0com.apple.DataObjectSalt\0");
    let mut chunk_sigs: Vec<ChunkDesc> = vec![];

    let mut chunk = reader.read(5242880).await?;
    // chunk data into chunks of 5MB, generating a signature for each chunk
    while chunk.len() > 0 {
        total_hasher.update(&chunk);
        let (signature, key) = gen_chunk_sig(&chunk, prefix ^ 0x80);
        chunk_sigs.push(ChunkDesc {
            id: signature,
            size: chunk.len(),
            key: if encrypt { Some(key) } else { None },
        });
        total_len += chunk.len();
        chunk = reader.read(5242880).await?;
    }
    Ok(PreparedPut {
        total_sig: [
            vec![prefix],
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
    dsid: String,
    confirm_url: String,
    buffer: Option<Vec<u8>>,
    index: HashMap<String, ChunkDesc>,
    user_agent: String,
}

impl MMCSPutContainer {
    fn new(target: UploadTarget, index: HashMap<String, ChunkDesc>, length: usize, finish_binary: Option<Vec<u8>>, dsid: String, confirm_url: String, user_agent: String) -> MMCSPutContainer {
        MMCSPutContainer {
            target,
            hasher: Hasher::new(MessageDigest::md5()).unwrap(),
            sender: None,
            finalize: None,
            length,
            transfer_progress: 0,
            finish_binary,
            dsid,
            confirm_url,
            buffer: None,
            index,
            user_agent
        }
    }
    
    fn get_chunks(&self) -> Vec<ChunkDesc> {
        self.target.chunks.iter().enumerate().map(|(idx, chunk)| {
            let len = if idx == self.target.chunks.len() - 1 {
                self.length % 5242880
            } else {
                5242880
            };
            ChunkDesc {
                id: (&chunk.chunk_id[..]).try_into().unwrap(),
                size: len,
                key: self.index[&encode_hex(&chunk.chunk_id)].key,
            }
        }).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.sender.is_none() {
            let (sender, receiver) = flume::bounded(0);
            self.sender = Some(sender);
            let body: Body = Body::wrap_stream(receiver.into_stream());
            let request = self.target.request.clone().unwrap();
            let user_agent = self.user_agent.clone();
            let task = tokio::spawn(async move {
                let response = transfer_mmcs_container(&REQWEST, &request, Some(body), &user_agent).await?;
                Ok::<_, PushError>(response)
            });
            self.finalize = Some(task);

        }
    }

}

impl Container for MMCSPutContainer { }

#[async_trait]
impl WriteContainer for MMCSPutContainer {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        self.ensure_stream().await;

        if let Some(data) = self.buffer.take() {
            if let Err(err) = self.sender.as_ref().unwrap().send_async(Ok(data)).await {
                err.into_inner()?;
            }
        }
        self.buffer = Some(data.to_vec());
        self.hasher.update(data).unwrap();
        self.transfer_progress += data.len();
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    // finalize the http stream
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        let result = self.hasher.finish()?;
        
        return Ok(if complete_req_at_edge(self.target.request.as_ref().unwrap()) {
            debug!("MMCS complete at edge");
            let footer = mmcsp::PutFooter {
                md5_sum: result.to_vec(),
                confirm_data: self.finish_binary.clone()
            };

            let mut buf: Vec<u8> = footer.encode_to_vec();

            let result = self.sender.take().unwrap().into_send_async(Ok([
                self.buffer.take().unwrap(),
                (buf.len() as u32).to_be_bytes().to_vec(),
                buf
            ].concat())).await;
            if let Err(err) = result {
                err.into_inner()?;
            }
            let reader = self.finalize.take().unwrap().await.unwrap()?;

            if !reader.status().is_success() {
                let status = reader.status().as_u16();
                debug!("mmcs failed {status} {}", encode_hex(&reader.bytes().await?));
                return Err(PushError::MMCSUploadFailed(status));
            }

            debug!("mmcs response {}", encode_hex(&reader.bytes().await?));

            None
        } else {
            debug!("MMCS complete normal");
            if let Err(err) = self.sender.as_ref().unwrap().send_async(Ok(self.buffer.take().unwrap())).await {
                err.into_inner()?;
            }
            self.sender = None;
            let reader = self.finalize.take().unwrap().await.unwrap()?;
            let confirmed = confirm_for_resp(&reader, &get_container_url(&self.target.request.as_ref().unwrap()), &self.target.cl_auth_p2, Some(&result));
            reader.bytes().await?;

            let confirmation = mmcsp::ConfirmResponse {
                inner: vec![confirmed],
                confirm_data: self.finish_binary.clone(),
            };
            let buf: Vec<u8> = confirmation.encode_to_vec();
            let resp = send_mmcs_req(&REQWEST, config, &self.confirm_url, "putComplete", &format!("{} {} {}", self.target.cl_auth_p1, self.length, self.target.cl_auth_p2), &self.dsid, &buf).await?;
            if !resp.status().is_success() {
                return Err(PushError::MMCSUploadFailed(resp.status().as_u16()));
            }

            let body: Vec<u8> = resp.bytes().await?.into();

            debug!("mmcs response {}", encode_hex(&body));

            let response = mmcsp::PutCompleteResponse::decode(&mut Cursor::new(&body)).expect("Put complete decode fail");
            
            Some(MMCSReceipt::Put(response))
        })
    }
}


pub struct FileContainer<T> {
    inner: T,
    cacher: DataCacher,
}

impl<T> FileContainer<T> {
    pub fn new<'a>(inner: T) -> Self {
        Self {
            inner,
            cacher: DataCacher::new(),
        }
    }
}

#[async_trait]
impl<T: Send + Sync> Container for FileContainer<T> { }

#[async_trait]
impl<T: Read + Send + Sync> ReadContainer for FileContainer<T> {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let mut data = vec![0; len];
            let read = self.inner.read(&mut data)?;
            if read == 0 {
                recieved = self.cacher.read_exact(len).or_else(|| Some(self.cacher.read_all()));
                break
            } else {
                data.resize(read, 0);
                self.cacher.data_avail(&data);
            }
            recieved = self.cacher.read_exact(len);
        }
        
        Ok(recieved.unwrap_or(vec![]))
    }
}

#[async_trait]
impl<T: Write + Send + Sync> WriteContainer for FileContainer<T> {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        self.inner.write_all(data)?;
        Ok(())
    }
}

pub async fn authorize_put(config: &MMCSConfig, inputs: &[(&PreparedPut, Option<String>, impl ReadContainer + Send + Sync)], url: &str) -> Result<AuthorizedOperation, PushError> {
    let (_, buf) = put_authorize_body(config, inputs);
    let request = send_mmcs_req(&REQWEST, config, url, "authorizePut", &format!("{} {} {}", encode_hex(&inputs[0].0.total_sig), inputs[0].0.total_len, inputs[0].1.clone().unwrap()), config.dsid.as_ref().unwrap(), &buf).await?;
    let body = request.bytes().await?;
    
    Ok(AuthorizedOperation {
        url: url.to_string(),
        body: body.into(),
        dsid: config.dsid.clone().unwrap(),
    })
}

pub fn get_headers(mme_client_info: String) -> HashMap<&'static str, String> {
    [
        ("x-apple-mmcs-proto-version", "5.0".to_string()),
        ("x-apple-mmcs-plist-sha256", "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=".to_string()),
        ("x-apple-mmcs-plist-version", "v1.0".to_string()),
        ("x-mme-client-info", mme_client_info),
    ].into_iter().collect()
}

pub fn put_authorize_body(config: &MMCSConfig, inputs: &[(&PreparedPut, Option<String>, impl ReadContainer + Send + Sync)]) -> (HashMap<&'static str, String>, Vec<u8>) {
    let get = mmcsp::AuthorizePut {
        data: inputs.iter().map(|(prepared, object, _)| mmcsp::authorize_put::PutData {
            sig: prepared.total_sig.clone(),
            token: Some(object.clone().unwrap_or_default()), // TODO changed; verify doesn't break other stuff
            chunks: prepared.chunk_sigs.iter().map(|chunk| mmcsp::authorize_put::put_data::Chunk {
                sig: chunk.id.to_vec(),
                size: chunk.size as u32,
                encryption_key: chunk.key.map(|c| c.to_vec()),
            }).collect(),
            footer: Some(mmcsp::authorize_put::put_data::Footer {
                chunk_count: prepared.chunk_sigs.len() as u32,
                profile_type: "kCKProfileTypeFixed".to_string(),
                f103: Some(0),
                f102: config.extra_1.clone(),
                f104: config.extra_2.clone(),
            }),
        }).collect(),
        f3: 81
    };
    let buf: Vec<u8> = get.encode_to_vec();

    (get_headers(config.mme_client_info.to_string()), buf)
}

#[derive(Default)]
pub struct AuthorizedOperation {
    pub url: String,
    pub body: Vec<u8>,
    pub dsid: String,
}

// upload data to mmcs
pub async fn put_mmcs(config: &MMCSConfig, inputs: Vec<(&PreparedPut, Option<String>, impl ReadContainer + Send + Sync)>, auth: AuthorizedOperation, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(String, Option<String>, HashMap<Vec<u8>, String>), PushError> {
    let mut inputs = inputs.into_iter().map(|(a, b, c)| (a, b, Some(c))).collect::<Vec<_>>();

    let AuthorizedOperation { url, body, dsid } = auth;

    let mut receipts: HashMap<Vec<u8>, String> = HashMap::new();

    let response = mmcsp::AuthorizePutResponse::decode(&mut Cursor::new(body)).unwrap();

    for state in &response.current_states {
        let Some(receipt) = &state.receipt else { continue };
        receipts.insert(state.signature.clone(), receipt.clone());
    }

    let sources = inputs.iter_mut().map(|(prepared, _, container)| ChunkedContainer::new(prepared.chunk_sigs.clone().into_iter().map(|mut i| {
        i.key = None;
        i
    }).collect(), container.take().expect("Duplicate PUT containers??"))).collect::<Vec<_>>();

    let index: HashMap<String, ChunkDesc> = inputs.iter().flat_map(|s| s.0.chunk_sigs.iter().map(|c| (encode_hex(&c.id), *c))).collect::<HashMap<_, _>>();

    let targets: Vec<ChunkedContainer<MMCSPutContainer>> = response.targets.iter().map(|target| {
        let len = target.chunks.iter().fold(0, |acc, chunk| {
            let wanted_chunk = index[&encode_hex(&chunk.chunk_id)];
            wanted_chunk.size + acc
        });
        let target = MMCSPutContainer::new(target.clone(), index.clone(), len, response.confirm_data.clone(), dsid.clone(), url.clone(), config.user_agent.clone());
        ChunkedContainer::new(target.get_chunks(), target)
    }).collect();

    // and, hopefully, everything "just works."
    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: inputs.iter().fold(0, |acc, chunk| chunk.0.total_len + acc)
    };
    matcher.transfer_chunks(config, progress).await?;

    receipts.extend(matcher.get_confirm_reciepts().iter().flat_map(|i| {
        let MMCSReceipt::Put(g) = i else { panic!("Bad receipt type") };
        g.finished.iter().map(|i| (i.signature.clone(), i.receipt.clone()))
    }));

    Ok((url, inputs[0].1.clone(), receipts))
}

fn get_container_url(req: &HttpRequest) -> String {
    format!("{}://{}:{}{}", req.scheme, req.domain, req.port, req.path)
}

fn complete_req_at_edge(req: &HttpRequest) -> bool {
    req.headers.iter().find_map(|header| if header.name == "x-apple-put-complete-at-edge-version" { Some(header.value.as_str()) } else { None }) == Some("2")
}

pub async fn transfer_mmcs_container(client: &Client, req: &HttpRequest, body: Option<Body>, user_agent: &str) -> Result<Response, PushError> {
    let data_url = get_container_url(req);
    let mut upload_resp = match req.method.as_str() {
        "GET" => client.get(&data_url),
        "PUT" => client.put(&data_url),
        _method => panic!("Cannot upload {}", _method)
    }
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("user-agent", user_agent);
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
pub trait Container {}

#[async_trait]
pub trait ReadContainer: Container {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError>;
    // read ONE chunk
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> { Ok(None) }
    // this should represent the byte count that represents transfer *progress*
    // if this is a file container, return 0 as writing to disk does not indicate progress
    fn get_progress_count(&self) -> usize { 0 }
}

#[async_trait]
pub trait WriteContainer: Container {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError>;
    // read ONE chunk
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> { Ok(None) }
    // this should represent the byte count that represents transfer *progress*
    // if this is a file container, return 0 as writing to disk does not indicate progress
    fn get_progress_count(&self) -> usize { 0 }
}

#[derive(Clone, Copy)]
pub struct ChunkDesc {
    id: [u8; 21],
    size: usize,
    key: Option<[u8; 17]>,
}

// used for files on disk and containers, for files there is just one container with the chunks in "correct order"
struct ChunkedContainer<T: Container> {
    chunks: Vec<ChunkDesc>,
    // either reading or writing
    current_chunk: usize,
    // only used when writing
    cached_chunks: HashMap<[u8; 21], Vec<u8>>,
    container: T,
}

impl<T: Container + Send + Sync> ChunkedContainer<T> {
    fn new(chunks: Vec<ChunkDesc>, container: T) -> Self {
        Self {
            chunks,
            current_chunk: 0,
            cached_chunks: HashMap::new(),
            container,
        }
    }

    fn complete(&self) -> bool {
        self.current_chunk == self.chunks.len()
    }

    fn wanted_chunk(&self) -> Option<[u8; 21]> {
        self.chunks.get(self.current_chunk).map(|c| c.id)
    }
}

impl<T: ReadContainer + Send + Sync> ChunkedContainer<T> {
    // (chunk id, data)
    async fn read_next(&mut self) -> Result<([u8; 21], Vec<u8>), PushError> {
        let reading_chunk = &self.chunks[self.current_chunk];
        self.current_chunk += 1;
        let mut data = self.container.read(reading_chunk.size).await?;

        if let Some(key) = &reading_chunk.key {
            data = decrypt(Cipher::aes_128_cfb128(), &key[1..], None, &data)?;
        }

        Ok((reading_chunk.id, data))
    }
}

impl<T: WriteContainer + Send + Sync> ChunkedContainer<T> {
    async fn write_chunk(&mut self, chunk: &([u8; 21], Vec<u8>)) -> Result<(), PushError> {
        let chunk_id = chunk.0;
        let mut chunk_value = chunk.1.clone();
        let reading_chunk = &self.chunks.iter().find(|c| &c.id[..] == &chunk.0).expect("Written chunk not found?");
        if let Some(key) = &reading_chunk.key {
            chunk_value = encrypt(Cipher::aes_128_cfb128(), &key[1..], None, &chunk_value)?;
        }

        // are we current chunk?
        if Some(chunk_id) == self.wanted_chunk() {
            // write right now (stream)
            self.container.write(&chunk_value).await?;
            self.current_chunk += 1;
            if !self.complete() {
                // try to catch up on any cached chunks
                while let Some(cached) = self.cached_chunks.remove(&self.wanted_chunk().unwrap()) {
                    let wanted = self.wanted_chunk().unwrap();
                    self.container.write(&cached).await?;
                    self.current_chunk += 1;

                    let wants_more = self.chunks[self.current_chunk..].iter().any(|c| c.id == wanted);
                    if wants_more {
                        warn!("Duplicate chunks!");
                        self.cached_chunks.insert(chunk_id, chunk_value.clone());
                    }
                }
            }
        }
        let wants_more = self.chunks[self.current_chunk..].iter().any(|c| c.id == chunk.0);
        if wants_more {
            warn!("Chunks out of order!");
            self.cached_chunks.insert(chunk_id, chunk_value.clone());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum MMCSReceipt {
    Get(mmcsp::confirm_response::Request),
    Put(mmcsp::PutCompleteResponse),
}

// code that matches streams of chunks, and caches any extra chunks that are out of order
struct MMCSMatcher<A, B>
    where A: ReadContainer,
        B: WriteContainer {
    sources: Vec<ChunkedContainer<A>>,
    targets: Vec<ChunkedContainer<B>>,
    reciepts: Vec<MMCSReceipt>,
    total: usize
}

impl<A, B> MMCSMatcher<A, B>
    where A: ReadContainer + Send + Sync,
        B: WriteContainer + Send + Sync {
    // find best source, first figuring out start chunks that align, or failing that whichever ones aren't complete
    fn best_source<'a>(targets: &Vec<ChunkedContainer<B>>, sources: &'a mut Vec<ChunkedContainer<A>>) -> Option<&'a mut ChunkedContainer<A>> {
        let wanted = sources.iter().enumerate()
            .filter(|source| !source.1.complete())
            .max_by_key(|source| targets.iter().filter(|target| target.wanted_chunk() == Some(source.1.chunks[0].id)).count());
        let wanted_idx = wanted.map(|w| w.0).unwrap_or(usize::MAX);
        // so now we know what we want, now we need to get a mutable reference
        sources.get_mut(wanted_idx)
    }

    async fn transfer_chunks(&mut self, config: &MMCSConfig, mut progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
        let mut total_source_progress = 0;
        while let Some(source) = Self::best_source(&self.targets, &mut self.sources) {
            while !source.complete() {
                let chunk = source.read_next().await?;
                // finialize if the source was just completed
                if source.complete() {
                    if let Some(data) = source.container.finalize(config).await? {
                        self.reciepts.push(data);
                    }
                }
                for target in &mut self.targets {
                    if !target.chunks.iter().any(|c| c.id == chunk.0) {
                        continue
                    }
                    target.write_chunk(&chunk).await?;
                    // finialize if the target was just completed
                    if target.complete() {
                        if let Some(data) = target.container.finalize(config).await? {
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

    fn get_confirm_reciepts(&self) -> &[MMCSReceipt] {
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
    confirm: Option<MMCSReceipt>,
    transfer_progress: usize,
    user_agent: String,
}

impl MMCSGetContainer {
    fn new(container: ProtoContainer, user_agent: String) -> MMCSGetContainer {
        MMCSGetContainer {
            container,
            cacher: DataCacher::new(),
            response: None,
            confirm: None,
            transfer_progress: 0,
            user_agent
        }
    }

    fn get_chunks(&self) -> Vec<ChunkDesc> {
        self.container.chunks.iter().map(|chunk| ChunkDesc {
            id: chunk.meta.clone().unwrap().checksum.try_into().unwrap(),
            size: chunk.meta.as_ref().unwrap().size as usize,
            key: chunk.meta.clone().unwrap().encryption_key.map(|i| i.try_into().unwrap()),
        }).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) -> Result<(), PushError> {
        if self.response.is_none() {
            let response = transfer_mmcs_container(&REQWEST, &self.container.request.as_ref().unwrap(), None, &self.user_agent).await?;
            self.confirm = Some(MMCSReceipt::Get(confirm_for_resp(&response, &get_container_url(&self.container.request.as_ref().unwrap()), &self.container.cl_auth_p2, None)));
            self.response = Some(response);
        }
        Ok(())
    }
}

#[async_trait]
impl Container for MMCSGetContainer { }

#[async_trait]
impl ReadContainer for MMCSGetContainer {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        self.ensure_stream().await?;

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

    async fn finalize(&mut self, _config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        Ok(self.confirm.clone())
    }
}

pub async fn authorize_get(config: &MMCSConfig, url: &str, files: &[(Vec<u8>, &str, impl WriteContainer + Send + Sync)]) -> Result<AuthorizedOperation, PushError> {
    let confirmation = mmcsp::AuthorizeGet {
        item: files.iter().map(|(sig, object, _)| mmcsp::authorize_get::Item {
            signature: sig.to_vec(),
            object: object.to_string(),
        }).collect()
    };
    let buf: Vec<u8> = confirmation.encode_to_vec();
    let (sig, object, _) = &files[0];
    let request = send_mmcs_req(&REQWEST, config, &url, "authorizeGet", &format!("{} {}", encode_hex(&sig), object), config.dsid.as_ref().unwrap(), &buf).await?;
    
    Ok(AuthorizedOperation {
        url: url.to_string(),
        body: request.bytes().await?.into(),
        dsid: config.dsid.clone().unwrap()
    })
}

pub async fn get_mmcs(config: &MMCSConfig, authorized: AuthorizedOperation, files: Vec<(Vec<u8>, &str, impl WriteContainer + Send + Sync)>, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
    let mut files = files.into_iter().map(|(a, b, c)| (a, b, Some(c))).collect::<Vec<_>>();

    let AuthorizedOperation { url, body, dsid } = authorized;

    debug!("get response hex {}", encode_hex(&body));
    let response = mmcsp::AuthorizeGetResponse::decode(&mut Cursor::new(body)).unwrap();

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
    
    let sources: Vec<ChunkedContainer<MMCSGetContainer>> = response.f1.as_ref().unwrap().containers.iter().map(|container| {
        let container = MMCSGetContainer::new(container.clone(), config.user_agent.clone());
        ChunkedContainer::new(container.get_chunks(), container)
    }).collect();
    
    let data = &response.f1.as_ref().unwrap().containers;
    let targets = response.f1.as_ref().unwrap().references.iter().map(|wanted_chunks| {
        let container = files.iter_mut().find(|container| &container.0 == &wanted_chunks.file_checksum && container.2.is_some()).expect("no file??");
        ChunkedContainer::new(wanted_chunks.chunk_references.iter().map(|chunk| {
            let container = data.get(chunk.container_index as usize).unwrap();
            let chunk = &container.chunks[chunk.chunk_index as usize];
            ChunkDesc {
                id: chunk.meta.clone().unwrap().checksum.try_into().unwrap(),
                size: chunk.meta.as_ref().unwrap().size as usize,
                key: None, // do not re-encrypt for output
            }
        }).collect(), container.2.take().unwrap())
    }).collect();

    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: total_bytes
    };
    matcher.transfer_chunks(config, progress).await?;

    // cloudkit doesn't do getComplete
    if url != "" {
        let confirmation = mmcsp::ConfirmResponse {
            inner: matcher.get_confirm_reciepts().iter().map(|i| {
                let MMCSReceipt::Get(g) = i else { panic!("Bad receipt type") };
                g.clone()
            }).collect(),
            confirm_data: None,
        };
        let buf: Vec<u8> = confirmation.encode_to_vec();
        let resp = send_mmcs_req(&REQWEST, config, &url, "getComplete", &format!("{} {}", data[0].cl_auth_p1, data[0].cl_auth_p2), &dsid, &buf).await?;
        if !resp.status().is_success() {
            panic!("confirm failed {}", resp.status())
        }
    }

    Ok(())
}