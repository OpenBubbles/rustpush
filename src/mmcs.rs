use std::{io::Cursor, collections::HashMap, sync::Arc};

use crate::{ids::IDSError, mmcsp::{self, HttpRequest, Container as ProtoContainer, authorize_put_response::UploadTarget}, util::{make_reqwest, encode_hex}};
use log::{warn, info};
use openssl::{sha::{Sha1, sha256}, hash::{MessageDigest, Hasher}};
use prost::Message;
use reqwest::{Client, Response, Body};
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MMCSTransferData {
    pub mmcs_owner: String,
    pub mmcs_url: String,
    pub mmcs_signature_hex: String,
    pub file_size: String,
    pub decryption_key: String
}

async fn send_mmcs_req(client: &Client, url: &str, method: &str, auth: &str, dsid: &str, body: &[u8]) -> Result<Response, IDSError> {
    Ok(client.post(format!("{}/{}", url, method))
        .header("x-apple-mmcs-dataclass", "com.apple.Dataclass.Messenger")
        .header("x-apple-mmcs-auth", auth)
        .header("Accept", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("x-apple-mme-dsid", dsid)
        .header("x-mme-client-info", "<iMac13,1> <Mac OS X;10.11.6;15G31> <com.apple.icloud.content/357.1 (com.apple.Messenger/1.0)>")
        .header("Accept-Language", "en-us")
        .header("Content-Type", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header("User-Agent", "IMTransferAgent/1000 CFNetwork/760.6.3 Darwin/15.6.0 (x86_64)")
        .header("x-apple-mmcs-proto-version", "4.0")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Proxy-Connection", "keep-alive")
        .header("Connection", "keep-alive")
        .body(body.to_owned())
        .send().await?)
}

// build confirm request, mostly a bunch of analytics I don't care to track accurately
fn confirm_for_resp(resp: &Response, url: &str, conf_token: &str, upload_md5: Option<&[u8]>) -> mmcsp::confirm_response::Request {
    let edge_info = resp.headers().get("x-apple-edge-info").clone().unwrap().to_str().unwrap().to_string();
    let etag = resp.headers().get("ETag").clone().unwrap().to_str().unwrap().to_string();
    let status = resp.status();
    mmcsp::confirm_response::Request {
        url: url.to_string(),
        status: status.as_u16() as u32,
        edge_info: [
            if upload_md5.is_some() {
                vec![mmcsp::confirm_response::request::Metric {
                    n: "Etag".to_string(),
                    v: etag
                }]
            } else { vec![] },
            vec![mmcsp::confirm_response::request::Metric {
                n: "x-apple-edge-info".to_string(),
                v: edge_info
            }]
        ].concat(),
        upload_md5: upload_md5.map(|md5| md5.to_vec()),
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

pub async fn prepare_put(reader: &mut dyn Container) -> Result<PreparedPut, IDSError> {
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
            vec![0x01],
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
    hasher: Arc<Mutex<Hasher>>,
    sender: Option<flume::Sender<Result<Vec<u8>, IDSError>>>,
    finalize: Option<JoinHandle<Result<mmcsp::confirm_response::Request, IDSError>>>,
    length: usize,
    finish_dsid: String,
    finish_url: String,
    transfer_progress: usize,
}

impl MMCSPutContainer {
    fn new(target: UploadTarget, length: usize, finish_dsid: String, finish_url: String) -> MMCSPutContainer {
        MMCSPutContainer {
            target,
            hasher: Arc::new(Mutex::new(Hasher::new(MessageDigest::md5()).unwrap())),
            sender: None,
            finalize: None,
            length,
            finish_dsid,
            finish_url,
            transfer_progress: 0
        }
    }
    
    fn get_chunks(&self) -> Vec<([u8; 21], usize)> {
        self.target.chunks.iter().enumerate().map(|(idx, chunk)| {
            let len = if idx == self.target.chunks.len() - 1 {
                self.length % 5242880
            } else {
                5242880
            };
            ((&chunk[..]).try_into().unwrap(), len)
        }).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.sender.is_none() {
            let (sender, reciever) = flume::bounded(0);
            self.sender = Some(sender);
            let body: Body = Body::wrap_stream(reciever.into_stream());
            let request = self.target.request.clone().unwrap();
            let target = self.target.cl_auth_p2.clone();
            let hasher_cpy = self.hasher.clone();
            let task = tokio::spawn(async move {
                let response = transfer_mmcs_container(&make_reqwest(), &request, Some(body)).await?;
                let mut hasher = hasher_cpy.lock().await;
                let result = hasher.finish()?;
                let only_confirm = confirm_for_resp(&response, &get_container_url(&request), &target, Some(&result));
                response.bytes().await?;
                Ok::<mmcsp::confirm_response::Request, IDSError>(only_confirm)
            });
            self.finalize = Some(task);

        }
    }

}

#[async_trait]
impl Container for MMCSPutContainer {
    async fn read(&mut self, _len: usize) -> Result<Vec<u8>, IDSError> {
        panic!("cannot write to put container!")
    }
    async fn write(&mut self, data: &[u8]) -> Result<(), IDSError> {
        self.ensure_stream().await;
        if let Err(err) = self.sender.as_ref().unwrap().send_async(Ok(data.to_vec())).await {
            err.into_inner()?;
        }
        let mut hasher = self.hasher.lock().await;
        hasher.update(data).unwrap();
        self.transfer_progress += data.len();
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    // finalize the http stream
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, IDSError> {
        self.sender = None;
        let only_confirm = self.finalize.take().unwrap().await.unwrap()?;

        // send the confirm message
        let confirmation = mmcsp::ConfirmResponse {
            inner: vec![only_confirm]
        };
        let mut buf: Vec<u8> = Vec::new();
        buf.reserve(confirmation.encoded_len());
        confirmation.encode(&mut buf).unwrap();
        let resp = send_mmcs_req(&make_reqwest(), &self.finish_url, "putComplete", &format!("{} {} {}", self.target.cl_auth_p1, self.length, self.target.cl_auth_p2), &self.finish_dsid, &buf).await?;
        if !resp.status().is_success() {
            panic!("confirm failed {}", resp.status())
        };
        Ok(None)
    }
}

// upload data to mmcs
pub async fn put_mmcs(source: &mut dyn Container, prepared: &PreparedPut, url: &str, token: &str, object: &str, progress: &mut dyn FnMut(usize, usize)) -> Result<(), IDSError> {
    let get = mmcsp::AuthorizePut {
        data: Some(mmcsp::authorize_put::PutData {
            sig: prepared.total_sig.clone(),
            token: token.to_string(),
            chunks: prepared.chunk_sigs.iter().map(|chunk| mmcsp::authorize_put::put_data::Chunk {
                sig: chunk.0.to_vec(),
                size: chunk.1 as u32
            }).collect()
        }),
        f: 3
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(get.encoded_len());
    get.encode(&mut buf).unwrap();

    let client = make_reqwest();
    let resp = send_mmcs_req(&client, &url, "authorizePut", 
            &format!("{} {} {}", encode_hex(&prepared.total_sig), prepared.total_len, token), object, &buf).await?;

    let resp_data = resp.bytes().await?;
    let response = mmcsp::AuthorizePutResponse::decode(&mut Cursor::new(resp_data)).unwrap();
    let sources = vec![ChunkedContainer::new(prepared.chunk_sigs.clone(), source)];

    let mut put_containers: Vec<Box<MMCSPutContainer>> = response.targets.iter().map(|target| {
        let len = target.chunks.iter().fold(0, |acc, chunk| {
            let wanted_chunk = prepared.chunk_sigs.iter().find(|test| &test.0[..] == &chunk[..]).unwrap();
            wanted_chunk.1 + acc
        });
        Box::new(MMCSPutContainer::new(target.clone(), len, object.to_string(), url.to_string()))
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

    Ok(())
}

fn get_container_url(req: &HttpRequest) -> String {
    format!("{}://{}:{}{}", req.scheme, req.domain, req.port, req.path)
}

pub async fn transfer_mmcs_container(client: &Client, req: &HttpRequest, body: Option<Body>) -> Result<Response, IDSError> {
    let data_url = get_container_url(req);
    let mut upload_resp = match req.method.as_str() {
        "GET" => client.get(&data_url),
        "PUT" => client.put(&data_url),
        _method => panic!("Cannot upload {}", _method)
    }
        .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
        .header("x-mme-client-info", "<iMac13,1> <Mac OS X;10.11.6;15G31> <com.apple.icloud.content/357.1 (com.apple.Messenger/1.0)>");
    for header in &req.headers {
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
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, IDSError>;
    async fn write(&mut self, data: &[u8]) -> Result<(), IDSError>;
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, IDSError>;
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
    container: &'a mut dyn Container,
}

impl ChunkedContainer<'_> {
    fn new<'a>(chunks: Vec<([u8; 21], usize)>, container: &'a mut dyn Container) -> ChunkedContainer<'a> {
        ChunkedContainer {
            chunks,
            current_chunk: 0,
            cached_chunks: HashMap::new(),
            container,
        }
    }

    // (chunk id, data)
    async fn read_next(&mut self) -> Result<([u8; 21], Vec<u8>), IDSError> {
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

    async fn write_chunk(&mut self, chunk: &([u8; 21], Vec<u8>)) -> Result<(), IDSError> {
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

    async fn transfer_chunks(&mut self, progress: &mut dyn FnMut(usize, usize)) -> Result<(), IDSError> {
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
        self.container.chunks.iter().map(|chunk| (chunk.checksum.clone().try_into().unwrap(), chunk.size as usize)).collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.response.is_none() {
            let response = transfer_mmcs_container(&make_reqwest(), &self.container.request.as_ref().unwrap(), None).await.unwrap();
            self.confirm = Some(confirm_for_resp(&response, &get_container_url(&self.container.request.as_ref().unwrap()), &self.container.cl_auth_p2, None));
            self.response = Some(response);
        }
    }
}

#[async_trait]
impl Container for MMCSGetContainer {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, IDSError> {
        self.ensure_stream().await;

        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let Some(bytes) = self.response.as_mut().unwrap().chunk().await? else {
                return Ok(self.cacher.read_all())
            };
            self.cacher.data_avail(&bytes);
            recieved = self.cacher.read_exact(len);
        }
        
        let read = recieved.unwrap();
        self.transfer_progress += read.len();
        Ok(read)
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    async fn write(&mut self, _data: &[u8]) -> Result<(), IDSError> {
        panic!("cannot write to get container!")
    }

    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, IDSError> {
        Ok(self.confirm.clone())
    }
}

pub async fn get_mmcs(sig: &[u8], token: &str, dsid: &str, url: &str, target: &mut dyn Container, progress: &mut dyn FnMut(usize, usize)) -> Result<(), IDSError> {
    let get = mmcsp::AuthorizeGet {
        data: Some(mmcsp::authorize_get::GetData {
            sig: sig.to_vec(),
            token: token.to_string()
        }),
        f: 2
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(get.encoded_len());
    get.encode(&mut buf).unwrap();

    let client = make_reqwest();
    let resp = send_mmcs_req(&client, url, "authorizeGet", &format!("{} {}", encode_hex(&sig), token), dsid, &buf).await?;

    let resp_data = resp.bytes().await?;
    let response = mmcsp::AuthorizeGetResponse::decode(&mut Cursor::new(resp_data)).unwrap();

    let total_bytes = response.f1.as_ref().unwrap().containers.iter()
        .fold(0, |acc, container| acc + 
                container.chunks.iter().fold(0, |acc, chunk| acc + chunk.size)) as usize;
    
    let mut mmcs_sources: Vec<Box<MMCSGetContainer>> = response.f1.as_ref().unwrap().containers.iter().map(|container| Box::new(MMCSGetContainer::new(container.clone()))).collect();
    let sources = mmcs_sources.iter_mut().map(|container| {
        ChunkedContainer::new(container.get_chunks(), container.as_mut())
    }).collect();
    
    let wanted_chunks = &response.f1.as_ref().unwrap().references.as_ref().unwrap().chunk_references;
    let data = &response.f1.as_ref().unwrap().containers;
    let targets = vec![ChunkedContainer::new(wanted_chunks.iter().map(|chunk| {
        let container = data.get(chunk.container_index as usize).unwrap();
        let chunk = &container.chunks[chunk.chunk_index as usize];
        (chunk.checksum.clone().try_into().unwrap(), chunk.size as usize)
    }).collect(), target)];

    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: total_bytes
    };
    matcher.transfer_chunks(progress).await?;

    let confirmation = mmcsp::ConfirmResponse {
        inner: matcher.get_confirm_reciepts().to_vec()
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(confirmation.encoded_len());
    confirmation.encode(&mut buf).unwrap();
    let resp = send_mmcs_req(&client, url, "getComplete", &format!("{} {}", data[0].cl_auth_p1, data[0].cl_auth_p2), dsid, &buf).await?;
    if !resp.status().is_success() {
        panic!("confirm failed {}", resp.status())
    }

    Ok(())
}