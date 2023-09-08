use std::{io::Cursor, collections::HashMap};

use crate::{ids::IDSError, mmcsp::{self, HttpRequest, container::ChunkMeta}, util::{make_reqwest, encode_hex}};
use openssl::{sha::{Sha1, sha256}, hash::{hash, MessageDigest}};
use prost::Message;
use reqwest::{Client, Response};
use uuid::Uuid;

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

pub fn calculate_mmcs_signature(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(b"com.apple.XattrObjectSalt\0com.apple.DataObjectSalt\0");
    hasher.update(data);
    [
        vec![0x01],
        hasher.finish().to_vec()
    ].concat()
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
fn gen_chunk_sig(chunk: &[u8]) -> [u8; 20] {
    let out = sha256(chunk);
    sha256(&out)[..20].try_into().unwrap()
}

// upload data to mmcs
pub async fn put_mmcs(req_sig: &[u8], data: &[u8], url: &str, token: &str, object: &str) -> Result<(), IDSError> {
    // chunk data into chunks of 5MB, generating a signature for each chunk
    let chunks: Vec<(&[u8], [u8; 20])> = data.chunks(5242880).map(|chunk|
        (chunk, gen_chunk_sig(chunk))).collect();
    let get = mmcsp::AuthorizePut {
        data: Some(mmcsp::authorize_put::PutData {
            sig: req_sig.to_vec(),
            token: token.to_string(),
            chunks: chunks.iter().map(|chunk| mmcsp::authorize_put::put_data::Chunk {
                sig: [
                    vec![0x1],
                    chunk.1.to_vec()
                ].concat(),
                size: chunk.0.len() as u32
            }).collect()
        }),
        f: 3
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(get.encoded_len());
    get.encode(&mut buf).unwrap();

    let client = make_reqwest();
    let resp = send_mmcs_req(&client, &url, "authorizePut", 
            &format!("{} {} {}", encode_hex(&req_sig), data.len(), token), object, &buf).await?;
    
    let resp_data = resp.bytes().await?;
    let response = mmcsp::AuthorizePutResponse::decode(&mut Cursor::new(resp_data)).unwrap();
    for target in response.targets {
        // find the chunks Apple wants in this request, and build a body
        let mut body: Vec<u8> = vec![];
        for chunk_uuid in target.chunks {
            let wanted_chunk = chunks.iter().find(|test| &test.1 == &chunk_uuid[1..] /* without 0x1 */).unwrap();
            body.extend_from_slice(wanted_chunk.0);
        }

        let body_md5 = hash(MessageDigest::md5(), &body)?;
        let request = target.request.unwrap();
        let response = transfer_mmcs_container(&client, &request, Some(&body)).await?;
        // compute confirm message for this upload, then finish the upload
        let only_confirm = confirm_for_resp(&response, &get_container_url(&request), &target.cl_auth_p2, Some(&body_md5));
        response.bytes().await?;

        // send the confirm message
        let confirmation = mmcsp::ConfirmResponse {
            inner: vec![only_confirm]
        };
        let mut buf: Vec<u8> = Vec::new();
        buf.reserve(confirmation.encoded_len());
        confirmation.encode(&mut buf).unwrap();
        let resp = send_mmcs_req(&client, url, "putComplete", &format!("{} {} {}", target.cl_auth_p1, body.len(), target.cl_auth_p2), object, &buf).await?;
        if !resp.status().is_success() {
            panic!("confirm failed {}", resp.status())
        }
    }

    Ok(())
}

fn get_container_url(req: &HttpRequest) -> String {
    format!("{}://{}:{}{}", req.scheme, req.domain, req.port, req.path)
}

pub async fn transfer_mmcs_container(client: &Client, req: &HttpRequest, body: Option<&[u8]>) -> Result<Response, IDSError> {
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
        upload_resp = upload_resp.body(body.to_owned());
    }

    Ok(upload_resp.send().await?)
}

pub async fn get_mmcs(sig: &[u8], token: &str, dsid: &str, url: &str) -> Result<Vec<u8>, IDSError> {
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

    let mut container_cache: HashMap<u32, (Vec<u8>, Vec<ChunkMeta>)> = HashMap::new();
    let mut confirm_responses: Vec<mmcsp::confirm_response::Request> = vec![];
    let mut body: Vec<u8> = vec![];
    // reassemble the body, going chunk by chunk
    let data = &response.f1.as_ref().unwrap().containers;
    for chunk in response.f1.as_ref().unwrap().references.as_ref().unwrap().chunk_references.iter() {
        // download bucket for chunk if bucket not downloaded yet
        if !container_cache.contains_key(&chunk.container_index) {
            let container = data.get(chunk.container_index as usize).unwrap();
            let req = container.request.as_ref().unwrap();
            let response = transfer_mmcs_container(&client, req, None).await?;
            confirm_responses.push(confirm_for_resp(&response, &get_container_url(req), &container.cl_auth_p2, None));
            container_cache.insert(chunk.container_index, (response.bytes().await?.to_vec(), container.chunks.clone()));
        }
        
        let container = container_cache.get(&chunk.container_index).unwrap();
        let start = container.1.iter().take(chunk.chunk_index as usize).fold(0, |a, chunk| a + chunk.size) as usize;
        let len = container.1.get(chunk.chunk_index as usize).unwrap().size as usize;
        
        body.extend_from_slice(&container.0[start..start + len]);
    }

    // confirm get
    let confirmation = mmcsp::ConfirmResponse {
        inner: confirm_responses
    };
    let mut buf: Vec<u8> = Vec::new();
    buf.reserve(confirmation.encoded_len());
    confirmation.encode(&mut buf).unwrap();
    let resp = send_mmcs_req(&client, url, "getComplete", &format!("{} {}", data[0].cl_auth_p1, data[0].cl_auth_p2), dsid, &buf).await?;
    if !resp.status().is_success() {
        panic!("confirm failed {}", resp.status())
    }

    Ok(body)
}