use anyhow::Error;
use hyper::client::HttpConnector;
use hyper::{self, body::HttpBody, client::Client, Body, Request};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    ClientConfig, RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;
use waitgroup::WaitGroup;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutRsp {
    #[serde(rename = "Len")]
    pub len: usize,
}

async fn send_req_https(
    c: Arc<Client<HttpsConnector<HttpConnector>>>,
    bufsz: usize,
    url: &str,
) -> Result<(), Error> {
    let buf = vec![0u8; bufsz];

    let req = Request::builder()
        .method("POST")
        .uri(url)
        .body(hyper::Body::from(buf))?;

    let rsp = c.request(req).await?;
    let rsp_buf = rsp.into_body().data().await.unwrap()?;
    let _put_rsp: PutRsp = serde_json::from_slice(&rsp_buf)?;

    Ok(())
}

fn new_client() -> Result<Arc<Client<HttpsConnector<HttpConnector>>>, Error> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http2()
        .build();

    let client_builder = hyper::client::Client::builder();
    Ok(Arc::new(client_builder.build::<_, Body>(https)))
}

async fn test_https() -> Result<(), Error> {
    let url = std::env::var("HTEST_URL")?;
    let fut_limit: usize = std::env::var("HTEST_FUT_LIMIT")?.parse()?;
    let req_count: usize = std::env::var("HTEST_REQ_COUNT")?.parse()?;
    let bufsz: usize = std::env::var("HTEST_BUF_SIZE")?.parse()?;
    let conn_count: usize = std::env::var("HTEST_CONN_COUNT")?.parse()?;

    let mut client_vec = Vec::with_capacity(conn_count);
    for _ in 0..conn_count {
        let c = new_client()?;
        client_vec.push(c)
    }

    let handle = Handle::current();
    let allowed = Arc::new(Semaphore::new(fut_limit));

    let wg = WaitGroup::new();

    for client in client_vec.iter() {
        send_req_https(client.clone(), bufsz, url.as_str()).await?;
    }

    for i in 0..req_count {
        if i % 100 == 0 {
            println!("i={}", i);
        }
        let permit = Semaphore::acquire_owned(allowed.clone()).await?;
        let worker = wg.worker();

        let cc = client_vec[i % conn_count].clone();

        let url_clone = url.clone();
        handle.spawn(async move {
            let _ = permit;
            let _ = worker;

            let res = send_req_https(cc, bufsz, url_clone.as_str()).await;
            if res.is_err() {
                println!("err = {:?}", res.err().unwrap());
            }
        });
    }

    wg.wait().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    test_https().await?;
    Ok(())
}

struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}
