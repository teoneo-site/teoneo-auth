use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::common::error::ErrorResponse;


pub async fn get_request<R: for<'a> Deserialize<'a>>(httpclient: &reqwest::Client, req_url: &str, ) -> anyhow::Result<R> {
    let response = httpclient.get(req_url).send().await?;
    match response.status() {
        StatusCode::OK => {
            // Parse the success body as JSON
            let resp: R = response.json().await.unwrap();
            return Ok(resp);
        }
        _ => {
            let err = response.json::<ErrorResponse>().await?;
            return Err(anyhow::anyhow!("Internal error: could not fetch {}: {}", req_url, err.error_msg));
        }
    }
}

pub async fn post_request<Req: Serialize, Resp: for<'a> Deserialize<'a>>(
    http_client: &reqwest::Client,
    req_url: &str,
    req: Req
) -> anyhow::Result<Resp> {
    let response = http_client
        .post(req_url)
        .json(&req)
        .send()
        .await?;
    match response.status() {
        StatusCode::OK => {
            let resp = response.json::<Resp>().await?;
            return Ok(resp);
        }
        _ => {
            let err = response.json::<ErrorResponse>().await?;
            return Err(anyhow::anyhow!("Internal error: could not fetch {}: {}", req_url, err.error_msg));
        }
    }
}

pub async fn post_request_empty<Req: Serialize>(
    http_client: &reqwest::Client,
    req_url: &str,
    req: Req
) -> anyhow::Result<()> {
    let response = http_client
        .post(req_url)
        .json(&req)
        .send()
        .await?;
    match response.status() {
        StatusCode::OK => {
            return Ok(());
        }
        _ => {
            let err = response.json::<ErrorResponse>().await?;
            return Err(anyhow::anyhow!("Internal error: could not fetch {}: {}", req_url, err.error_msg));
        }
    }
}