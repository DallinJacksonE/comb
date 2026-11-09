//! Token-free access is limited to same-origin requests from the local web GUI.
//! Fetch Metadata is browser-controlled; the custom header prevents simple CSRF.
use axum::{extract::Request, http::Method};
use std::net::IpAddr;

/// Validate browser provenance without weakening CLI or Git authentication.
/// The caller must still enforce the FRAME lifecycle before executing operations.
pub(crate) fn is_local_webgui(request: &Request) -> bool {
    let headers = request.headers();
    if !request.uri().path().starts_with("/api/")
        || headers.contains_key("authorization")
        || headers.get("x-comb-webgui").and_then(|v| v.to_str().ok()) != Some("1")
        || headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) != Some("same-origin")
    {
        return false;
    }
    let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let hostname = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if !hostname.eq_ignore_ascii_case("localhost")
        && !hostname.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    {
        return false;
    }
    let Ok(expected) = reqwest::Url::parse(&format!("http://{authority}")) else {
        return false;
    };
    match headers.get("origin") {
        Some(origin) => origin
            .to_str()
            .ok()
            .and_then(|v| reqwest::Url::parse(v).ok())
            .is_some_and(|origin| {
                origin.origin() == expected.origin()
                    && origin.username().is_empty()
                    && origin.password().is_none()
                    && origin.path() == "/"
                    && origin.query().is_none()
                    && origin.fragment().is_none()
            }),
        None => matches!(*request.method(), Method::GET | Method::HEAD),
    }
}
