extern crate actix_web;
extern crate askama;

#[macro_use]
extern crate serde_derive;

extern crate sha2;
extern crate base64;
extern crate urlencoding;

use actix_web::{server, http, App, HttpRequest, HttpResponse, Result, Query};
use actix_web::middleware::session::{RequestSession, SessionStorage, CookieSessionBackend};
// use askama::Template;
use sha2::{Sha512Trunc224 as Sha, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::u8;
use base64::{encode as b64encode};
use urlencoding::encode as uencode;


#[derive(Deserialize)]
struct OAuthQuery {
    state: String,
    code: String,
}


fn create_url<'a>(redirect: &'a str, sid: &'a str) -> String {
    format!("https://discordapp.com/api/oauth2/authorize?response_type=code&client_id={}&scope=identify%20guilds&redirect_uri={}&state={}", env::var("CLIENT_ID").unwrap(), uencode(redirect), uencode(sid))
}

fn index(req: &HttpRequest) -> Result<HttpResponse> {
    if let Some(_discord_token) = req.session().get::<String>("code")? {

        Ok(HttpResponse::build(http::StatusCode::OK)
            .content_type("text/html")
            .body("All good"))
    }
    else {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let raw_bytes: [u8; 16] = unsafe { std::mem::transmute(since_the_epoch.as_millis()) };

        let mut hasher = Sha::new();
        hasher.input(raw_bytes);

        let sid = &hasher.result()[..];
        let ssid = b64encode(sid);

        req.session().set("sid", &ssid)?;
        let url = req.url_for_static("oauth").unwrap();

        Ok(HttpResponse::build(http::StatusCode::from_u16(303).unwrap())
            .header("Location", 
                create_url(
                    url.as_str(),
                    &ssid
                ).as_str()
            )
            .content_type("text/plain")
            .body("Redirected"))
    }
}

fn oauth((query, req): (Query<OAuthQuery>, HttpRequest)) -> Result<HttpResponse> {
    if let Some(ssid) = req.session().get::<String>("sid")? {
        req.session().set("code", &query.code)?;

        if ssid == query.state {
            Ok(HttpResponse::build(http::StatusCode::OK)
                .content_type("text/html")
                .body("Success"))
        }
        else {
            Ok(HttpResponse::build(http::StatusCode::OK)
                .content_type("text/html")
                .body("Something fishy is going on here"))   
        }
    }
    else {
        Ok(HttpResponse::build(http::StatusCode::from_u16(303).unwrap())
            .header("Location", req.url_for_static("/").unwrap().as_str())
            .content_type("text/plain")
            .body("Redirected"))
    }
}


fn main() {
    server::HttpServer::new(|| {
        App::new()
            .middleware(
                SessionStorage::new(
                    CookieSessionBackend::signed(&[0; 32])
                        .secure(false)
                    )
                )
            .resource("/", |r| r.method(http::Method::GET).f(index))
            .resource("/oauth", |r| {
                r.name("oauth");
                r.method(http::Method::GET)
                .with(oauth)
            })
            .finish()

    }).workers(4)
    .bind("localhost:5000")
    .expect("Failed to bind to address")
    .run();
}