extern crate actix;
extern crate actix_web;
extern crate askama;

extern crate futures;

#[macro_use]
extern crate serde_derive;

extern crate sha2;
extern crate base64;
extern crate urlencoding;

use actix_web::{server, http, App, HttpResponse, Result, Query, client, AsyncResponder, Error, HttpMessage, HttpRequest};
use actix_web::middleware::session::{RequestSession, SessionStorage, CookieSessionBackend};
use askama::Template;
use sha2::{Sha512Trunc224 as Sha, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::u8;
use base64::{encode as b64encode};
use urlencoding::encode as uencode;
use futures::Future;


const DISCORD_BASE: &str = "https://discordapp.com/api/v6";

struct AppState;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    logged_in: bool,
    user: String,
    login_redir: String,
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    client_id: String,
    client_secret: String,
    grant_type: String,
    code: String,
    redirect_uri: String,
    scope: String,
}

impl TokenRequest {
    fn new(code: String, redir: String) -> TokenRequest {
        TokenRequest {
            client_id: env::var("CLIENT_ID").expect("CLIENT_ID missing"),
            client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET missing"),
            grant_type: String::from("authorization_code"),
            code: code,
            redirect_uri: redir,
            scope: String::from("identify guilds"),
        }
    }
}

#[derive(Deserialize)]
struct OAuthQuery {
    state: String,
    code: String,
}


#[derive(Debug, Deserialize)]
struct OAuthAccess {
    access_token: String,
    token_type: String,
    expires_in: u32,
    refresh_token: String,
    scope: String,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
}


fn create_auth_url<'a>(redirect: &'a str, sid: &'a str) -> String {
    format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=identify%20guilds&redirect_uri={}&state={}", DISCORD_BASE, env::var("CLIENT_ID").unwrap(), uencode(redirect), uencode(sid))
}

fn index(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    if let Some(discord_token) = req.session().get::<String>("access_token").unwrap() {
        client::ClientRequest::get(&format!("{}/users/@me", DISCORD_BASE))
            .header("Authorization", format!("Bearer {}", discord_token).as_str())
            .finish().unwrap()
            .send()
            .map_err(|m| {
                println!("{:?}", m);
                Error::from(m)
            })
            .and_then(
                move |resp| {
                    resp.json::<DiscordUser>()
                        .map_err(|m| {
                            println!("{:?}", m);
                            Error::from(m)
                        })
                        .and_then(move |body| {
                            let i = IndexTemplate { logged_in: true, user: body.username.clone(), login_redir: req.url_for_static("login").unwrap().to_string() };

                            Ok(HttpResponse::Ok()
                                .content_type("text/html")
                                .body(i.render().unwrap()))
                        })
                })
            .responder()
    }
    else {
        let i = IndexTemplate { logged_in: false, user: String::from(""), login_redir: req.url_for_static("login").unwrap().to_string() };
        Box::new(req.body().map_err(Error::from).map(move |_f| {
            HttpResponse::Ok()
                .content_type("text/html")
                .body(i.render().unwrap())
            }))
    }
}

fn login(req: &HttpRequest<AppState>) -> Result<HttpResponse> {
    if let Some(_discord_token) = req.session().get::<String>("access_token")? {
        Ok(HttpResponse::build(http::StatusCode::OK)
            .content_type("text/html")
            .body("User authorized"))
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
                create_auth_url(
                    url.as_str(),
                    &ssid
                ).as_str()
            )
            .content_type("text/plain")
            .body("Redirected"))
    }
}

fn oauth((query, req): (Query<OAuthQuery>, HttpRequest<AppState>)) -> Box<Future<Item = HttpResponse, Error = Error>> {
    if let Some(ssid) = req.session().get::<String>("sid").unwrap() {
        if ssid == query.state {
            let code = &query.code;
            let c = TokenRequest::new(code.clone(), req.url_for_static("oauth").unwrap().to_string());

            client::ClientRequest::post(format!("{}/oauth2/token", DISCORD_BASE).as_str())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(c).unwrap()
                .send()
                .map_err(|m| {
                    println!("{:?}", m);
                    Error::from(m)
                })
                .and_then(
                    move |resp| {
                        resp.json::<OAuthAccess>()
                            .from_err()
                            .and_then(move |body| {
                                req.session().set("access_token", body.access_token.clone()).unwrap();
                                Ok(HttpResponse::build(http::StatusCode::from_u16(303).unwrap())
                                    .header("Location", req.url_for_static("index").unwrap().as_str())
                                    .content_type("text/plain")
                                    .body("You have been logged in. Your browser will redirect you now."))
                            })
                    })
                .responder()
        }
        else {
            Box::new(req.body().map_err(Error::from).map(move |_f| {
                HttpResponse::build(http::StatusCode::OK)
                    .content_type("text/html")
                    .body(r#"OAuth state check failed. Did you mess with the session storage? <a href="/">Return home</a>"#)
                }))
        }
    }
    else {
        Box::new(req.body().map_err(Error::from).map(move |_f| {
            HttpResponse::build(http::StatusCode::from_u16(303).unwrap())
                .header("Location", req.url_for_static("index").unwrap().as_str())
                .content_type("text/plain")
                .body("Session token is missing. Your browser will redirect you now.")
            }))
    }
}


fn main() {
    server::HttpServer::new(|| {
        App::with_state(AppState {  })
            .middleware(
                SessionStorage::new(
                    CookieSessionBackend::signed(&[0; 32])
                        .secure(false)
                    )
                )
            .resource("/", |r| {
                r.name("index");
                r.method(http::Method::GET).with(index)
            })
            .resource("/login", |r| {
                r.name("login");
                r.method(http::Method::GET).f(login)
            })
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