extern crate actix;
extern crate actix_web;
extern crate askama;

#[macro_use]
extern crate mysql;
extern crate dotenv;

extern crate futures;

#[macro_use]
extern crate serde_derive;

extern crate sha2;
extern crate base64;
extern crate urlencoding;

use actix_web::{server, http, App, HttpResponse, Query, client, AsyncResponder, Error, HttpMessage, HttpRequest};
use actix_web::dev::HttpResponseBuilder;
use actix_web::middleware::session::{RequestSession, SessionStorage, CookieSessionBackend};
use sha2::{Sha512Trunc224 as Sha, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, u8};
use askama::Template;
use base64::{encode as b64encode};
use urlencoding::encode as uencode;
use futures::Future;
use dotenv::dotenv;

mod form_types;
mod templates;

use crate::form_types::*;
use crate::templates::*;


trait ReplyTo<T> {
    fn reply(&self, status: http::StatusCode, message: T) -> Box<Future<Item = HttpResponse, Error = Error>>;
}

trait ReplyBuilder<F> {
    fn reply_builder(&self, status: http::StatusCode, f: F) -> Box<Future<Item = HttpResponse, Error = Error>>;
}


impl<T: 'static> ReplyTo<T> for HttpRequest<AppState> 
    where 
        actix_web::Binary: std::convert::From<T> {
    fn reply(&self, status: http::StatusCode, message: T) -> Box<Future<Item = HttpResponse, Error = Error>> {
        Box::new(self.body().map_err(Error::from).map(move |_f| {
            HttpResponse::build(status)
                .content_type("text/html")
                .body(message)
            }))
    }
}

impl<F: 'static> ReplyBuilder<F> for HttpRequest<AppState>
    where
        F: FnOnce(HttpResponseBuilder) -> HttpResponse {
    fn reply_builder(&self, status: http::StatusCode, f: F) -> Box<Future<Item = HttpResponse, Error = Error>> {
        Box::new(self.body().map_err(Error::from).map(move |_f| {
            f(HttpResponse::build(status))
        }))
    }
}


const DISCORD_BASE: &str = "https://discordapp.com/api/v6";

const ADMINISTRATOR: u16 = 0x8;
const MANAGE_CHANNELS: u16 = 0x10;
const MANAGE_GUILD: u16 = 0x20;

struct AppState {
    database: mysql::Pool,
}

fn create_auth_url<'a>(redirect: &'a str, sid: &'a str) -> String {
    format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=identify%20guilds&redirect_uri={}&state={}", DISCORD_BASE, env::var("CLIENT_ID").unwrap(), uencode(redirect), uencode(sid))
}

fn index(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    if let Some(discord_token) = req.session().get::<String>("access_token").unwrap() {

        let login_url = req.url_for_static("login").unwrap().to_string();
        let session = req.session();

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
                        .and_then(
                            move |user| {
                                session.set("client_id", user.id.parse::<u64>().unwrap()).unwrap();

                                let i = IndexTemplate { logged_in: true, user: user.username.clone(), login_redir: login_url };

                                Ok(HttpResponse::Ok()
                                    .content_type("text/html")
                                    .body(i.render().unwrap()))
                        })
                })
            .responder()

    }
    else {
        let i = IndexTemplate { logged_in: false, user: String::from(""), login_redir: req.url_for_static("login").unwrap().to_string() };
        req.reply(http::StatusCode::OK, i.render().unwrap())
    }
}


fn get_all_guilds(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let database = req.state().database.clone();
    let discord_token: String = req.session().get("access_token").unwrap().unwrap();
    let client_id: u64 = req.session().get("client_id").unwrap().unwrap();

    let mut query = database.prep_exec("SELECT 1 FROM user_guilds WHERE user = :u AND cache_time < UNIX_TIMESTAMP()", params!{"u" => &client_id}).unwrap();

    if query.next().is_some() {
        database.prep_exec("DELETE FROM user_guilds WHERE user = :u", params!{"u" => &client_id}).unwrap();

        client::ClientRequest::get(&format!("{}/users/@me/guilds", DISCORD_BASE))
            .header("Authorization", format!("Bearer {}", discord_token).as_str())
            .finish().unwrap()
            .send()
            .map_err(|m| {
                println!("{:?}", m);
                Error::from(m)
            })
            .and_then(
                move |resp| {
                    resp.json::<Vec<DiscordGuild>>()
                        .map_err(|m| {
                            println!("{:?}", m);
                            Error::from(m)
                        })
                        .and_then(
                            move |body| {
                                body.iter()
                                    .filter(|guild| (guild.permissions & ADMINISTRATOR) != 0 || (guild.permissions & MANAGE_GUILD) != 0 || (guild.permissions & MANAGE_CHANNELS) != 0)
                                    .for_each(|guild| {
                                        database.prep_exec("INSERT INTO user_guilds (user, guild, guild_name) VALUES (:u, :g, :n)",
                                            params!{"u" => &client_id, "g" => &guild.id, "n" => &guild.name}).unwrap();
                                    });

                                Ok(HttpResponse::Ok()
                                    .content_type("text/html")
                                    .body(""))
                            })
                })
            .responder()
    }
    else {
        req.reply(http::StatusCode::OK, "")
    }
}


fn login(req: &HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let raw_bytes: [u8; 16] = unsafe { std::mem::transmute(since_the_epoch.as_millis()) };

    let mut hasher = Sha::new();
    hasher.input(raw_bytes);

    let sid = &hasher.result()[..];
    let ssid = b64encode(sid);

    req.session().set("sid", &ssid).unwrap();
    let url = req.url_for_static("oauth").unwrap();

    req.reply_builder(http::StatusCode::SEE_OTHER, move |mut h| h
        .header("Location", 
            create_auth_url(
                url.as_str(),
                ssid.as_str()
            ).as_str()
        )
        .content_type("text/plain")
        .body("Redirected")
    )
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

                                Ok(HttpResponse::build(http::StatusCode::SEE_OTHER)
                                    .header("Location", req.url_for_static("index").unwrap().as_str())
                                    .content_type("text/plain")
                                    .body("You have been logged in. Your browser will redirect you now."))
                            })
                    })
                .responder()
        }
        else {
            let url = req.url_for_static("index").unwrap();
            let t = BadSession { home_redir: url.to_string(), status: 403 };

            req.reply(http::StatusCode::FORBIDDEN, t.render().unwrap())
        }
    }
    else {
        let url = req.url_for_static("index").unwrap();
        let t = BadSession { home_redir: url.to_string(), status: 400 };

        req.reply(http::StatusCode::BAD_REQUEST, t.render().unwrap())
    }
}


fn main() {
    dotenv().ok();

    server::HttpServer::new(|| {
        let url = env::var("SQL_URL").expect("SQL URL environment variable missing");
        let mysql_conn = mysql::Pool::new(url).unwrap();

        App::with_state(AppState { database: mysql_conn })
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
