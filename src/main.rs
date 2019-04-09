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

extern crate env_logger;

extern crate chrono;
extern crate chrono_tz;

extern crate rand;

use actix_web::{
    server, http, App, HttpResponse, Query, client, AsyncResponder, Error, HttpMessage, HttpRequest, Form, Result, fs,
    dev::HttpResponseBuilder, 
    middleware::{
        csrf,
        Logger, ErrorHandlers, Response,
        session::{
            RequestSession, SessionStorage, CookieSessionBackend
        },
    },
};

use chrono_tz::Tz;
use chrono::prelude::*;

use std::{env, u8};
use askama::Template;
use base64::{encode as b64encode};
use urlencoding::encode as uencode;
use futures::Future;
use dotenv::dotenv;
use rand::thread_rng;
use rand::Rng;
use std::time::Duration;
use std::sync::Arc;

mod models;
mod templates;

use crate::models::*;
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

const ADMINISTRATOR: u32 = 0x8;
const MANAGE_GUILD: u32 = 0x20;
const MANAGE_CHANNELS: u32 = 0x10;

const PERMISSION_CHECK: u32 = ADMINISTRATOR | MANAGE_GUILD | MANAGE_CHANNELS;


struct AppState {
    database: mysql::Pool, // not in a cell; pool can be safely cloned to get a connection
}


fn create_auth_url<'a>(redirect: &'a str, sid: &'a str) -> String {
    format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=identify%20guilds&redirect_uri={}&state={}", DISCORD_BASE, env::var("CLIENT_ID").unwrap(), uencode(redirect), uencode(sid))
}

fn generate_noise() -> String {
    let mut raw_bytes1: [u8; 32] = [0; 32];
    let mut raw_bytes2: [u8; 32] = [0; 32];

    thread_rng().fill(&mut raw_bytes1);
    thread_rng().fill(&mut raw_bytes2);

    b64encode(&raw_bytes1) + &b64encode(&raw_bytes2)
}


fn index(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let login_url = req.url_for_static("login").unwrap().to_string();
    let form_redir = req.url_for_static("delete_channel").unwrap().to_string();
    let create_redir = req.url_for_static("create_channel").unwrap().to_string();
    
    if let Some(client_id) = req.session().get::<u64>("client_id").unwrap() {
        let database = req.state().database.clone();

        let query = database.prep_exec(r#"
SELECT clocks.channel, clocks.timezone, clocks.name, clocks.guild, user_guilds.guild_name 
FROM clocks, user_guilds
WHERE 
    user_guilds.user = :u AND
    clocks.guild = user_guilds.guild"#, params!{"u" => &client_id}).unwrap();

        let clocks = query.into_iter().map(|row| {
            let (channel, timezone, name, _guild, guild_name) = mysql::from_row::<(u64, String, String, u64, String)>(row.unwrap());

            ClockChannel { id: channel, timezone: timezone, name: name, guild: guild_name }
        }).collect();

        let guild_query = database.prep_exec(r#"SELECT guild, guild_name FROM user_guilds WHERE user = :u"#, params!{"u" => &client_id}).unwrap();

        let guilds: Vec<DiscordGuild> = guild_query.into_iter().map(|row| {
            let (id, name) = mysql::from_row::<(u64, String)>(row.unwrap());

            DiscordGuild { id: id.to_string(), name: name, permissions: 0 }
        }).collect();

        let i = IndexTemplate { channels: clocks, guilds: guilds, delete_redir: form_redir, create_redir: create_redir, };
        req.reply(http::StatusCode::OK, i.render().unwrap())

    }
    else {
        let i = Login { login_redir: login_url };
        req.reply(http::StatusCode::OK, i.render().unwrap())
    }
}


fn delete_channel((req, delete_form): (HttpRequest<AppState>, Form<DeleteChannel>)) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let index_url = req.url_for_static("index").unwrap();

    if let Some(client_id) = req.session().get::<u64>("client_id").unwrap() {
        let database = req.state().database.clone();
        let clock_id = delete_form.id;

        database.prep_exec(r#"
DELETE FROM clocks 
WHERE 
    channel = :id AND 
    guild IN (SELECT guild FROM user_guilds WHERE user = :u)"#, params!{"id" => clock_id, "u" => client_id}).unwrap();

        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
            .header("Location", index_url.as_str())
            .content_type("text/plain")
            .body(""))
    }
    else {
        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
            .header("Location", index_url.as_str())
            .content_type("text/plain")
            .body(""))
    }
}


fn create_channel((req, create_form): (HttpRequest<AppState>, Form<CreateChannel>)) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let index_url = req.url_for_static("index").unwrap();
    let database = req.state().database.clone();

    let mut check_query = database.prep_exec("SELECT COUNT(*) FROM clocks WHERE guild = :g", params!{"g" => &create_form.guild}).unwrap();

    let r = mysql::from_row::<(u32)>(check_query.next().unwrap().unwrap());

    let max_channels = env::var("MAX_CLOCKS").unwrap().parse::<u32>().unwrap();

    if r >= max_channels {
        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
            .header("Location", format!("{}?err=Too+many", index_url).as_str())
            .content_type("text/plain")
            .body(""))
    }
    else if let Some(client_id) = req.session().get::<u64>("client_id").unwrap() {

        let timezone = create_form.timezone.split(" ").nth(0).unwrap();

        let mut guild_check = database.prep_exec("SELECT 1 FROM user_guilds WHERE user = :u AND guild = :g", params!{"u" => client_id, "g" => &create_form.guild}).unwrap();

        match guild_check.next() {
            Some(_) => {
                let t = timezone.parse::<Tz>();

                match t {
                    Ok(timezone) => {
                        let dt = Utc::now().with_timezone(&timezone);
                        let name = dt.format(&create_form.name).to_string();

                        client::ClientRequest::post(&format!("{}/guilds/{}/channels", DISCORD_BASE, create_form.guild))
                            .timeout(Duration::from_secs(8))
                            .header("Authorization", format!("Bot {}", env::var("BOT_TOKEN").unwrap()).as_str())
                            .json(DiscordChannelCreator { name: name, r#type: 2 }).unwrap()
                            .send()
                            .and_then(
                                move |resp| {
                                    resp.json::<DiscordChannel>()
                                        .then(
                                            move |res| {
                                                match res {
                                                    Ok(body) => {
                                                        database.prep_exec("INSERT INTO clocks (channel, timezone, name, guild) VALUES (:c, :t, :n, :g)",
                                                            params!{"c" => &body.id, "t" => &create_form.timezone, "n" => &create_form.name, "g" => &create_form.guild}
                                                        ).unwrap();

                                                        Ok(HttpResponse::SeeOther()
                                                            .header("Location", index_url.as_str())
                                                            .body("Redirected"))
                                                    },

                                                    Err(e) => {
                                                        println!("{:?}", e);

                                                        Ok(HttpResponse::SeeOther()
                                                            .header("Location", format!("{}{}", index_url, "?err=No+perms").as_str())
                                                            .body("Redirected"))
                                                    }
                                                }
                                            })
                                })
                            .or_else(move |_| {
                                Ok(HttpResponse::SeeOther()
                                    .header("Location", format!("{}?err=Other", req.url_for_static("index").unwrap()).as_str())
                                    .body("Redirected"))
                            })
                            .responder()
                    },

                    Err(_) => {
                        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
                            .header("Location", format!("{}?err=No+timezone", index_url).as_str())
                            .content_type("text/plain")
                            .body("Redirected"))
                    },
                }
            },

            None => {
                req.reply(http::StatusCode::FORBIDDEN, "<html><h1>403 Forbidden</h1></html>")
            }
        }
    }
    else {
        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
            .header("Location", index_url.as_str())
            .content_type("text/plain")
            .body(""))
    }
}


fn get_all_guilds(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let database = req.state().database.clone();
    let discord_token: String = req.session().get("access_token").unwrap().unwrap();
    let client_id: u64 = req.session().get("client_id").unwrap().unwrap();

    let index = req.url_for_static("index").unwrap();
    let error_page = Arc::new(GetGuildsError { home_redir: index.clone().to_string() });

    let error_page1 = error_page.clone();

    let mut query = database.prep_exec("SELECT 1 FROM user_guilds WHERE user = :u AND cache_time > UNIX_TIMESTAMP()", params!{"u" => &client_id}).unwrap();

    if query.next().is_none() {
        database.prep_exec("DELETE FROM user_guilds WHERE user = :u", params!{"u" => &client_id}).unwrap();

        client::ClientRequest::get(&format!("{}/users/@me/guilds", DISCORD_BASE))
            .header("Authorization", format!("Bearer {}", discord_token).as_str())
            .finish().unwrap()
            .send()
            .and_then(
                move |resp| {
                    resp.json::<Vec<DiscordGuild>>()
                        .and_then(
                            move |body| {
                                body.iter()
                                    .filter(|guild| (guild.permissions & PERMISSION_CHECK) != 0)
                                    .for_each(|guild| {
                                        database.prep_exec("INSERT INTO user_guilds (user, guild, guild_name) VALUES (:u, :g, :n)",
                                            params!{"u" => &client_id, "g" => &guild.id, "n" => &guild.name}).unwrap();
                                    });

                                Ok(HttpResponse::SeeOther()
                                    .header("Location", index.as_str())
                                    .body(""))
                            })
                        .or_else(
                            move |_| {
                                Ok(HttpResponse::InternalServerError()
                                    .content_type("text/html")
                                    .body(error_page1.render().unwrap()))
                            })
                })
            .or_else(
                move |_| {
                    Ok(HttpResponse::InternalServerError()
                        .content_type("text/html")
                        .body(error_page.render().unwrap()))
                })
            .responder()
    }
    else {
        let index_url = req.url_for_static("index").unwrap();
        req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
            .header("Location", index_url.as_str())
            .content_type("text/plain")
            .body("")
        )
    }
}


fn get_user_data(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let discord_token: String = req.session().get("access_token").unwrap().unwrap();

    let login_url = req.url_for_static("login").unwrap();
    let login_url_ = req.url_for_static("login").unwrap();

    client::ClientRequest::get(&format!("{}/users/@me", DISCORD_BASE))
        .header("Authorization", format!("Bearer {}", discord_token).as_str())
        .finish().unwrap()
        .send()
        .and_then(
            move |resp| {
                resp.json::<DiscordUser>()
                    .and_then(
                        move |user| {
                            req.session().set("client_id", user.id.parse::<u64>().unwrap()).unwrap();

                            Ok(HttpResponse::SeeOther()
                                .header("Location", req.url_for_static("sync").unwrap().as_str())
                                .content_type("text/html")
                                .body(""))
                    })
                    .or_else(
                        move |_| {
                            Ok(HttpResponse::SeeOther()
                                .header("Location", login_url.as_str())
                                .content_type("text/html")
                                .body(""))
                    })
            })
        .or_else(
            move |_| {
                Ok(HttpResponse::SeeOther()
                    .header("Location", login_url_.as_str())
                    .content_type("text/html")
                    .body(""))
            })
        .responder()
}


fn login(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let ssid = generate_noise();

    req.session().set("session_id", &ssid).unwrap();
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
    if let Some(ssid) = req.session().get::<String>("session_id").unwrap() {
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
                                    .header("Location", req.url_for_static("sync_user").unwrap().as_str())
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


fn render_404<S>(_: &HttpRequest<S>, resp: HttpResponse) -> Result<Response> {
   let mut builder = resp.into_builder();
   let response = builder.header(http::header::CONTENT_TYPE, "text/plain").body("Not found");
   Ok(Response::Done(response))
}


fn main() {
    dotenv().ok();

    env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    server::HttpServer::new(|| {
        let url = env::var("SQL_URL").expect("SQL URL environment variable missing");
        let mysql_conn = mysql::Pool::new(url).unwrap();

        let secure = env::var("SECURE").is_ok();

        if secure {
            println!("Session is set to secure");
        }

        App::with_state(AppState { database: mysql_conn, })
            .middleware(
                SessionStorage::new(
                    CookieSessionBackend::signed(env::var("SECRET").unwrap().as_bytes())
                        .secure(secure)
                    )
                )
            .middleware(
                csrf::CsrfFilter::new().allowed_origin(env::var("CSRF_ORIGIN").expect("No CSRF origin set"))
            )
            .middleware(Logger::default())
            .middleware(Logger::new("%a %{User-Agent}i"))
            .middleware(ErrorHandlers::new()
                .handler(http::StatusCode::NOT_FOUND, render_404))

            .handler("/static", fs::StaticFiles::new("static/").unwrap())

            .resource("/", |r| {
                r.name("index");
                r.method(http::Method::GET)
                .with(index)
            })
            .resource("/login", |r| {
                r.name("login");
                r.method(http::Method::GET)
                .with(login)
            })
            .resource("/sync_guilds", |r| {
                r.name("sync");
                r.method(http::Method::GET)
                .with(get_all_guilds)
            })
            .resource("/sync_user", |r| {
                r.name("sync_user");
                r.method(http::Method::GET)
                .with(get_user_data)
            })
            .resource("/oauth", |r| {
                r.name("oauth");
                r.method(http::Method::GET)
                .with(oauth)
            })
            .resource("/delete_channel", |r| {
                r.name("delete_channel");
                r.method(http::Method::POST)
                .with(delete_channel)
            })
            .resource("/create_channel", |r| {
                r.name("create_channel");
                r.method(http::Method::POST)
                .with(create_channel)
            })
            .finish()

    }).workers(4)
    .bind(env::var("BIND_URL").expect("BIND_URL address missing from environment"))
    .expect("Failed to bind to address")
    .run();
}
