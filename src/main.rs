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

extern crate chrono_tz;

extern crate rand;

use actix_web::{
    server, http, App, HttpResponse, Query, client, AsyncResponder, Error, HttpMessage, HttpRequest, Form, Result, fs,
    dev::HttpResponseBuilder,
    middleware::{
        Logger, ErrorHandlers, Response,
        session::{
            RequestSession, SessionStorage, CookieSessionBackend
        },
    },
};

use std::{env, u8};
use askama::Template;
use base64::{encode as b64encode};
use urlencoding::encode as uencode;
use futures::Future;
use dotenv::dotenv;
use rand::thread_rng;
use rand::Rng;

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

const TIMEZONES: [&str; 591] = ["Africa/Abidjan","Africa/Accra","Africa/Addis_Ababa","Africa/Algiers","Africa/Asmara","Africa/Asmera","Africa/Bamako","Africa/Bangui","Africa/Banjul","Africa/Bissau","Africa/Blantyre","Africa/Brazzaville","Africa/Bujumbura","Africa/Cairo","Africa/Casablanca","Africa/Ceuta","Africa/Conakry","Africa/Dakar","Africa/Dar_es_Salaam","Africa/Djibouti","Africa/Douala","Africa/El_Aaiun","Africa/Freetown","Africa/Gaborone","Africa/Harare","Africa/Johannesburg","Africa/Juba","Africa/Kampala","Africa/Khartoum","Africa/Kigali","Africa/Kinshasa","Africa/Lagos","Africa/Libreville","Africa/Lome","Africa/Luanda","Africa/Lubumbashi","Africa/Lusaka","Africa/Malabo","Africa/Maputo","Africa/Maseru","Africa/Mbabane","Africa/Mogadishu","Africa/Monrovia","Africa/Nairobi","Africa/Ndjamena","Africa/Niamey","Africa/Nouakchott","Africa/Ouagadougou","Africa/Porto-Novo","Africa/Sao_Tome","Africa/Timbuktu","Africa/Tripoli","Africa/Tunis","Africa/Windhoek","America/Adak","America/Anchorage","America/Anguilla","America/Antigua","America/Araguaina","America/Argentina/Buenos_Aires","America/Argentina/Catamarca","America/Argentina/ComodRivadavia","America/Argentina/Cordoba","America/Argentina/Jujuy","America/Argentina/La_Rioja","America/Argentina/Mendoza","America/Argentina/Rio_Gallegos","America/Argentina/Salta","America/Argentina/San_Juan","America/Argentina/San_Luis","America/Argentina/Tucuman","America/Argentina/Ushuaia","America/Aruba","America/Asuncion","America/Atikokan","America/Atka","America/Bahia","America/Bahia_Banderas","America/Barbados","America/Belem","America/Belize","America/Blanc-Sablon","America/Boa_Vista","America/Bogota","America/Boise","America/Buenos_Aires","America/Cambridge_Bay","America/Campo_Grande","America/Cancun","America/Caracas","America/Catamarca","America/Cayenne","America/Cayman","America/Chicago","America/Chihuahua","America/Coral_Harbour","America/Cordoba","America/Costa_Rica","America/Creston","America/Cuiaba","America/Curacao","America/Danmarkshavn","America/Dawson","America/Dawson_Creek","America/Denver","America/Detroit","America/Dominica","America/Edmonton","America/Eirunepe","America/El_Salvador","America/Ensenada","America/Fort_Nelson","America/Fort_Wayne","America/Fortaleza","America/Glace_Bay","America/Godthab","America/Goose_Bay","America/Grand_Turk","America/Grenada","America/Guadeloupe","America/Guatemala","America/Guayaquil","America/Guyana","America/Halifax","America/Havana","America/Hermosillo","America/Indiana/Indianapolis","America/Indiana/Knox","America/Indiana/Marengo","America/Indiana/Petersburg","America/Indiana/Tell_City","America/Indiana/Vevay","America/Indiana/Vincennes","America/Indiana/Winamac","America/Indianapolis","America/Inuvik","America/Iqaluit","America/Jamaica","America/Jujuy","America/Juneau","America/Kentucky/Louisville","America/Kentucky/Monticello","America/Knox_IN","America/Kralendijk","America/La_Paz","America/Lima","America/Los_Angeles","America/Louisville","America/Lower_Princes","America/Maceio","America/Managua","America/Manaus","America/Marigot","America/Martinique","America/Matamoros","America/Mazatlan","America/Mendoza","America/Menominee","America/Merida","America/Metlakatla","America/Mexico_City","America/Miquelon","America/Moncton","America/Monterrey","America/Montevideo","America/Montreal","America/Montserrat","America/Nassau","America/New_York","America/Nipigon","America/Nome","America/Noronha","America/North_Dakota/Beulah","America/North_Dakota/Center","America/North_Dakota/New_Salem","America/Ojinaga","America/Panama","America/Pangnirtung","America/Paramaribo","America/Phoenix","America/Port-au-Prince","America/Port_of_Spain","America/Porto_Acre","America/Porto_Velho","America/Puerto_Rico","America/Punta_Arenas","America/Rainy_River","America/Rankin_Inlet","America/Recife","America/Regina","America/Resolute","America/Rio_Branco","America/Rosario","America/Santa_Isabel","America/Santarem","America/Santiago","America/Santo_Domingo","America/Sao_Paulo","America/Scoresbysund","America/Shiprock","America/Sitka","America/St_Barthelemy","America/St_Johns","America/St_Kitts","America/St_Lucia","America/St_Thomas","America/St_Vincent","America/Swift_Current","America/Tegucigalpa","America/Thule","America/Thunder_Bay","America/Tijuana","America/Toronto","America/Tortola","America/Vancouver","America/Virgin","America/Whitehorse","America/Winnipeg","America/Yakutat","America/Yellowknife","Antarctica/Casey","Antarctica/Davis","Antarctica/DumontDUrville","Antarctica/Macquarie","Antarctica/Mawson","Antarctica/McMurdo","Antarctica/Palmer","Antarctica/Rothera","Antarctica/South_Pole","Antarctica/Syowa","Antarctica/Troll","Antarctica/Vostok","Arctic/Longyearbyen","Asia/Aden","Asia/Almaty","Asia/Amman","Asia/Anadyr","Asia/Aqtau","Asia/Aqtobe","Asia/Ashgabat","Asia/Ashkhabad","Asia/Atyrau","Asia/Baghdad","Asia/Bahrain","Asia/Baku","Asia/Bangkok","Asia/Barnaul","Asia/Beirut","Asia/Bishkek","Asia/Brunei","Asia/Calcutta","Asia/Chita","Asia/Choibalsan","Asia/Chongqing","Asia/Chungking","Asia/Colombo","Asia/Dacca","Asia/Damascus","Asia/Dhaka","Asia/Dili","Asia/Dubai","Asia/Dushanbe","Asia/Famagusta","Asia/Gaza","Asia/Harbin","Asia/Hebron","Asia/Ho_Chi_Minh","Asia/Hong_Kong","Asia/Hovd","Asia/Irkutsk","Asia/Istanbul","Asia/Jakarta","Asia/Jayapura","Asia/Jerusalem","Asia/Kabul","Asia/Kamchatka","Asia/Karachi","Asia/Kashgar","Asia/Kathmandu","Asia/Katmandu","Asia/Khandyga","Asia/Kolkata","Asia/Krasnoyarsk","Asia/Kuala_Lumpur","Asia/Kuching","Asia/Kuwait","Asia/Macao","Asia/Macau","Asia/Magadan","Asia/Makassar","Asia/Manila","Asia/Muscat","Asia/Nicosia","Asia/Novokuznetsk","Asia/Novosibirsk","Asia/Omsk","Asia/Oral","Asia/Phnom_Penh","Asia/Pontianak","Asia/Pyongyang","Asia/Qatar","Asia/Qyzylorda","Asia/Rangoon","Asia/Riyadh","Asia/Saigon","Asia/Sakhalin","Asia/Samarkand","Asia/Seoul","Asia/Shanghai","Asia/Singapore","Asia/Srednekolymsk","Asia/Taipei","Asia/Tashkent","Asia/Tbilisi","Asia/Tehran","Asia/Tel_Aviv","Asia/Thimbu","Asia/Thimphu","Asia/Tokyo","Asia/Tomsk","Asia/Ujung_Pandang","Asia/Ulaanbaatar","Asia/Ulan_Bator","Asia/Urumqi","Asia/Ust-Nera","Asia/Vientiane","Asia/Vladivostok","Asia/Yakutsk","Asia/Yangon","Asia/Yekaterinburg","Asia/Yerevan","Atlantic/Azores","Atlantic/Bermuda","Atlantic/Canary","Atlantic/Cape_Verde","Atlantic/Faeroe","Atlantic/Faroe","Atlantic/Jan_Mayen","Atlantic/Madeira","Atlantic/Reykjavik","Atlantic/South_Georgia","Atlantic/St_Helena","Atlantic/Stanley","Australia/ACT","Australia/Adelaide","Australia/Brisbane","Australia/Broken_Hill","Australia/Canberra","Australia/Currie","Australia/Darwin","Australia/Eucla","Australia/Hobart","Australia/LHI","Australia/Lindeman","Australia/Lord_Howe","Australia/Melbourne","Australia/NSW","Australia/North","Australia/Perth","Australia/Queensland","Australia/South","Australia/Sydney","Australia/Tasmania","Australia/Victoria","Australia/West","Australia/Yancowinna","Brazil/Acre","Brazil/DeNoronha","Brazil/East","Brazil/West","CET","CST6CDT","Canada/Atlantic","Canada/Central","Canada/Eastern","Canada/Mountain","Canada/Newfoundland","Canada/Pacific","Canada/Saskatchewan","Canada/Yukon","Chile/Continental","Chile/EasterIsland","Cuba","EET","EST","EST5EDT","Egypt","Eire","Etc/GMT","Etc/GMT+0","Etc/GMT+1","Etc/GMT+10","Etc/GMT+11","Etc/GMT+12","Etc/GMT+2","Etc/GMT+3","Etc/GMT+4","Etc/GMT+5","Etc/GMT+6","Etc/GMT+7","Etc/GMT+8","Etc/GMT+9","Etc/GMT-0","Etc/GMT-1","Etc/GMT-10","Etc/GMT-11","Etc/GMT-12","Etc/GMT-13","Etc/GMT-14","Etc/GMT-2","Etc/GMT-3","Etc/GMT-4","Etc/GMT-5","Etc/GMT-6","Etc/GMT-7","Etc/GMT-8","Etc/GMT-9","Etc/GMT0","Etc/Greenwich","Etc/UCT","Etc/UTC","Etc/Universal","Etc/Zulu","Europe/Amsterdam","Europe/Andorra","Europe/Astrakhan","Europe/Athens","Europe/Belfast","Europe/Belgrade","Europe/Berlin","Europe/Bratislava","Europe/Brussels","Europe/Bucharest","Europe/Budapest","Europe/Busingen","Europe/Chisinau","Europe/Copenhagen","Europe/Dublin","Europe/Gibraltar","Europe/Guernsey","Europe/Helsinki","Europe/Isle_of_Man","Europe/Istanbul","Europe/Jersey","Europe/Kaliningrad","Europe/Kiev","Europe/Kirov","Europe/Lisbon","Europe/Ljubljana","Europe/London","Europe/Luxembourg","Europe/Madrid","Europe/Malta","Europe/Mariehamn","Europe/Minsk","Europe/Monaco","Europe/Moscow","Europe/Nicosia","Europe/Oslo","Europe/Paris","Europe/Podgorica","Europe/Prague","Europe/Riga","Europe/Rome","Europe/Samara","Europe/San_Marino","Europe/Sarajevo","Europe/Saratov","Europe/Simferopol","Europe/Skopje","Europe/Sofia","Europe/Stockholm","Europe/Tallinn","Europe/Tirane","Europe/Tiraspol","Europe/Ulyanovsk","Europe/Uzhgorod","Europe/Vaduz","Europe/Vatican","Europe/Vienna","Europe/Vilnius","Europe/Volgograd","Europe/Warsaw","Europe/Zagreb","Europe/Zaporozhye","Europe/Zurich","GB","GB-Eire","GMT","GMT+0","GMT-0","GMT0","Greenwich","HST","Hongkong","Iceland","Indian/Antananarivo","Indian/Chagos","Indian/Christmas","Indian/Cocos","Indian/Comoro","Indian/Kerguelen","Indian/Mahe","Indian/Maldives","Indian/Mauritius","Indian/Mayotte","Indian/Reunion","Iran","Israel","Jamaica","Japan","Kwajalein","Libya","MET","MST","MST7MDT","Mexico/BajaNorte","Mexico/BajaSur","Mexico/General","NZ","NZ-CHAT","Navajo","PRC","PST8PDT","Pacific/Apia","Pacific/Auckland","Pacific/Bougainville","Pacific/Chatham","Pacific/Chuuk","Pacific/Easter","Pacific/Efate","Pacific/Enderbury","Pacific/Fakaofo","Pacific/Fiji","Pacific/Funafuti","Pacific/Galapagos","Pacific/Gambier","Pacific/Guadalcanal","Pacific/Guam","Pacific/Honolulu","Pacific/Johnston","Pacific/Kiritimati","Pacific/Kosrae","Pacific/Kwajalein","Pacific/Majuro","Pacific/Marquesas","Pacific/Midway","Pacific/Nauru","Pacific/Niue","Pacific/Norfolk","Pacific/Noumea","Pacific/Pago_Pago","Pacific/Palau","Pacific/Pitcairn","Pacific/Pohnpei","Pacific/Ponape","Pacific/Port_Moresby","Pacific/Rarotonga","Pacific/Saipan","Pacific/Samoa","Pacific/Tahiti","Pacific/Tarawa","Pacific/Tongatapu","Pacific/Truk","Pacific/Wake","Pacific/Wallis","Pacific/Yap","Poland","Portugal","ROC","ROK","Singapore","Turkey","UCT","US/Alaska","US/Aleutian","US/Arizona","US/Central","US/East-Indiana","US/Eastern","US/Hawaii","US/Indiana-Starke","US/Michigan","US/Mountain","US/Pacific","US/Samoa","UTC","Universal","W-SU","WET","Zulu"];

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

        let i = IndexTemplate { logged_in: true, channels: clocks, guilds: guilds, timezones: TIMEZONES, login_redir: login_url, delete_redir: form_redir, create_redir: create_redir };
        req.reply(http::StatusCode::OK, i.render().unwrap())

    }
    else {
        let i = IndexTemplate { logged_in: false, channels: vec![], guilds: vec![], timezones: TIMEZONES, login_redir: login_url, delete_redir: form_redir, create_redir: create_redir };
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

    if let Some(client_id) = req.session().get::<u64>("client_id").unwrap() {
        let database = req.state().database.clone();

        let timezone = create_form.timezone.split(" ").nth(0).unwrap();

        let mut guild_check = database.prep_exec("SELECT 1 FROM user_guilds WHERE user = :u AND guild = :g", params!{"u" => client_id, "g" => &create_form.guild}).unwrap();

        match guild_check.next() {
            Some(_) => {
                if !TIMEZONES.contains(&timezone) {
                    req.reply_builder(http::StatusCode::SEE_OTHER, move |mut r| r
                        .header("Location", format!("{}?err=No+timezone", index_url).as_str())
                        .content_type("text/plain")
                        .body("Redirected"))                
                }
                else {
                    client::ClientRequest::post(&format!("{}/guilds/{}/channels", DISCORD_BASE, create_form.guild))
                        .header("Authorization", format!("Bot {}", env::var("BOT_TOKEN").unwrap()).as_str())
                        .json(DiscordChannelCreator { name: create_form.name.clone(), r#type: 2 }).unwrap()
                        .send()
                        .map_err(|m| {
                            println!("{:?}", m);
                            Error::from(m)
                        })
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
                        .responder()
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

    let mut query = database.prep_exec("SELECT 1 FROM user_guilds WHERE user = :u AND cache_time > UNIX_TIMESTAMP()", params!{"u" => &client_id}).unwrap();

    if query.next().is_none() {
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
                                    .filter(|guild| (guild.permissions & PERMISSION_CHECK) != 0)
                                    .for_each(|guild| {
                                        database.prep_exec("INSERT INTO user_guilds (user, guild, guild_name) VALUES (:u, :g, :n)",
                                            params!{"u" => &client_id, "g" => &guild.id, "n" => &guild.name}).unwrap();
                                    });

                                Ok(HttpResponse::SeeOther()
                                    .header("Location", req.url_for_static("index").unwrap().as_str())
                                    .body(""))
                            })
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
                            req.session().set("client_id", user.id.parse::<u64>().unwrap()).unwrap();

                            Ok(HttpResponse::SeeOther()
                                .header("Location", req.url_for_static("sync").unwrap().as_str())
                                .content_type("text/html")
                                .body(""))
                    })
            })
        .responder()
}


fn login(req: HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let mut raw_bytes1: [u8; 32] = [0; 32];
    let mut raw_bytes2: [u8; 32] = [0; 32];

    thread_rng().fill(&mut raw_bytes1);
    thread_rng().fill(&mut raw_bytes2);

    let ssid = b64encode(&raw_bytes1) + &b64encode(&raw_bytes2);

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

    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

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
