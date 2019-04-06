use askama::Template;

use crate::models::{ClockChannel, DiscordGuild};

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub channels: Vec<ClockChannel>,
    pub delete_redir: String,
    pub create_redir: String,
    pub guilds: Vec<DiscordGuild>,
    pub timezones: [&'static str; 591],
}

#[derive(Template)]
#[template(path = "bad_session.html")]
pub struct BadSession {
    pub home_redir: String,
    pub status: u16,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {
    pub login_redir: String,
}

#[derive(Template)]
#[template(path = "get_guilds_error.html")]
pub struct GetGuildsError {
    pub home_redir: String,
}