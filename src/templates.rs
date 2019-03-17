use askama::Template;

use crate::models::{ClockChannel, DiscordGuild};

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub channels: Vec<ClockChannel>,
    pub login_redir: String,
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