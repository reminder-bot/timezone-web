use askama::Template;

use crate::models::ClockChannel;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub channels: Vec<ClockChannel>,
    pub login_redir: String,
    pub form_redir: String,
}

#[derive(Template)]
#[template(path = "bad_session.html")]
pub struct BadSession {
    pub home_redir: String,
    pub status: u16,
}