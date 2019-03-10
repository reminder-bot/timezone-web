use askama::Template;


#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub user: String,
    pub login_redir: String,
}

#[derive(Template)]
#[template(path = "bad_session.html")]
pub struct BadSession {
    pub home_redir: String,
    pub status: u16,
}